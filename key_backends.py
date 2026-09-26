"""Pinned external CA keys: PKCS#11 and Azure Key Vault, with verified RSA-PSS.

Provider configuration contains credentials and must be encrypted by the caller.
No provider exports a private key or falls back to a software key. SoftHSM is a
software token, not a hardware protection or certification claim.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


AZURE_API_VERSION = "2025-07-01"
_PKCS11_LOCK = threading.RLock()
_PKCS11_LIBRARIES = {}


def pss_padding():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def public_key_fingerprint(public_key) -> str:
    encoded = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(encoded).hexdigest()


def _strong_public_key(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
        raise ValueError("External CA keys must be RSA with at least 3072 bits.")
    if public_key.public_numbers().e != 65537:
        raise ValueError("External RSA CA keys must use public exponent 65537.")
    return public_key


class ExternalSigner(ABC):
    """A public key plus a remote operation; deliberately no private_bytes API."""

    @abstractmethod
    def public_key(self) -> rsa.RSAPublicKey:
        raise NotImplementedError

    @abstractmethod
    def _sign(self, data: bytes) -> bytes:
        raise NotImplementedError

    def sign(self, data: bytes) -> bytes:
        public_key = _strong_public_key(self.public_key())
        signature = self._sign(data)
        try:
            public_key.verify(signature, data, pss_padding(), hashes.SHA256())
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValueError("The external provider returned an invalid signature for the pinned CA key.") from exc
        return signature


@lru_cache(maxsize=1)
def _encoding_key():
    # cryptography exposes signed builders, not an unsigned DER encoder. This
    # disposable key ONLY encodes a template. Its signature is always replaced
    # and never returned; the final signature is verified with the external key.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_builder(builder, signer):
    """Build cert/CSR/CRL using SHA256; every new RSA signature uses RSA-PSS."""
    if not isinstance(signer, ExternalSigner):
        options = {"rsa_padding": pss_padding()} if isinstance(signer, rsa.RSAPrivateKey) else {}
        return builder.sign(signer, hashes.SHA256(), **options)
    _strong_public_key(signer.public_key())
    try:
        from asn1crypto import crl, csr, keys, x509 as asn1_x509
    except ImportError as exc:
        raise ValueError("External signing requires the asn1crypto package.") from exc
    template = builder.sign(_encoding_key(), hashes.SHA256(), rsa_padding=pss_padding())
    encoded = template.public_bytes(serialization.Encoding.DER)
    if isinstance(builder, x509.CertificateSigningRequestBuilder):
        document = csr.CertificationRequest.load(encoded, strict=True)
        body_name = "certification_request_info"
        document[body_name]["subject_pk_info"] = keys.PublicKeyInfo.load(
            signer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        signature_name = "signature"
        loader = x509.load_der_x509_csr
    elif isinstance(builder, x509.CertificateBuilder):
        document = asn1_x509.Certificate.load(encoded, strict=True)
        body_name, signature_name, loader = "tbs_certificate", "signature_value", x509.load_der_x509_certificate
    elif isinstance(builder, x509.CertificateRevocationListBuilder):
        document = crl.CertificateList.load(encoded, strict=True)
        body_name, signature_name, loader = "tbs_cert_list", "signature", x509.load_der_x509_crl
    else:
        raise ValueError("Unsupported external signing object.")
    signed_data = document[body_name].dump()
    signature = signer.sign(signed_data)
    # Verify again at the lifecycle boundary even if a custom provider overrides
    # sign(); no unverified external bytes can reach the database via this path.
    try:
        signer.public_key().verify(signature, signed_data, pss_padding(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("External X.509 signature verification failed.") from exc
    document[signature_name] = signature
    result = loader(document.dump())
    if isinstance(result, x509.CertificateSigningRequest) and not result.is_signature_valid:
        raise ValueError("External CSR signature verification failed.")
    return result


def _text(config, field, maximum=4096):
    value = config.get(field, "")
    if not isinstance(value, str) or not value or len(value) > maximum or "\0" in value:
        raise ValueError(f"A valid {field.replace('_', ' ')} is required.")
    return value


def _token_label(config):
    label = _text(config, "token_label", 32)
    if len(label.encode("utf-8")) > 32 or any(ord(char) < 32 for char in label):
        raise ValueError("Token labels must contain at most 32 UTF-8 bytes and no control characters.")
    return label


def _check_pin(config, public_key, *, required=True):
    actual = public_key_fingerprint(_strong_public_key(public_key))
    expected = config.get("public_key_sha256", "")
    if required and not re.fullmatch(r"[0-9a-f]{64}", str(expected)):
        raise ValueError("A pinned external CA public-key fingerprint is required.")
    if expected and not secrets.compare_digest(actual, expected):
        raise ValueError("The external key no longer matches the pinned CA identity.")
    return actual


def _trusted_module(path: str) -> str:
    module = Path(path)
    if not module.is_absolute():
        raise ValueError("PKCS#11 module must be an absolute path.")
    try:
        module = module.resolve(strict=True)
        info = module.stat()
    except OSError as exc:
        raise ValueError("PKCS#11 module is not available.") from exc
    if os.name != "posix" or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("PKCS#11 requires a root-owned library that is not writable by group or other users.")
    for parent in module.parents:
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("PKCS#11 module directories must be controlled exclusively by root.")
    return str(module)


def _load_library(api, module):
    # SoftHSM reads its configuration at C_Initialize. A changed environment
    # cannot retarget an already initialized library; reject instead of silently
    # using another installation's token store in a shared Python process.
    configuration = os.environ.get("SOFTHSM2_CONF", "") if Path(module).name == "libsofthsm2.so" else ""
    existing = _PKCS11_LIBRARIES.get(module)
    if existing is not None:
        library, initialized_configuration = existing
        if configuration != initialized_configuration:
            raise ValueError("SoftHSM configuration changed in this process. Restart the service before accessing its token store.")
        return library
    library = api.PyKCS11Lib()
    library.load(module)
    _PKCS11_LIBRARIES[module] = (library, configuration)
    return library


@contextmanager
def _token_session(config):
    try:
        import PyKCS11 as api
    except ImportError as exc:
        raise ValueError("PKCS#11 signing requires the PyKCS11 package.") from exc
    module = _trusted_module(_text(config, "module_path"))
    label = _token_label(config)
    pin = _text(config, "user_pin", 256)
    # C_Login/C_Logout change token state for every session in this process.
    # Serialize the entire session, not only C_Sign, across worker threads.
    with _PKCS11_LOCK:
        session = None
        try:
            library = _load_library(api, module)
            serial = config.get("token_serial")
            slots = [slot for slot in library.getSlotList(tokenPresent=True)
                     if library.getTokenInfo(slot).label.strip() == label
                     and (not serial or library.getTokenInfo(slot).serialNumber.strip() == serial)]
            if len(slots) != 1:
                raise ValueError("Exactly one matching initialized PKCS#11 token must be available.")
            token_serial = library.getTokenInfo(slots[0]).serialNumber.strip()
            if not token_serial:
                raise ValueError("PKCS#11 token has no stable serial number.")
            session = library.openSession(slots[0], api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION)
            session.login(pin)
            yield api, session, token_serial
        except api.PyKCS11Error as exc:
            raise ValueError("PKCS#11 operation failed. Check token availability, PIN and RSA-PSS permissions.") from exc
        finally:
            if session is not None:
                try:
                    session.logout()
                except api.PyKCS11Error:
                    pass
                try:
                    session.closeSession()
                except api.PyKCS11Error:
                    pass


def _token_keys(api, session, config):
    key_id = _text(config, "key_id", 128)
    if not re.fullmatch(r"(?:[0-9a-f]{2}){1,64}", key_id):
        raise ValueError("PKCS#11 key ID must be a nonempty lowercase hexadecimal value.")
    identity = tuple(bytes.fromhex(key_id))
    objects = [session.findObjects([(api.CKA_CLASS, kind), (api.CKA_ID, identity)])
               for kind in (api.CKO_PUBLIC_KEY, api.CKO_PRIVATE_KEY)]
    if any(len(matches) != 1 for matches in objects):
        raise ValueError("PKCS#11 key ID must identify exactly one public/private key pair.")
    public, private = objects[0][0], objects[1][0]
    attributes = session.getAttributeValue(private, [api.CKA_KEY_TYPE, api.CKA_SIGN, api.CKA_SENSITIVE, api.CKA_EXTRACTABLE])
    if attributes != [api.CKK_RSA, True, True, False]:
        raise ValueError("PKCS#11 CA key must be sensitive, nonextractable RSA with signing enabled.")
    modulus, exponent = session.getAttributeValue(public, [api.CKA_MODULUS, api.CKA_PUBLIC_EXPONENT])
    public_key = rsa.RSAPublicNumbers(int.from_bytes(bytes(exponent), "big"), int.from_bytes(bytes(modulus), "big")).public_key()
    return _strong_public_key(public_key), private


class PKCS11Signer(ExternalSigner):
    def __init__(self, config, *, require_pin=True):
        self._config = dict(config)
        with _token_session(self._config) as (api, session, serial):
            if require_pin and not self._config.get("token_serial"):
                raise ValueError("A pinned PKCS#11 token serial is required.")
            self._public_key, _ = _token_keys(api, session, self._config)
            fingerprint = _check_pin(self._config, self._public_key, required=require_pin)
        self._config.update(token_serial=serial, public_key_sha256=fingerprint)

    def public_key(self):
        return self._public_key

    def _sign(self, data):
        with _token_session(self._config) as (api, session, _):
            public_key, private = _token_keys(api, session, self._config)
            _check_pin(self._config, public_key)
            mechanism = api.RSA_PSS_Mechanism(api.CKM_SHA256_RSA_PKCS_PSS, api.CKM_SHA256, api.CKG_MGF1_SHA256, 32)
            return bytes(session.sign(private, data, mechanism))


def _provision_pkcs11(config):
    config = {name: config[name] for name in ("module_path", "token_label", "user_pin", "token_serial", "key_id", "public_key_sha256") if name in config}
    config["module_path"] = _trusted_module(_text(config, "module_path"))
    if not config.get("key_id"):
        config["key_id"] = secrets.token_hex(20)
        with _token_session(config) as (api, session, serial):
            identity = tuple(bytes.fromhex(config["key_id"]))
            if session.findObjects([(api.CKA_ID, identity)]):
                raise ValueError("Generated PKCS#11 key ID already exists.")
            label = "PKIMaster CA " + config["key_id"][:12]
            public = [(api.CKA_TOKEN, True), (api.CKA_PRIVATE, False), (api.CKA_LABEL, label),
                      (api.CKA_ID, identity), (api.CKA_MODULUS_BITS, 4096),
                      (api.CKA_PUBLIC_EXPONENT, (1, 0, 1)), (api.CKA_VERIFY, True),
                      (api.CKA_ENCRYPT, False), (api.CKA_WRAP, False)]
            private = [(api.CKA_TOKEN, True), (api.CKA_PRIVATE, True), (api.CKA_LABEL, label),
                       (api.CKA_ID, identity), (api.CKA_SENSITIVE, True), (api.CKA_EXTRACTABLE, False),
                       (api.CKA_SIGN, True), (api.CKA_DECRYPT, False), (api.CKA_UNWRAP, False)]
            session.generateKeyPair(public, private, api.Mechanism(api.CKM_RSA_PKCS_KEY_PAIR_GEN))
            config["token_serial"] = serial
    signer = PKCS11Signer(config, require_pin=False)
    signer.sign(secrets.token_bytes(32))  # Prove the located private object matches the public object.
    return signer, dict(signer._config)


def initialize_softhsm(config: dict, so_pin: str) -> dict:
    """Initialize only a previously unused SoftHSM slot; never reset a token.

    The caller supplies a service-controlled SOFTHSM2_CONF/token directory. The
    security-officer PIN is used once and is not included in the returned config.
    """
    try:
        import PyKCS11 as api
    except ImportError as exc:
        raise ValueError("SoftHSM initialization requires the PyKCS11 package.") from exc
    module = _trusted_module(_text(config, "module_path"))
    if Path(module).name != "libsofthsm2.so":
        raise ValueError("Browser token initialization is restricted to SoftHSM.")
    label = _token_label(config)
    user_pin = _text(config, "user_pin", 256)
    _text({"so_pin": so_pin}, "so_pin", 256)
    if len(user_pin) < 8 or len(so_pin) < 8 or secrets.compare_digest(user_pin, so_pin):
        raise ValueError("Use different user and security-officer PINs of at least eight characters.")
    with _PKCS11_LOCK:
        session = None
        try:
            library = _load_library(api, module)
            slots = library.getSlotList(tokenPresent=True)
            if any(library.getTokenInfo(slot).label.strip() == label for slot in slots):
                raise ValueError("A token with this label already exists; it will not be initialized again.")
            unused = [slot for slot in slots if not library.getTokenInfo(slot).flags & api.CKF_TOKEN_INITIALIZED]
            if not unused:
                raise ValueError("No unused SoftHSM slot is available.")
            # C_InitToken requires an exactly 32-byte, space-padded UTF-8 label.
            library.initToken(unused[0], so_pin, label + " " * (32 - len(label.encode("utf-8"))))
            matches = [slot for slot in library.getSlotList(tokenPresent=True) if library.getTokenInfo(slot).label.strip() == label]
            if len(matches) != 1:
                raise ValueError("Initialized SoftHSM token could not be uniquely identified.")
            session = library.openSession(matches[0], api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION)
            session.login(so_pin, api.CKU_SO)
            session.initPin(user_pin)
            serial = library.getTokenInfo(matches[0]).serialNumber.strip()
        except api.PyKCS11Error as exc:
            raise ValueError("SoftHSM initialization failed; check token storage access and PIN policy.") from exc
        finally:
            if session is not None:
                try:
                    session.logout()
                except api.PyKCS11Error:
                    pass
                try:
                    session.closeSession()
                except api.PyKCS11Error:
                    pass
    return {"module_path": module, "token_label": label, "user_pin": user_pin, "token_serial": serial}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Azure credential-bearing requests cannot follow redirects.")


def _request_json(method, url, body=None, *, headers=None, form=False):
    """TLS-verified, bounded REST transport. Errors never expose remote payloads."""
    encoded = None if body is None else (urlencode(body).encode() if form else json.dumps(body).encode())
    request_headers = {"Accept": "application/json", **(headers or {})}
    if encoded is not None:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    request = Request(url, data=encoded, headers=request_headers, method=method)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=15) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("Azure response exceeds the size limit.")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("Azure returned an invalid response.")
        return result
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Azure Key Vault request failed. Check network access, credentials and key permissions.") from exc


def _azure_vault(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or not re.fullmatch(r"[a-z][a-z0-9-]{1,22}[a-z0-9]\.(?:vault|managedhsm)\.azure\.net", parsed.hostname or "")):
        raise ValueError("Use an HTTPS Azure public-cloud Key Vault or Managed HSM URL without a path or port.")
    return "https://" + parsed.hostname


def _azure_key_id(value, vault):
    if not isinstance(value, str) or not re.fullmatch(re.escape(vault) + r"/keys/[A-Za-z0-9-]{1,127}/[0-9a-f]{32}", value):
        raise ValueError("Azure CA identity requires an exact versioned key URL in the configured vault.")
    return value


def _unbase64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Azure returned invalid key or signature encoding.")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _base64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class AzureKeyVaultSigner(ExternalSigner):
    def __init__(self, config, *, require_pin=True, bundle=None):
        self._config = {name: config[name] for name in (
            "vault_url", "tenant_id", "client_id", "client_secret", "key_name", "key_type", "key_id", "public_key_sha256"
        ) if name in config}
        self._config["vault_url"] = _azure_vault(_text(config, "vault_url", 256))
        for field in ("tenant_id", "client_id"):
            try:
                self._config[field] = str(uuid.UUID(_text(config, field, 36)))
            except (ValueError, AttributeError) as exc:
                raise ValueError("Azure tenant and client IDs must be UUIDs.") from exc
        _text(config, "client_secret")
        self._token = None
        self._token_expires = 0
        if bundle is None:
            key_id = _azure_key_id(_text(config, "key_id", 512), self._config["vault_url"])
            bundle = self._api("GET", key_id)
        try:
            key = bundle["key"]
            key_id = _azure_key_id(key["kid"], self._config["vault_url"])
            if config.get("key_id") and key_id != config["key_id"]:
                raise ValueError("Azure returned a different key version.")
            if key["kty"] not in {"RSA", "RSA-HSM"} or (config.get("key_type") and config["key_type"] != key["kty"]):
                raise ValueError("Azure key type does not match the selected RSA protection level.")
            if "sign" not in key.get("key_ops", []) or set(key["key_ops"]) - {"sign", "verify"}:
                raise ValueError("Azure CA key must authorize only signing and verification.")
            attributes = bundle.get("attributes", {})
            now = time.time()
            if attributes.get("enabled") is not True or attributes.get("nbf", 0) > now or attributes.get("exp", now + 1) <= now:
                raise ValueError("Azure CA key is disabled, expired or not yet usable.")
            if attributes.get("exportable") or bundle.get("release_policy") or any(field in key for field in ("d", "p", "q", "dp", "dq", "qi")):
                raise ValueError("Azure CA key must not be exportable or release private key material.")
            self._public_key = rsa.RSAPublicNumbers(int.from_bytes(_unbase64(key["e"]), "big"), int.from_bytes(_unbase64(key["n"]), "big")).public_key()
            fingerprint = _check_pin(config, self._public_key, required=require_pin)
        except (KeyError, TypeError) as exc:
            raise ValueError("Azure returned an invalid key description.") from exc
        self._config.update(key_id=key_id, key_type=key["kty"], public_key_sha256=fingerprint)

    def public_key(self):
        return self._public_key

    def _access_token(self):
        if self._token and self._token_expires > time.time() + 60:
            return self._token
        vault_host = urlsplit(self._config["vault_url"]).hostname or ""
        audience = "https://managedhsm.azure.net" if vault_host.endswith(".managedhsm.azure.net") else "https://vault.azure.net"
        response = _request_json("POST", "https://login.microsoftonline.com/" + self._config["tenant_id"] + "/oauth2/v2.0/token", {
            "grant_type": "client_credentials", "client_id": self._config["client_id"],
            "client_secret": self._config["client_secret"], "scope": audience + "/.default",
        }, form=True)
        token = response.get("access_token")
        if not isinstance(token, str) or not token or len(token) > 32768 or any(char.isspace() for char in token):
            raise ValueError("Azure returned an invalid access token.")
        try:
            lifetime = max(0, min(int(response.get("expires_in", 0)), 3600))
        except (ValueError, TypeError) as exc:
            raise ValueError("Azure returned an invalid token lifetime.") from exc
        self._token, self._token_expires = token, time.time() + lifetime
        return token

    def _api(self, method, url, body=None):
        if not url.startswith(self._config["vault_url"] + "/keys/"):
            raise ValueError("Azure request is outside the configured vault.")
        return _request_json(method, url + "?api-version=" + AZURE_API_VERSION, body,
                             headers={"Authorization": "Bearer " + self._access_token()})

    def _sign(self, data):
        result = self._api("POST", self._config["key_id"] + "/sign", {"alg": "PS256", "value": _base64(hashlib.sha256(data).digest())})
        if result.get("kid") != self._config["key_id"]:
            raise ValueError("Azure signature came from a different key version.")
        return _unbase64(result.get("value"))


def _provision_azure(config):
    config = dict(config)
    if config.get("key_id"):
        signer = AzureKeyVaultSigner(config, require_pin=False)
    else:
        vault = _azure_vault(_text(config, "vault_url", 256))
        name = _text(config, "key_name", 127)
        if not re.fullmatch(r"[A-Za-z0-9-]{1,127}", name) or config.get("key_type") not in {"RSA", "RSA-HSM"}:
            raise ValueError("Select a valid Azure key name and RSA or RSA-HSM protection level.")
        # Authenticate without resolving any key. A named create explicitly makes
        # a new version; no latest-version lookup is ever used for signing.
        transport = object.__new__(AzureKeyVaultSigner)
        transport._config = dict(config, vault_url=vault)
        for field in ("tenant_id", "client_id"):
            try:
                transport._config[field] = str(uuid.UUID(_text(config, field, 36)))
            except ValueError as exc:
                raise ValueError("Azure tenant and client IDs must be UUIDs.") from exc
        _text(config, "client_secret")
        transport._token, transport._token_expires = None, 0
        bundle = transport._api("POST", vault + "/keys/" + name + "/create", {
            "kty": config["key_type"], "key_size": 4096, "public_exponent": 65537,
            "key_ops": ["sign", "verify"], "attributes": {"enabled": True, "exportable": False},
        })
        signer = AzureKeyVaultSigner(config, require_pin=False, bundle=bundle)
        if signer._config["key_id"].split("/")[-2] != name:
            raise ValueError("Azure created a different key name.")
        if signer.public_key().key_size != 4096:
            raise ValueError("Azure did not create the requested 4096-bit CA key.")
    signer.sign(secrets.token_bytes(32))
    return signer, dict(signer._config)


def provision_signer(backend: str, config: dict) -> tuple[ExternalSigner, dict]:
    """Create/attach a key once; persist the returned encrypted pinned config."""
    if backend == "pkcs11":
        return _provision_pkcs11(config)
    if backend == "azure":
        return _provision_azure(config)
    raise ValueError("External signing provider must be pkcs11 or azure.")


def load_signer(backend: str, config: dict) -> ExternalSigner:
    """Resolve only the pinned key identity. Never provision on a signing path."""
    if backend == "pkcs11":
        return PKCS11Signer(config)
    if backend == "azure":
        return AzureKeyVaultSigner(config)
    raise ValueError("External signing provider must be pkcs11 or azure.")
