"""Opt-in, credential-gated SCEP and EST enrollment."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

from asn1crypto import cms, core, x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, padding as symmetric_padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from enterprise import audit_event, get_setting, require_roles


scep_protocol = Blueprint("scep_protocol", __name__)
est_protocol = Blueprint("est_protocol", __name__, url_prefix="/.well-known/est")
scep_est_admin = Blueprint("scep_est_admin", __name__)
MAX_BODY = 256 * 1024
MAX_CERTS = 16
OID_MESSAGE_TYPE = "2.16.840.1.113733.1.9.2"
OID_PKI_STATUS = "2.16.840.1.113733.1.9.3"
OID_FAIL_INFO = "2.16.840.1.113733.1.9.4"
OID_SENDER_NONCE = "2.16.840.1.113733.1.9.5"
OID_RECIPIENT_NONCE = "2.16.840.1.113733.1.9.6"
OID_TRANSACTION_ID = "2.16.840.1.113733.1.9.7"
OID_CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7"


class EnrollmentRateLimitError(ValueError):
    pass


class EnrollmentAuditError(RuntimeError):
    pass


def _db():
    from app import get_db
    return get_db()


def _stamp(value=None):
    value = value or datetime.now(UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _config():
    try:
        value = json.loads(get_setting("scep_est_config", "{}"))
    except (json.JSONDecodeError, TypeError) as error:
        raise RuntimeError("Stored SCEP/EST configuration is malformed.") from error
    if not isinstance(value, dict):
        raise RuntimeError("Stored SCEP/EST configuration is not a JSON object.")
    for key in ("enabled", "scep", "est"):
        if key in value and type(value[key]) is not bool:
            raise RuntimeError(f"Stored SCEP/EST setting {key} is invalid.")
    validity_days = value.get("validity_days", 90)
    if type(validity_days) is not int or not 1 <= validity_days <= 7300:
        raise RuntimeError("Stored SCEP/EST validity period is invalid.")
    return {
        "enabled": value.get("enabled", False),
        "scep": value.get("scep", False),
        "est": value.get("est", False),
        "validity_days": validity_days,
    }


def init_scep_est(app):
    """Initialize storage and register the independent protocol/admin blueprints."""
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS enrollment_credentials (
                id TEXT PRIMARY KEY, label TEXT NOT NULL, protocol TEXT NOT NULL
                    CHECK(protocol IN ('scep','est')),
                secret_hash TEXT NOT NULL, authority_id INTEGER NOT NULL,
                template_id TEXT NOT NULL, domains TEXT NOT NULL,
                validity_days INTEGER NOT NULL, created_at TEXT NOT NULL,
                expires TEXT NOT NULL, used_at TEXT, revoked INTEGER NOT NULL DEFAULT 0
                    CHECK(revoked IN (0,1))
            );
            CREATE INDEX IF NOT EXISTS enrollment_credentials_live
                ON enrollment_credentials(protocol, revoked, used_at, expires);
            CREATE INDEX IF NOT EXISTS enrollment_credentials_secret
                ON enrollment_credentials(protocol, secret_hash);
            CREATE TABLE IF NOT EXISTS enrollment_replays (
                protocol TEXT NOT NULL, transaction_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(protocol, transaction_id)
            );
            CREATE TABLE IF NOT EXISTS enrollment_rate_limits (
                bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL
            );
        """)
    app.register_blueprint(scep_protocol)
    app.register_blueprint(est_protocol)
    app.register_blueprint(scep_est_admin)


def _enabled(protocol):
    config = _config()
    if not config["enabled"] or not config[protocol]:
        return False
    from urllib.parse import urlsplit
    base = urlsplit(get_setting("public_base_url", ""))
    return base.scheme == "https" and bool(base.hostname) and not base.username and not base.password


@scep_protocol.before_request
def _scep_enabled():
    if not _enabled("scep"):
        return Response("SCEP enrollment is unavailable.", status=503, headers={"Cache-Control": "no-store"})


@est_protocol.before_request
def _est_enabled():
    if not _enabled("est"):
        return Response("EST enrollment is unavailable.", status=503, headers={"Cache-Control": "no-store"})
    if not request.is_secure:
        return Response("EST requires HTTPS.", status=400, headers={"Cache-Control": "no-store"})


def _limit(bucket, maximum=20, window=60):
    db = _db()
    now = int(time.time())
    db.execute("DELETE FROM enrollment_rate_limits WHERE window_start<?", (now - window * 5,))
    row = db.execute("SELECT window_start,attempts FROM enrollment_rate_limits WHERE bucket=?", (bucket,)).fetchone()
    if not row or now - row["window_start"] >= window:
        db.execute("INSERT INTO enrollment_rate_limits VALUES (?,?,1) ON CONFLICT(bucket) DO UPDATE SET window_start=excluded.window_start,attempts=1",
                   (bucket, now))
        db.commit()
        return
    if row["attempts"] >= maximum:
        raise EnrollmentRateLimitError("Enrollment request limit exceeded.")
    db.execute("UPDATE enrollment_rate_limits SET attempts=attempts+1 WHERE bucket=?", (bucket,))
    db.commit()


def _require_body():
    request.max_content_length = MAX_BODY
    if request.content_length is not None and request.content_length > MAX_BODY:
        raise RequestEntityTooLarge()
    body = request.get_data(cache=False)
    if len(body) > MAX_BODY:
        raise RequestEntityTooLarge()
    return body


def _content_info(data):
    try:
        if not data or len(data) > MAX_BODY:
            raise ValueError
        return cms.ContentInfo.load(data, strict=True)
    except (ValueError, TypeError) as error:
        raise ValueError("Malformed CMS message.") from error


def _cms_certificates(signed_data):
    certificates = []
    for entry in signed_data["certificates"]:
        if entry.name == "certificate":
            certificates.append(x509.load_der_x509_certificate(entry.chosen.dump()))
    if len(certificates) > MAX_CERTS:
        raise ValueError("CMS message contains too many certificates.")
    return certificates


def _matching_signer(signer_info, certificates):
    sid = signer_info["sid"]
    for certificate in certificates:
        if sid.name == "issuer_and_serial_number":
            value = sid.chosen
            if (certificate.serial_number == value["serial_number"].native
                    and asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))["tbs_certificate"]["issuer"]
                    == value["issuer"]):
                return certificate
        elif sid.name == "subject_key_identifier":
            try:
                ski = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                if ski == sid.chosen.native:
                    return certificate
            except x509.ExtensionNotFound:
                continue
    raise ValueError("CMS signer certificate is missing.")


def _cms_attribute(signer_info, oid):
    found = []
    attrs = signer_info["signed_attrs"]
    if attrs.native is None:
        raise ValueError("CMS signed attributes are required.")
    for item in attrs:
        if item["type"].dotted == oid:
            found.extend(value.native for value in item["values"])
    if len(found) != 1:
        raise ValueError("CMS message has missing or ambiguous protocol attributes.")
    return found[0]


def _verify_signed_data(data):
    info = _content_info(data)
    if info["content_type"].native != "signed_data":
        raise ValueError("SCEP message must be CMS SignedData.")
    signed = info["content"]
    certificates = _cms_certificates(signed)
    if len(signed["signer_infos"]) != 1:
        raise ValueError("Exactly one CMS signer is supported.")
    signer_info = signed["signer_infos"][0]
    signer = _matching_signer(signer_info, certificates)
    try:
        if not signer.not_valid_before_utc <= datetime.now(UTC) < signer.not_valid_after_utc:
            raise ValueError("CMS signer certificate is not currently valid.")
        attrs = signer_info["signed_attrs"]
        content_value = signed["encap_content_info"]["content"]
        content = content_value.native
        if isinstance(content, dict):
            content = content_value.untag().dump()
        if not isinstance(content, bytes) or not hmac.compare_digest(
                _cms_attribute(signer_info, "1.2.840.113549.1.9.4"),
                hashlib.new(signer_info["digest_algorithm"]["algorithm"].native, content).digest()):
            raise ValueError("CMS content digest is invalid.")
        if _cms_attribute(signer_info, "1.2.840.113549.1.9.3") != signed["encap_content_info"]["content_type"].native:
            raise ValueError("CMS content type is invalid.")
        signed_bytes = attrs.untag().dump()
        key = signer.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            raise ValueError("CMS signer RSA keys must be at least 2048 bits.")
        if isinstance(key, ec.EllipticCurvePublicKey) and not isinstance(
                key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
            raise ValueError("Unsupported CMS signer curve.")
        if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise ValueError("Unsupported CMS signer key.")
        try:
            if signer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("CMS signer must not be a CA certificate.")
        except x509.ExtensionNotFound:
            pass
        try:
            if not signer.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
                raise ValueError("CMS signer certificate does not permit digital signatures.")
        except x509.ExtensionNotFound:
            pass
        signature = signer_info["signature"].native
        digest = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}.get(
            signer_info["digest_algorithm"]["algorithm"].native)
        if digest is None:
            raise ValueError("Unsupported CMS digest algorithm.")
        algorithm = signer_info["signature_algorithm"]["algorithm"].native
        if isinstance(key, rsa.RSAPublicKey) and algorithm == "rsassa_pkcs1v15":
            key.verify(signature, signed_bytes, padding.PKCS1v15(), digest)
        elif isinstance(key, ec.EllipticCurvePublicKey) and algorithm == "sha256_ecdsa" and isinstance(digest, hashes.SHA256):
            key.verify(signature, signed_bytes, ec.ECDSA(digest))
        else:
            raise ValueError("Unsupported CMS signer key or signature algorithm.")
        return signed, content, signer
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith(("CMS ", "Unsupported")):
            raise
        raise ValueError("CMS signature verification failed.") from error


def _decrypt_enveloped(data, private_key):
    try:
        info = _content_info(data)
        content_type = info["content_type"].native
    except ValueError:
        info = None
    if info is not None:
        if content_type != "enveloped_data":
            raise ValueError("Expected CMS EnvelopedData.")
        envelope = info["content"]
    else:
        try:
            envelope = cms.EnvelopedData.load(data, strict=True)
        except (ValueError, TypeError) as error:
            raise ValueError("Expected CMS EnvelopedData.") from error
    recipients = envelope["recipient_infos"]
    if len(recipients) != 1 or recipients[0].name != "ktri":
        raise ValueError("Only one RSA key-transport recipient is supported.")
    recipient = recipients[0].chosen
    if (not isinstance(private_key, rsa.RSAPrivateKey)
            or recipient["key_encryption_algorithm"]["algorithm"].native != "rsaes_pkcs1v15"):
        raise ValueError("SCEP requires an RSA software issuer key for CMS decryption.")
    cek = private_key.decrypt(recipient["encrypted_key"].native, padding.PKCS1v15())
    encrypted_info = envelope["encrypted_content_info"]
    algorithm = encrypted_info["content_encryption_algorithm"]["algorithm"].native
    iv = encrypted_info["content_encryption_algorithm"]["parameters"].native
    ciphers = {
        "aes128_cbc": (algorithms.AES, 16), "aes192_cbc": (algorithms.AES, 24),
        "aes256_cbc": (algorithms.AES, 32), "tripledes_3key": (TripleDES, 8),
    }
    if algorithm not in ciphers:
        raise ValueError("Unsupported SCEP content-encryption algorithm.")
    cipher, key_size = ciphers[algorithm]
    if len(cek) != key_size or len(iv) != cipher.block_size // 8:
        raise ValueError("Invalid CMS content-encryption parameters.")
    encrypted = encrypted_info["encrypted_content"].native
    decryptor = Cipher(cipher(cek), modes.CBC(iv)).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = symmetric_padding.PKCS7(cipher.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _cms_encrypt(data, recipient_certificate):
    public_key = recipient_certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("SCEP encryption requires an RSA recipient certificate.")
    cek, iv = secrets.token_bytes(32), secrets.token_bytes(16)
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    wrapped = public_key.encrypt(cek, padding.PKCS1v15())
    issuer = asn1_x509.Certificate.load(recipient_certificate.public_bytes(serialization.Encoding.DER))
    recipient = cms.RecipientInfo(name="ktri", value=cms.KeyTransRecipientInfo({
        "version": "v0",
        "rid": {"issuer_and_serial_number": {"issuer": issuer.issuer, "serial_number": recipient_certificate.serial_number}},
        "key_encryption_algorithm": {"algorithm": "rsa"},
        "encrypted_key": wrapped,
    }))
    envelope = cms.EnvelopedData({
        "version": "v0", "recipient_infos": [recipient],
        "encrypted_content_info": {
            "content_type": "data",
            "content_encryption_algorithm": {"algorithm": "aes256_cbc", "parameters": iv},
            "encrypted_content": encrypted,
        },
    })
    return cms.ContentInfo({"content_type": "enveloped_data", "content": envelope}).dump()


def _cms_certificates_only(certificates):
    choices = [cms.CertificateChoices(name="certificate", value=asn1_x509.Certificate.load(
        cert.public_bytes(serialization.Encoding.DER))) for cert in certificates]
    signed = cms.SignedData({
        "version": "v1", "digest_algorithms": [],
        "encap_content_info": {"content_type": "data"},
        "certificates": choices, "signer_infos": [],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()


def _cms_sign(data, signer, signer_certificate, *, content_type="data", extra_attrs=()):
    if not isinstance(signer, rsa.RSAPrivateKey):
        raise ValueError("SCEP response signing currently requires an RSA software CA key.")
    encapsulated = data
    if content_type == "enveloped_data":
        parsed = _content_info(data)
        if parsed["content_type"].native != "enveloped_data":
            raise ValueError("CMS response content must be EnvelopedData.")
        encapsulated = parsed["content"].untag()
        data = encapsulated.dump()
    certificate = asn1_x509.Certificate.load(signer_certificate.public_bytes(serialization.Encoding.DER))
    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": [content_type]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(data).digest()]}),
        *extra_attrs,
    ]
    signed_attrs = cms.CMSAttributes(attrs)
    signature = signer.sign(signed_attrs.untag().dump(), padding.PKCS1v15(), hashes.SHA256())
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": {"issuer_and_serial_number": {"issuer": certificate.issuer, "serial_number": signer_certificate.serial_number}},
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
        "signature": signature,
    })
    signed = cms.SignedData({
        "version": "v1", "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": content_type, "content": encapsulated},
        "certificates": [cms.CertificateChoices(name="certificate", value=certificate)],
        "signer_infos": [signer_info],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()


def _issuer(authority_id):
    from app import authority_block_reason, get_authority
    authority = get_authority(authority_id)
    if not authority or authority["role"] != "issuing" or authority["state"] != "active" or authority["revoked_at"]:
        raise ValueError("The credential's issuing CA is unavailable.")
    reason = authority_block_reason(authority)
    if reason:
        raise ValueError(reason)
    from key_storage import authority_signing_key
    key = authority_signing_key(authority)
    if isinstance(key, str):
        key = serialization.load_pem_private_key(key.encode(), password=None)
    certificate = x509.load_pem_x509_certificate(authority["certificate_pem"].encode())
    if certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError("Issuer certificate and signing key do not match.")
    return authority, certificate, key


def _authorize(protocol, identifier, secret):
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,64}", identifier or "") or not isinstance(secret, str) or not 32 <= len(secret) <= 128:
        raise ValueError("Enrollment credential is invalid.")
    row = _db().execute("""SELECT * FROM enrollment_credentials
        WHERE id=? AND protocol=? AND revoked=0 AND used_at IS NULL AND expires>?""",
        (identifier, protocol, _stamp())).fetchone()
    if not row or not hmac.compare_digest(row["secret_hash"], hashlib.sha256(secret.encode("utf-8")).hexdigest()):
        raise ValueError("Enrollment credential is invalid, expired, used or revoked.")
    return row


def _template_and_policy(row, csr):
    from app import get_db
    from certificate_profiles import validate_issuance
    from pki import _csr_key_and_names
    request_csr = x509.load_der_x509_csr(csr)
    if not request_csr.is_signature_valid:
        raise ValueError("CSR signature is invalid.")
    csr_pem = request_csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    common_names = request_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise ValueError("CSR must contain exactly one common name.")
    common_name = common_names[0].value
    # The shared issuance validator enforces minimum RSA key strength and CSR SAN policy.
    _, csr_names = _csr_key_and_names(csr_pem, 3072)
    requested = []
    for item in csr_names:
        if not isinstance(item, x509.DNSName):
            raise ValueError("Enrollment credential domains may contain DNS names only.")
        requested.append(item.value.lower().rstrip("."))
    requested.append(common_name.lower().rstrip("."))
    domains = json.loads(row["domains"])
    for name in requested:
        if not any(name == domain or name.endswith("." + domain) for domain in domains):
            raise ValueError("The requested common name or SAN is outside this credential's permitted domains.")
    policy = validate_issuance(
        get_db(), row["template_id"], common_name=common_name,
        subject_alt_names=[], validity_days=row["validity_days"],
        role="admin", csr_pem=csr_pem,
    )
    return common_name, policy, csr_pem


def _issue(row, csr_der):
    from app import encrypt_private_key, get_db
    from pki import issue_end_entity_certificate, serialize_private_key
    from audit_integrity import AuditIntegrityError, verify_chain
    try:
        verify_chain(get_db(), current_app.config["KEY_ENCRYPTION_SECRET"])
    except AuditIntegrityError as error:
        raise EnrollmentAuditError("Audit integrity check failed; enrollment is disabled.") from error
    authority, certificate, signer = _issuer(row["authority_id"])
    common_name, policy, csr_pem = _template_and_policy(row, csr_der)
    issuer_key = serialize_private_key(signer) if isinstance(
        signer, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)) else signer
    if policy["profile"] not in {"server", "client", "dual"}:
        raise ValueError("Unsupported issuance profile.")
    pem, private_key, serial, start, end = issue_end_entity_certificate(
        common_name, authority["certificate_pem"], issuer_key, row["validity_days"],
        policy["subject_alt_names"].split(", ") if policy["subject_alt_names"] else [],
        profile=policy["profile"], csr_pem=csr_pem,
        minimum_rsa_bits=3072,
    )
    issued = x509.load_pem_x509_certificate(pem.encode())
    try:
        sans = ", ".join(str(name.value) for name in issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        sans = ""
    db = get_db()
    item = db.execute("""INSERT INTO certificates
        (common_name,authority_id,subject_alt_names,certificate_pem,private_key_pem,
         serial_number,not_before,not_after,profile,template_id,template_snapshot)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (common_name, authority["id"], sans, pem, encrypt_private_key(private_key) if private_key else "",
         serial, start, end, policy["profile"], policy["template_id"], policy["template_snapshot"]))
    audit_event("certificate.issued", "certificate", item.lastrowid,
                f"{common_name}; profile={policy['profile']}; source=authenticated {row['protocol']} enrollment")
    chain = [certificate]
    if authority["parent_chain_pem"]:
        chain.extend(x509.load_pem_x509_certificates(authority["parent_chain_pem"].encode()))
    return pem, chain


def _consume(row):
    changed = _db().execute("""UPDATE enrollment_credentials SET used_at=?
        WHERE id=? AND used_at IS NULL AND revoked=0 AND expires>?""",
        (_stamp(), row["id"], _stamp()))
    if not changed.rowcount:
        raise ValueError("This one-use enrollment credential has already been consumed.")


def _est_response(pem, chain):
    certificate = x509.load_pem_x509_certificate(pem.encode())
    body = _cms_certificates_only([certificate, *chain])
    response = Response(body, mimetype="application/pkcs7-mime")
    response.headers["Content-Type"] = 'application/pkcs7-mime; smime-type=certs-only'
    response.headers["Cache-Control"] = "no-store"
    return response


@est_protocol.get("/cacerts")
def est_cacerts():
    from app import current_authority, authority_block_reason
    authority = current_authority()
    if not authority or authority_block_reason(authority):
        return Response("Issuing CA unavailable.", status=503)
    chain = [x509.load_pem_x509_certificate(authority["certificate_pem"].encode())]
    if authority["parent_chain_pem"]:
        chain.extend(x509.load_pem_x509_certificates(authority["parent_chain_pem"].encode()))
    response = Response(_cms_certificates_only(chain), mimetype="application/pkcs7-mime")
    response.headers["Content-Type"] = 'application/pkcs7-mime; smime-type=certs-only'
    response.headers["Cache-Control"] = "no-store"
    return response


def _est_enroll():
    try:
        _limit("est:" + (request.remote_addr or "unknown"))
    except EnrollmentRateLimitError:
        return Response("Enrollment request limit exceeded.", status=429, headers={"Retry-After": "60", "Cache-Control": "no-store"})
    if not request.is_secure:
        return Response("EST requires HTTPS.", status=400)
    authorization = request.authorization
    if not authorization or authorization.type.lower() != "basic":
        return Response("Enrollment credentials required.", status=401, headers={"WWW-Authenticate": 'Basic realm="EST enrollment"'})
    try:
        row = _authorize("est", authorization.username, authorization.password)
    except ValueError:
        return Response("Enrollment credentials rejected.", status=401, headers={"WWW-Authenticate": 'Basic realm="EST enrollment"'})
    try:
        body = _require_body()
        if request.mimetype != "application/pkcs10":
            return Response("Use application/pkcs10.", status=415)
        x509.load_der_x509_csr(body)
        fingerprint = hashlib.sha256(body).hexdigest()
        db = _db()
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM enrollment_replays WHERE protocol='est' AND transaction_id=?", (fingerprint,)).fetchone():
            raise ValueError("This CSR has already been submitted.")
        pem, chain = _issue(row, body)
        _consume(row)
        db.execute("INSERT INTO enrollment_replays VALUES ('est',?,?)", (fingerprint, _stamp()))
        db.commit()
        return _est_response(pem, chain)
    except RequestEntityTooLarge:
        raise
    except EnrollmentAuditError as error:
        _db().rollback()
        return Response(str(error), status=503, headers={"Cache-Control": "no-store"})
    except EnrollmentRateLimitError:
        _db().rollback()
        return Response("Enrollment request limit exceeded.", status=429, headers={"Retry-After": "60", "Cache-Control": "no-store"})
    except (ValueError, TypeError, KeyError, UnsupportedAlgorithm, sqlite3.Error) as error:
        _db().rollback()
        current_app.logger.info("EST enrollment rejected: %s", error)
        return Response("EST enrollment request rejected.", status=400, headers={"Cache-Control": "no-store"})


@est_protocol.post("/simpleenroll")
def est_simpleenroll():
    return _est_enroll()


def _scep_attributes(signer_info):
    result = {}
    for oid in (OID_MESSAGE_TYPE, OID_TRANSACTION_ID, OID_SENDER_NONCE):
        result[oid] = _cms_attribute(signer_info, oid)
    return result


def _csr_challenge(csr_der):
    from asn1crypto import csr as asn1_csr
    request_csr = asn1_csr.CertificationRequest.load(csr_der, strict=True)
    found = []
    for attribute in request_csr["certification_request_info"]["attributes"]:
        if attribute["type"].dotted == OID_CHALLENGE_PASSWORD:
            for value in attribute["values"]:
                if not isinstance(value.native, str):
                    raise ValueError("SCEP challengePassword must be a DirectoryString.")
                found.append(value.native)
    if len(found) != 1 or not isinstance(found[0], str):
        raise ValueError("PKCSReq must contain one challengePassword enrollment credential.")
    return found[0]


def _scep_request(body):
    signed, envelope, signer = _verify_signed_data(body)
    infos = signed["signer_infos"]
    attrs = _scep_attributes(infos[0])
    if attrs[OID_MESSAGE_TYPE] not in {"19", 19}:
        raise ValueError("Only SCEP PKCSReq is supported.")
    transaction = attrs[OID_TRANSACTION_ID]
    nonce = attrs[OID_SENDER_NONCE]
    if not isinstance(transaction, str) or not 1 <= len(transaction) <= 128:
        raise ValueError("Invalid SCEP transaction identifier.")
    if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 32:
        raise ValueError("Invalid SCEP sender nonce.")
    from app import current_authority
    authority = current_authority()
    if not authority:
        raise ValueError("No active issuing CA.")
    authority, certificate, key = _issuer(authority["id"])
    plaintext = _decrypt_enveloped(envelope, key)
    try:
        inner = _content_info(plaintext)
        inner_content_type = inner["content_type"].native
    except ValueError:
        inner, inner_content_type = None, ""
    if inner is None:
        inner_content = plaintext
    elif inner_content_type == "signed_data":
        content_value = inner["content"]["encap_content_info"]["content"]
        inner_content = content_value.native
        if isinstance(inner_content, dict):
            inner_content = content_value.untag().dump()
    elif inner_content_type == "data":
        inner_content = inner["content"].native
    else:
        inner_content = plaintext
    if not isinstance(inner_content, bytes):
        raise ValueError("PKCSReq CSR is malformed.")
    csr = x509.load_der_x509_csr(inner_content)
    if not csr.is_signature_valid:
        raise ValueError("PKCSReq CSR signature is invalid.")
    secret = _csr_challenge(inner_content)
    secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    row = _db().execute("""SELECT * FROM enrollment_credentials
        WHERE protocol='scep' AND secret_hash=? AND revoked=0 AND used_at IS NULL AND expires>? LIMIT 1""",
        (secret_hash, _stamp())).fetchone()
    if not row:
        raise ValueError("SCEP challengePassword credential is invalid.")
    if row["authority_id"] != authority["id"]:
        raise ValueError("Credential is bound to a different issuing CA.")
    return row, inner_content, transaction, nonce, signer, certificate, key


def _scep_success(row, csr, transaction, nonce, recipient, certificate, key):
    db = _db()
    db.execute("BEGIN IMMEDIATE")
    if db.execute("SELECT 1 FROM enrollment_replays WHERE protocol='scep' AND transaction_id=?", (transaction,)).fetchone():
        raise ValueError("SCEP transaction identifier has already been used.")
    pem, chain = _issue(row, csr)
    _consume(row)
    db.execute("INSERT INTO enrollment_replays VALUES ('scep',?,?)", (transaction, _stamp()))
    certificate_only = _cms_certificates_only([x509.load_pem_x509_certificate(pem.encode()), *chain])
    encrypted = _cms_encrypt(certificate_only, recipient)
    attrs = [
        cms.CMSAttribute({"type": cms.CMSAttributeType(OID_MESSAGE_TYPE), "values": [core.PrintableString("3")]}),
        cms.CMSAttribute({"type": cms.CMSAttributeType(OID_PKI_STATUS), "values": [core.PrintableString("0")]}),
        cms.CMSAttribute({"type": cms.CMSAttributeType(OID_TRANSACTION_ID), "values": [core.PrintableString(transaction)]}),
        cms.CMSAttribute({"type": cms.CMSAttributeType(OID_RECIPIENT_NONCE), "values": [core.OctetString(nonce)]}),
        cms.CMSAttribute({"type": cms.CMSAttributeType(OID_SENDER_NONCE),
                          "values": [core.OctetString(secrets.token_bytes(16))]}),
    ]
    response = _cms_sign(encrypted, key, certificate, content_type="enveloped_data", extra_attrs=attrs)
    db.commit()
    return Response(response, mimetype="application/x-pki-message", headers={"Cache-Control": "no-store"})


@scep_protocol.route("/scep", methods=["GET", "POST"])
def scep_endpoint():
    operation = request.args.get("operation", "")
    if operation == "GetCACaps" and request.method == "GET":
        return Response(b"AES\nSHA-256\nSCEPStandard\nPOSTPKIOperation\n", mimetype="text/plain",
                        headers={"Cache-Control": "no-store"})
    if operation == "GetCACert" and request.method == "GET":
        from app import current_authority, authority_block_reason
        authority = current_authority()
        if not authority or authority_block_reason(authority):
            return Response("Issuing CA unavailable.", status=503)
        certificate = x509.load_pem_x509_certificate(authority["certificate_pem"].encode())
        if not isinstance(certificate.public_key(), rsa.RSAPublicKey):
            return Response("This CA key cannot provide SCEP CMS encryption.", status=503)
        return Response(certificate.public_bytes(serialization.Encoding.DER), mimetype="application/x-x509-ca-cert",
                        headers={"Cache-Control": "no-store"})
    if operation != "PKIOperation":
        return Response("Unsupported SCEP operation.", status=400)
    try:
        _limit("scep:" + (request.remote_addr or "unknown"))
        if request.method == "GET":
            encoded = request.args.get("message", "")
            if len(encoded) > 350000 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", encoded):
                raise ValueError("Invalid SCEP message encoding.")
            body = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        else:
            if request.mimetype != "application/x-pki-message":
                return Response("Use application/x-pki-message.", status=415)
            body = _require_body()
        row, csr, transaction, nonce, recipient, certificate, key = _scep_request(body)
        return _scep_success(row, csr, transaction, nonce, recipient, certificate, key)
    except RequestEntityTooLarge:
        raise
    except EnrollmentAuditError as error:
        _db().rollback()
        return Response(str(error), status=503, headers={"Cache-Control": "no-store"})
    except EnrollmentRateLimitError:
        _db().rollback()
        return Response("Enrollment request limit exceeded.", status=429, headers={"Retry-After": "60", "Cache-Control": "no-store"})
    except (ValueError, TypeError, KeyError, InvalidSignature, UnsupportedAlgorithm, sqlite3.Error) as error:
        _db().rollback()
        current_app.logger.info("SCEP enrollment rejected: %s", error)
        return Response("SCEP enrollment request rejected.", status=400,
                        mimetype="text/plain", headers={"Cache-Control": "no-store"})


@scep_est_admin.route("/settings/scep-est", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    from app import get_db, current_authority, authority_block_reason
    from certificate_profiles import available_templates
    db = get_db()
    credential = None
    config = _config()
    if request.method == "POST":
        from approvals import approval_gate
        response = approval_gate()
        if response is not None:
            return response
        try:
            action = request.form.get("action", "")
            db.execute("BEGIN IMMEDIATE")
            if action == "save":
                validity = int(request.form.get("validity_days", "90"))
                maximum = int(get_setting("max_leaf_days", 397))
                if not 1 <= validity <= maximum:
                    raise ValueError("Enrollment lifetime must fit the configured leaf lifetime.")
                enabled = request.form.get("enabled") == "on"
                scep = request.form.get("scep") == "on"
                est = request.form.get("est") == "on"
                if enabled and not (scep or est):
                    raise ValueError("Select at least one enrollment protocol.")
                if enabled:
                    from urllib.parse import urlsplit
                    base = urlsplit(get_setting("public_base_url", ""))
                    if base.scheme != "https" or not base.hostname:
                        raise ValueError("Configure the HTTPS public base URL before enabling enrollment.")
                    authority = current_authority()
                    if (not authority or authority["role"] != "issuing" or authority["state"] != "active"
                            or authority["revoked_at"] or authority_block_reason(authority)):
                        raise ValueError("An active Issuing CA is required.")
                    if scep:
                        _, ca_certificate, ca_key = _issuer(authority["id"])
                        if not isinstance(ca_certificate.public_key(), rsa.RSAPublicKey) or not isinstance(ca_key, rsa.RSAPrivateKey):
                            raise ValueError("SCEP requires a software RSA Issuing CA key; EST supports configured CA key providers.")
                config = {"enabled": enabled, "scep": scep, "est": est, "validity_days": validity}
                db.execute("INSERT INTO settings VALUES ('scep_est_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                           (json.dumps(config, sort_keys=True),))
                audit_event("scep_est.settings.updated", "settings", "scep_est")
                flash("SCEP/EST settings saved.", "success")
            elif action == "create_credential":
                label = request.form.get("label", "").strip()
                protocol = request.form.get("protocol", "")
                domains = list(dict.fromkeys(_domain(item) for item in re.split(r"[,\r\n]+", request.form.get("domains", "")) if item.strip()))
                template_id = request.form.get("template_id", "")
                validity = int(request.form.get("validity_days", str(config["validity_days"])))
                authority = current_authority()
                templates = available_templates(db)
                template = next((item for item in templates if str(item["id"]) == template_id and item["enabled"]), None)
                live_count = db.execute("""SELECT COUNT(*) FROM enrollment_credentials
                    WHERE revoked=0 AND used_at IS NULL AND expires>?""", (_stamp(),)).fetchone()[0]
                if (not label or len(label) > 100 or protocol not in {"scep", "est"}
                        or not config["enabled"] or not config[protocol] or not authority
                        or authority["role"] != "issuing" or authority["state"] != "active"
                        or authority["revoked_at"] or authority_block_reason(authority)
                        or live_count >= 10000 or template is None or "admin" not in template["roles"] or not domains or len(domains) > 50
                        or not 1 <= validity <= min(config["validity_days"], int(get_setting("max_leaf_days", 397)),
                                                    template["max_validity_days"])):
                    raise ValueError("Provide a label, enabled protocol, permitted template, domains, and lifetime within configured limits.")
                credential = {"id": secrets.token_urlsafe(18), "secret": secrets.token_urlsafe(32)}
                db.execute("""INSERT INTO enrollment_credentials
                    (id,label,protocol,secret_hash,authority_id,template_id,domains,validity_days,created_at,expires)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (credential["id"], label, protocol, hashlib.sha256(credential["secret"].encode()).hexdigest(),
                     authority["id"], template_id, json.dumps(domains), validity, _stamp(),
                     _stamp(datetime.now(UTC) + timedelta(days=365))))
                audit_event("scep_est.credential.created", "enrollment_credential", credential["id"],
                            f"protocol={protocol}; template={template_id}; domains={','.join(domains)}")
            elif action == "revoke_credential":
                identifier = request.form.get("id", "")
                db.execute("UPDATE enrollment_credentials SET revoked=1,secret_hash='' WHERE id=?", (identifier,))
                audit_event("scep_est.credential.revoked", "enrollment_credential", identifier)
                flash("Enrollment credential revoked.", "success")
            else:
                raise ValueError("Unknown SCEP/EST action.")
            db.commit()
            if credential is None:
                return redirect(url_for("scep_est_admin.settings"))
        except (ValueError, TypeError, sqlite3.Error) as error:
            db.rollback()
            flash(str(error), "error")
            credential = None
    return render_template("scep_est_settings.html", title="SCEP / EST enrollment",
        config=config, credential=credential, templates=available_templates(db),
        credentials=db.execute("""SELECT id,label,protocol,authority_id,template_id,domains,
            validity_days,created_at,expires,used_at,revoked FROM enrollment_credentials
            ORDER BY created_at DESC LIMIT 100""").fetchall())


def _domain(value):
    from pki import _dns_name
    value = value.strip().lower().rstrip(".")
    name = _dns_name(value)
    if name.startswith("*.") or len(name.split(".")) < 2:
        raise ValueError("Enter a DNS suffix such as example.com; wildcard entries are not accepted.")
    return name
