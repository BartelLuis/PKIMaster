"""Certificate and CRL construction with an explicit private-PKI issuance policy."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID, NameOID, SignatureAlgorithmOID

from key_backends import ExternalSigner, sign_builder


REVOCATION_REASONS = {
    reason.name: reason
    for reason in (
        x509.ReasonFlags.unspecified,
        x509.ReasonFlags.key_compromise,
        x509.ReasonFlags.ca_compromise,
        x509.ReasonFlags.affiliation_changed,
        x509.ReasonFlags.superseded,
        x509.ReasonFlags.cessation_of_operation,
        x509.ReasonFlags.certificate_hold,
        x509.ReasonFlags.privilege_withdrawn,
        x509.ReasonFlags.aa_compromise,
    )
}
CERTIFICATE_PROFILES = {
    "server": (ExtendedKeyUsageOID.SERVER_AUTH,),
    "client": (ExtendedKeyUsageOID.CLIENT_AUTH,),
    "dual": (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def max_subordinate_depth(role: str) -> int:
    try:
        return {"root": 2, "intermediate": 1, "issuing": 0}[role]
    except KeyError as exc:
        raise ValueError("Unknown certificate authority role.") from exc


def allowed_ca_path_length(role: str, issuer_role: str | None = None) -> int:
    depth = max_subordinate_depth(role)
    if issuer_role is None:
        return depth
    return min(depth, max(max_subordinate_depth(issuer_role) - 1, 0))


def valid_parent_child_roles(parent_role: str, child_role: str) -> bool:
    return child_role in {
        "root": {"intermediate", "issuing"},
        "intermediate": {"issuing"},
        "issuing": set(),
    }.get(parent_role, set())


def build_subject(common_name: str) -> x509.Name:
    if not isinstance(common_name, str):
        raise ValueError("Common name must be text.")
    common_name = common_name.strip()
    try:
        encoded = common_name.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Common name contains invalid Unicode.") from exc
    if not encoded or len(encoded) > 64:
        raise ValueError("Common name must contain 1 to 64 UTF-8 bytes.")
    if any(unicodedata.category(char).startswith("C") for char in common_name):
        raise ValueError("Common name cannot contain control characters.")
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> str:
    if isinstance(private_key, ExternalSigner):
        raise ValueError("External CA private keys cannot be exported.")
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")


def serialize_certificate(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def authority_key_identifier_from_certificate(certificate: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    try:
        identifier = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier(identifier.digest, None, None)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(certificate.public_key())


def _dns_name(value: str) -> str:
    value = value.rstrip(".") if value.endswith(".") and not value.endswith("..") else value
    wildcard = value.startswith("*.")
    hostname = value[2:] if wildcard else value
    if "*" in hostname:
        raise ValueError("A DNS wildcard must occupy the complete leftmost label.")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
        # Validate existing A-labels as well as Unicode input.
        for label in hostname.split("."):
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized DNS name.") from exc
    labels = hostname.split(".")
    if (
        not hostname
        or len(hostname) + (2 if wildcard else 0) > 253
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        or all(label.isdigit() for label in labels)
    ):
        raise ValueError("Invalid DNS subject alternative name.")
    if wildcard and len(labels) < 2:
        raise ValueError("A DNS wildcard requires at least two following labels.")
    return ("*." if wildcard else "") + hostname


def parse_subject_alt_names(entries: Iterable[str] | str) -> list[x509.GeneralName]:
    """Validate DNS/IP names; text input accepts comma or newline separators.

    IP literals become IPAddress extensions, never DNSName extensions. Optional
    DNS: and IP: prefixes are supported. The returned names retain input order.
    """
    if isinstance(entries, str):
        entries = re.split(r"[,\r\n]", entries)
    result: list[x509.GeneralName] = []
    seen: set[tuple[type, str]] = set()
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError("Subject alternative names must be text.")
        value = entry.strip()
        if not value:
            continue
        prefix = ""
        if value[:4].lower() == "dns:":
            prefix, value = "dns", value[4:].strip()
        elif value[:3].lower() == "ip:":
            prefix, value = "ip", value[3:].strip()
        if not value or "%" in value:
            raise ValueError("Invalid subject alternative name.")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            if prefix == "ip" or ":" in value:
                raise ValueError("Invalid IP subject alternative name.") from None
            name = x509.DNSName(_dns_name(value))
        else:
            if prefix == "dns":
                raise ValueError("IP addresses must use IP subject alternative names.")
            name = x509.IPAddress(address)
        identity = (type(name), str(name.value))
        if identity not in seen:
            seen.add(identity)
            result.append(name)
        if len(result) > 100:
            raise ValueError("A certificate may contain at most 100 subject alternative names.")
    return result


def _validate_validity_days(validity_days: int) -> None:
    if isinstance(validity_days, bool) or not isinstance(validity_days, int) or not 1 <= validity_days <= 36500:
        raise ValueError("Validity must be between 1 and 36500 days.")


def _load_private_key(value):
    if isinstance(value, ExternalSigner):
        return value
    return serialization.load_pem_private_key(value.encode("utf-8"), password=None)


def _load_issuer(certificate_pem: str, private_key_pem: str | ExternalSigner, now: datetime, *, crl: bool = False):
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        private_key = _load_private_key(private_key_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid issuer certificate or private key.") from exc
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ExternalSigner)):
        raise ValueError("Issuer must use an RSA or ECDSA key.")
    public_bytes = lambda key: key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if public_bytes(certificate.public_key()) != public_bytes(private_key.public_key()):
        raise ValueError("Issuer certificate and private key do not match.")
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Issuer must contain CA constraints and signing key usage.") from exc
    if not constraints.ca or not (usage.crl_sign if crl else usage.key_cert_sign):
        raise ValueError("Issuer is not authorized for this signing operation.")
    if now < certificate.not_valid_before_utc:
        raise ValueError("Issuer certificate is not yet valid.")
    if now >= certificate.not_valid_after_utc:
        raise ValueError("Issuer certificate has expired.")
    return certificate, private_key, constraints


def _validity_window(now: datetime, validity_days: int, issuer: x509.Certificate | None = None):
    not_before = (now - timedelta(minutes=5)).replace(microsecond=0)
    not_after = (now + timedelta(days=validity_days)).replace(microsecond=0)
    if issuer is not None:
        not_before = max(not_before, issuer.not_valid_before_utc)
        not_after = min(not_after, issuer.not_valid_after_utc)
    return not_before, not_after


def validate_publication_url(value: str, *, label: str = "Publication") -> str:
    """Validate an HTTP(S) URI for public certificate/CRL discovery, without I/O."""
    try:
        if (not isinstance(value, str) or not value or not value.isascii()
                or any(ord(char) <= 32 or ord(char) == 127 for char in value)
                or "\\" in value or "#" in value or re.search(r"%(?![0-9a-fA-F]{2})", value)
                or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)", value, flags=re.IGNORECASE)):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or "%" in parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.netloc.endswith(":") or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if "*" in parsed.hostname or "%" in parsed.hostname:
                raise ValueError from None
            _dns_name(parsed.hostname)
    except ValueError:
        raise ValueError(f"{label} URL must be absolute ASCII HTTP or HTTPS with a valid host and port, without credentials, fragments, backslashes or control characters.") from None
    return value


def _add_crl_distribution_point(builder: x509.CertificateBuilder, crl_url: str | None):
    if crl_url is None:
        return builder
    validate_publication_url(crl_url, label="CRL")
    point = x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)
    return builder.add_extension(x509.CRLDistributionPoints([point]), critical=False)


def _add_authority_information_access(builder: x509.CertificateBuilder, aia_url: str | None):
    if aia_url is None:
        return builder
    validate_publication_url(aia_url, label="Issuer certificate")
    # RFC 5280 4.2.2.1: this location identifies the ISSUER's public certificate,
    # not the new certificate or an OCSP service. The caller chooses its URL.
    access = x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia_url))
    return builder.add_extension(x509.AuthorityInformationAccess([access]), critical=False)


def _certificate_result(certificate: x509.Certificate, private_key=None) -> tuple[str, str, str, str, str]:
    return (
        serialize_certificate(certificate),
        serialize_private_key(private_key) if private_key is not None and not isinstance(private_key, ExternalSigner) else "",
        hex(certificate.serial_number),
        certificate.not_valid_before_utc.isoformat(),
        certificate.not_valid_after_utc.isoformat(),
    )


def create_ca_certificate(
    common_name: str,
    validity_days: int,
    role: str,
    issuer_role: str | None = None,
    issuer_certificate_pem: str | None = None,
    issuer_private_key_pem: str | None = None,
    *,
    crl_url: str | None = None,
    signer: ExternalSigner | None = None,
    aia_url: str | None = None,
) -> tuple[str, str, str, str, str]:
    subject = build_subject(common_name)
    _validate_validity_days(validity_days)
    path_length = allowed_ca_path_length(role, issuer_role)
    now = utc_now()
    issuer = issuer_key = None
    if bool(issuer_certificate_pem) != bool(issuer_private_key_pem):
        raise ValueError("Both issuer certificate and private key are required.")
    if issuer_certificate_pem and issuer_private_key_pem:
        if role == "root" or (issuer_role is not None and not valid_parent_child_roles(issuer_role, role)):
            raise ValueError("Invalid parent and child certificate authority roles.")
        issuer, issuer_key, constraints = _load_issuer(issuer_certificate_pem, issuer_private_key_pem, now)
        if constraints.path_length is not None:
            if constraints.path_length < 1:
                raise ValueError("Issuer path length does not permit subordinate certificate authorities.")
            path_length = min(path_length, constraints.path_length - 1)
    elif role != "root" or issuer_role is not None:
        raise ValueError("Only a root authority may be self-signed.")
    not_before, not_after = _validity_window(now, validity_days, issuer)
    private_key = signer if signer is not None else generate_private_key()
    public_key = private_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            authority_key_identifier_from_certificate(issuer) if issuer else
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    )
    builder = _add_crl_distribution_point(builder, crl_url)
    builder = _add_authority_information_access(builder, aia_url)
    certificate = sign_builder(builder, issuer_key or private_key)
    return _certificate_result(certificate, private_key)


def _validate_exchange_key(public_key) -> None:
    """The CA exchange baseline is deliberately stricter than legacy leaf CSRs."""
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 3072:
            raise ValueError("CA exchange requires RSA keys of at least 3072 bits.")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
            raise ValueError("CA exchange ECDSA keys must use P-256, P-384, or P-521.")
    else:
        raise ValueError("CA exchange requires an RSA or approved ECDSA key.")


def _exchange_public_bytes(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _validate_exchange_hash(signed_object) -> None:
    if not isinstance(signed_object.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
        raise ValueError("Certificate and CSR signatures must use SHA-256, SHA-384, or SHA-512.")


def _strict_pem_blocks(pem: str, label: str, maximum: int, *, allow_empty: bool = False) -> list[bytes]:
    if not isinstance(pem, str) or len(pem) > 262144:
        raise ValueError("CA exchange PEM input must be text no larger than 256 KiB.")
    try:
        raw = pem.encode("ascii")
    except UnicodeError as exc:
        raise ValueError("PEM input must contain ASCII characters only.") from exc
    expression = re.compile(
        rb"-----BEGIN " + label.encode("ascii") + rb"-----[A-Za-z0-9+/=\r\n \t]+-----END "
        + label.encode("ascii") + rb"-----"
    )
    blocks = expression.findall(raw)
    if expression.sub(b"", raw).strip() or len(blocks) > maximum or (not blocks and not allow_empty):
        raise ValueError(f"Provide only {label} PEM blocks, with no extra content or duplicate bundle fields.")
    return blocks


def _validate_ca_extensions(extensions: x509.Extensions, role: str) -> x509.BasicConstraints:
    # We do not implement policy/name-constraint processing; accepting these
    # extensions would allow later issuance outside an imported CA's scope.
    forbidden = {
        ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.POLICY_CONSTRAINTS,
        ExtensionOID.POLICY_MAPPINGS, ExtensionOID.INHIBIT_ANY_POLICY,
        ExtensionOID.EXTENDED_KEY_USAGE,
    }
    supported_critical = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}
    for extension in extensions:
        if extension.oid in forbidden or (extension.critical and extension.oid not in supported_critical):
            raise ValueError("CA exchange contains unsupported critical extensions or issuance constraints.")
    try:
        basic = extensions.get_extension_for_class(x509.BasicConstraints)
        usage = extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound as exc:
        raise ValueError("CA certificates and requests require BasicConstraints and signing KeyUsage.") from exc
    if not basic.critical or not basic.value.ca or basic.value.path_length is None:
        raise ValueError("CA BasicConstraints must be critical, assert CA, and specify a bounded path length.")
    if basic.value.path_length > max_subordinate_depth(role):
        raise ValueError("CA path length exceeds the selected role's permitted depth.")
    flags = usage.value
    if (not usage.critical or not flags.key_cert_sign or not flags.crl_sign or flags.digital_signature
            or flags.content_commitment or flags.key_encipherment or flags.data_encipherment or flags.key_agreement):
        raise ValueError("CA KeyUsage must be critical and authorize only certificate and CRL signing.")
    return basic.value


def _validate_exchange_certificate(certificate: x509.Certificate, role: str, now: datetime) -> x509.BasicConstraints:
    _validate_exchange_key(certificate.public_key())
    _validate_exchange_hash(certificate)
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValueError("Every CA in the activation chain must be currently valid.")
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1:
        raise ValueError("Each CA must have exactly one valid common name.")
    build_subject(names[0].value)
    return _validate_ca_extensions(certificate.extensions, role)


def _verify_exchange_link(child: x509.Certificate, parent: x509.Certificate) -> None:
    child.verify_directly_issued_by(parent)
    if child.not_valid_before_utc < parent.not_valid_before_utc or child.not_valid_after_utc > parent.not_valid_after_utc:
        raise ValueError("A CA's validity must remain within its issuer's validity period.")
    try:
        authority = child.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return
    if authority.key_identifier is not None:
        expected = authority_key_identifier_from_certificate(parent).key_identifier
        if authority.key_identifier != expected:
            raise ValueError("CA authority key identifier does not match the supplied issuer.")
    if authority.authority_cert_serial_number is not None and authority.authority_cert_serial_number != parent.serial_number:
        raise ValueError("CA authority serial number does not match the supplied issuer.")
    if authority.authority_cert_issuer is not None and x509.DirectoryName(parent.issuer) not in authority.authority_cert_issuer:
        raise ValueError("CA authority certificate name does not match the supplied issuer.")


def create_ca_request(common_name: str, role: str, *, signer: ExternalSigner | None = None) -> tuple[str, str]:
    """Create a subordinate CA's key and request on that CA's own server."""
    if role not in {"intermediate", "issuing"}:
        raise ValueError("Only intermediate and issuing authorities request a parent signature.")
    subject = build_subject(common_name)
    private_key = signer if signer is not None else generate_private_key()
    _validate_exchange_key(private_key.public_key())
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.BasicConstraints(True, max_subordinate_depth(role)), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    )
    request = sign_builder(builder, private_key)
    private_pem = "" if isinstance(private_key, ExternalSigner) else serialize_private_key(private_key)
    return request.public_bytes(serialization.Encoding.PEM).decode("ascii"), private_pem


def sign_ca_request(
    csr_pem: str,
    role: str,
    validity_days: int,
    issuer_role: str,
    issuer_certificate_pem: str,
    issuer_private_key_pem: str,
    crl_url: str | None = None,
    *,
    aia_url: str | None = None,
) -> tuple[str, str, str, str]:
    """Sign a remote CA's public request; its private key is never transferred.

    The supplied local issuer must already have an activated, validated chain.
    Requested extensions are validated but rebuilt under this server's policy.
    """
    if not valid_parent_child_roles(issuer_role, role):
        raise ValueError("Invalid parent and child certificate authority roles.")
    _validate_validity_days(validity_days)
    try:
        blocks = _strict_pem_blocks(csr_pem, "CERTIFICATE REQUEST", 1)
        request = x509.load_pem_x509_csr(blocks[0])
        _validate_exchange_key(request.public_key())
        _validate_exchange_hash(request)
        if not request.is_signature_valid:
            raise ValueError("CA request signature is invalid.")
        names = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1 or request.subject != build_subject(names[0].value):
            raise ValueError("CA requests must contain exactly the intended common-name subject.")
        requested = _validate_ca_extensions(request.extensions, role)
        now = utc_now()
        _strict_pem_blocks(issuer_certificate_pem, "CERTIFICATE", 1)
        issuer, issuer_key, _ = _load_issuer(issuer_certificate_pem, issuer_private_key_pem, now)
        constraints = _validate_exchange_certificate(issuer, issuer_role, now)
        if issuer_role == "root":
            _verify_exchange_link(issuer, issuer)
        elif issuer.subject == issuer.issuer:
            raise ValueError("An intermediate issuer must have a separate parent authority.")
        if constraints.path_length < 1:
            raise ValueError("Issuer path length does not permit subordinate certificate authorities.")
        if request.subject == issuer.subject or _exchange_public_bytes(request.public_key()) == _exchange_public_bytes(issuer.public_key()):
            raise ValueError("A remote CA must have a distinct subject and private key from its issuer.")
        not_before, not_after = _validity_window(now, validity_days, issuer)
        builder = (
            x509.CertificateBuilder()
            .subject_name(request.subject)
            .issuer_name(issuer.subject)
            .public_key(request.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(request.public_key()), critical=False)
            .add_extension(authority_key_identifier_from_certificate(issuer), critical=False)
            .add_extension(x509.BasicConstraints(True, min(requested.path_length, constraints.path_length - 1)), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        )
        builder = _add_crl_distribution_point(builder, crl_url)
        builder = _add_authority_information_access(builder, aia_url)
        certificate = sign_builder(builder, issuer_key)
        result = _certificate_result(certificate)
        return result[0], result[2], result[3], result[4]
    except (InvalidSignature, UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType,
            x509.InvalidVersion, TypeError) as exc:
        raise ValueError("CA request or issuer has an invalid signature, key, or unsupported certificate structure.") from exc


def validate_ca_activation(
    certificate_pem: str,
    chain_pem: str,
    private_key_pem: str,
    common_name: str,
    role: str,
) -> str:
    """Validate the returned CA certificate and an ordered, complete parent chain.

    This verifies cryptographic linkage and the local issuance policy. The
    administrator must independently authenticate the selected root trust anchor;
    no external trust store or online revocation service is consulted here.
    The returned canonical PEM contains parents only, immediate issuer first.
    """
    expected_subject = build_subject(common_name)
    max_subordinate_depth(role)
    try:
        certificate = x509.load_pem_x509_certificate(_strict_pem_blocks(certificate_pem, "CERTIFICATE", 1)[0])
        parents = [x509.load_pem_x509_certificate(block)
                   for block in _strict_pem_blocks(chain_pem, "CERTIFICATE", 2, allow_empty=role == "root")]
        if (role == "root" and parents) or (role == "intermediate" and len(parents) != 1):
            raise ValueError("The parent chain does not match the intended CA hierarchy.")
        private_key = _load_private_key(private_key_pem)
        _validate_exchange_key(private_key.public_key())
        if certificate.subject != expected_subject:
            raise ValueError("The returned CA subject does not match the local certificate request.")
        if _exchange_public_bytes(certificate.public_key()) != _exchange_public_bytes(private_key.public_key()):
            raise ValueError("The returned CA public key does not match the local private key.")
        chain = [certificate, *parents]
        fingerprints = [item.fingerprint(hashes.SHA256()) for item in chain]
        public_keys = [_exchange_public_bytes(item.public_key()) for item in chain]
        if len(set(fingerprints)) != len(chain) or len(set(public_keys)) != len(chain):
            raise ValueError("The CA chain contains duplicate certificates or reused authority keys.")
        if len({item.subject for item in chain}) != len(chain):
            raise ValueError("Every CA in the activation chain must have a distinct subject.")
        now = utc_now()
        constraints = []
        for index, item in enumerate(chain):
            item_role = role if index == 0 else ("root" if index == len(chain) - 1 else "intermediate")
            constraints.append(_validate_exchange_certificate(item, item_role, now))
        for index, (child, parent) in enumerate(zip(chain, chain[1:])):
            _verify_exchange_link(child, parent)
            if constraints[index].path_length >= constraints[index + 1].path_length:
                raise ValueError("The subordinate CA's path length exceeds its parent's delegation.")
            if constraints[index + 1].path_length < index + 1:
                raise ValueError("An ancestor's path length does not permit this complete CA chain.")
        root = chain[-1]
        _verify_exchange_link(root, root)
        return "".join(serialize_certificate(parent) for parent in parents)
    except (InvalidSignature, UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType,
            x509.InvalidVersion, TypeError) as exc:
        raise ValueError("CA activation has an invalid signature, key, or unsupported certificate structure.") from exc


def _csr_key_and_names(csr_pem: str, minimum_rsa_bits: int = 2048):
    if len(csr_pem) > 65536:
        raise ValueError("CSR exceeds the 64 KiB size limit.")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if minimum_rsa_bits >= 3072:
            _validate_exchange_hash(csr)
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid.")
        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < minimum_rsa_bits:
                raise ValueError(f"CSR RSA keys must be at least {minimum_rsa_bits} bits.")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not isinstance(public_key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
                raise ValueError("CSR ECDSA keys must use P-256, P-384, or P-521.")
        else:
            raise ValueError("CSR must use an RSA or supported ECDSA key.")
        names: list[str] = []
        for extension in csr.extensions:
            if isinstance(extension.value, x509.BasicConstraints) and extension.value.ca:
                raise ValueError("A CA CSR cannot be used to issue an end-entity certificate.")
            if isinstance(extension.value, x509.KeyUsage) and (extension.value.key_cert_sign or extension.value.crl_sign):
                raise ValueError("A CSR requesting CA signing usage is not permitted.")
            if isinstance(extension.value, x509.SubjectAlternativeName):
                for name in extension.value:
                    if isinstance(name, x509.DNSName):
                        names.append("DNS:" + name.value)
                    elif isinstance(name, x509.IPAddress) and isinstance(name.value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        names.append("IP:" + str(name.value))
                    else:
                        raise ValueError("CSR subject alternative names must be DNS names or IP addresses.")
        return public_key, parse_subject_alt_names(names)
    except (UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as exc:
        raise ValueError("CSR contains an unsupported algorithm or malformed extensions.") from exc


def issue_end_entity_certificate(
    common_name: str,
    issuer_certificate_pem: str,
    issuer_private_key_pem: str,
    validity_days: int,
    subject_alt_names: Iterable[str],
    *,
    profile: str = "server",
    csr_pem: str | None = None,
    crl_url: str | None = None,
    minimum_rsa_bits: int = 2048,
    aia_url: str | None = None,
) -> tuple[str, str, str, str, str]:
    """Issue under a fixed EKU profile; explicit SANs replace requested CSR SANs.

    The explicit common name always supplies the subject. CSR extensions other
    than validated DNS/IP SANs are never copied. CSR issuance returns an empty
    private-key field because that key remains with its requester.
    """
    subject = build_subject(common_name)
    _validate_validity_days(validity_days)
    if isinstance(minimum_rsa_bits, bool) or not isinstance(minimum_rsa_bits, int) or minimum_rsa_bits < 2048:
        raise ValueError("Minimum RSA key length must be an integer of at least 2048 bits.")
    if profile not in CERTIFICATE_PROFILES:
        raise ValueError("Certificate profile must be server, client, or dual.")
    now = utc_now()
    issuer, issuer_key, _ = _load_issuer(issuer_certificate_pem, issuer_private_key_pem, now)
    names = parse_subject_alt_names(subject_alt_names)
    private_key = None
    if csr_pem is not None:
        public_key, csr_names = _csr_key_and_names(csr_pem, minimum_rsa_bits)
        names = names or csr_names
    else:
        public_key = None
    if not names and profile in {"server", "dual"}:
        names = parse_subject_alt_names([common_name])
    if public_key is None:
        private_key = generate_private_key()
        public_key = private_key.public_key()
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < minimum_rsa_bits:
        raise ValueError(f"RSA keys must be at least {minimum_rsa_bits} bits.")
    not_before, not_after = _validity_window(now, validity_days, issuer)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier_from_certificate(issuer), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, isinstance(public_key, rsa.RSAPublicKey), False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(CERTIFICATE_PROFILES[profile]), critical=False)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    builder = _add_crl_distribution_point(builder, crl_url)
    builder = _add_authority_information_access(builder, aia_url)
    return _certificate_result(sign_builder(builder, issuer_key), private_key)


def build_crl(
    issuer_certificate_pem: str,
    issuer_private_key_pem: str,
    revoked_entries: Iterable[Mapping[str, object]],
    crl_number: int,
    validity_days: int,
) -> bytes:
    """Produce a full DER CRL; serial numbers use the application's hex format."""
    _validate_validity_days(validity_days)
    if isinstance(crl_number, bool) or not isinstance(crl_number, int) or not 0 <= crl_number < 2**159:
        raise ValueError("CRL number must be a nonnegative integer of at most 159 bits.")
    now = utc_now()
    issuer, issuer_key, _ = _load_issuer(issuer_certificate_pem, issuer_private_key_pem, now, crl=True)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(now.replace(microsecond=0))
        .next_update(min((now + timedelta(days=validity_days)).replace(microsecond=0), issuer.not_valid_after_utc))
        .add_extension(authority_key_identifier_from_certificate(issuer), critical=False)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )
    seen: set[int] = set()
    for entry in revoked_entries:
        try:
            serial = int(str(entry["serial_number"]), 16)
            revoked_at = datetime.fromisoformat(str(entry["revoked_at"]))
            reason = REVOCATION_REASONS[str(entry["revocation_reason"])]
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("Invalid CRL revocation entry.") from exc
        if serial in seen or not 0 < serial < 2**159:
            raise ValueError("CRL serial numbers must be unique positive integers of at most 159 bits.")
        if revoked_at.tzinfo is None or revoked_at > now:
            raise ValueError("Revocation time must include a timezone and cannot be in the future.")
        seen.add(serial)
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return sign_builder(builder, issuer_key).public_bytes(serialization.Encoding.DER)


def crl_signature_is_valid(crl: x509.CertificateRevocationList, public_key) -> bool:
    """Verify approved CRL signatures, including PSS on Debian cryptography 43.

    That release can create RSA-PSS CRLs but does not decode their hash through
    signature_hash_algorithm. Parse the signed algorithm parameters explicitly;
    never assume a hash, MGF, or salt length from the signature OID alone.
    """
    try:
        if crl.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
            from asn1crypto import crl as asn1_crl
            document = asn1_crl.CertificateList.load(crl.public_bytes(serialization.Encoding.DER), strict=True)
            algorithm = document["signature_algorithm"]
            if algorithm.dump() != document["tbs_cert_list"]["signature"].dump() or not isinstance(public_key, rsa.RSAPublicKey):
                return False
            parameters = algorithm["parameters"]
            digest_name = parameters["hash_algorithm"]["algorithm"].native
            digest = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}.get(digest_name)
            mask = parameters["mask_gen_algorithm"]
            if (digest is None or mask["algorithm"].native != "mgf1"
                    or mask["parameters"]["algorithm"].native != digest_name
                    or parameters["trailer_field"].native != "trailer_field_bc"):
                return False
            digest = digest()
            salt_length = parameters["salt_length"].native
            if salt_length != digest.digest_size:
                return False
            public_key.verify(crl.signature, crl.tbs_certlist_bytes,
                              padding.PSS(mgf=padding.MGF1(digest), salt_length=salt_length), digest)
            return True
        if not isinstance(crl.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            return False
        return crl.is_signature_valid(public_key)
    except (InvalidSignature, ValueError, TypeError, KeyError, UnsupportedAlgorithm):
        return False
