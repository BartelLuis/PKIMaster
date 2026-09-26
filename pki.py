"""Certificate and CRL construction with an explicit private-PKI issuance policy."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


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


def _load_issuer(certificate_pem: str, private_key_pem: str, now: datetime, *, crl: bool = False):
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid issuer certificate or private key.") from exc
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
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


def _add_crl_distribution_point(builder: x509.CertificateBuilder, crl_url: str | None):
    if crl_url is None:
        return builder
    try:
        parsed = urlsplit(crl_url)
        valid = (
            parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.fragment
            and parsed.username is None and parsed.password is None and parsed.port != 0
            and crl_url.isascii() and not any(char.isspace() or ord(char) < 32 for char in crl_url)
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("CRL URL must be an absolute ASCII HTTP or HTTPS URL without credentials.")
    point = x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)
    return builder.add_extension(x509.CRLDistributionPoints([point]), critical=False)


def _certificate_result(certificate: x509.Certificate, private_key=None) -> tuple[str, str, str, str, str]:
    return (
        serialize_certificate(certificate),
        serialize_private_key(private_key) if private_key is not None else "",
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
    private_key = generate_private_key()
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
    certificate = builder.sign(issuer_key or private_key, hashes.SHA256())
    return _certificate_result(certificate, private_key)


def _csr_key_and_names(csr_pem: str):
    if len(csr_pem) > 65536:
        raise ValueError("CSR exceeds the 64 KiB size limit.")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid.")
        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                raise ValueError("CSR RSA keys must be at least 2048 bits.")
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
) -> tuple[str, str, str, str, str]:
    """Issue under a fixed EKU profile; explicit SANs replace requested CSR SANs.

    The explicit common name always supplies the subject. CSR extensions other
    than validated DNS/IP SANs are never copied. CSR issuance returns an empty
    private-key field because that key remains with its requester.
    """
    subject = build_subject(common_name)
    _validate_validity_days(validity_days)
    if profile not in CERTIFICATE_PROFILES:
        raise ValueError("Certificate profile must be server, client, or dual.")
    now = utc_now()
    issuer, issuer_key, _ = _load_issuer(issuer_certificate_pem, issuer_private_key_pem, now)
    names = parse_subject_alt_names(subject_alt_names)
    private_key = None
    if csr_pem is not None:
        public_key, csr_names = _csr_key_and_names(csr_pem)
        names = names or csr_names
    else:
        public_key = None
    if not names and profile in {"server", "dual"}:
        names = parse_subject_alt_names([common_name])
    if public_key is None:
        private_key = generate_private_key()
        public_key = private_key.public_key()
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
    return _certificate_result(builder.sign(issuer_key, hashes.SHA256()), private_key)


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
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
