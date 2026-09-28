"""Verify the certificate actually deployed at an explicitly configured TLS service."""
from __future__ import annotations

import socket
import ssl
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from monitoring_transports import MonitoringError, TIMEOUT, resolve_address


def inspect_endpoint(host, port, server_name, trust_pem):
    """A pinned TCP destination, trusted issuer chain, hostname and bounded TLS handshake."""
    address = resolve_address(host, port)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=trust_pem)
    raw = None
    try:
        raw = socket.create_connection((address, port), timeout=TIMEOUT)
        # SSL inherits this timeout; Python bounds the entire handshake by it.
        with context.wrap_socket(raw, server_hostname=server_name or host) as connection:
            certificate = x509.load_der_x509_certificate(connection.getpeercert(binary_form=True))
            return {"sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                    "not_after": certificate.not_valid_after_utc.isoformat(),
                    "subject": certificate.subject.rfc4514_string()[:500]}
    except ssl.SSLCertVerificationError as exc:
        raise MonitoringError("The deployed certificate's chain, hostname or validity could not be verified.") from exc
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise MonitoringError("The configured TLS service is unavailable or did not complete a valid TLS handshake.") from exc
    finally:
        if raw:
            raw.close()


def collect_endpoint_findings(db, now, warning_days):
    from monitoring import _finding, _expiry
    rows = [dict(row) for row in db.execute("""SELECT c.*,a.certificate_pem AS issuer_pem,a.parent_chain_pem,
        a.revoked_at AS issuer_revoked,e.checked_at FROM certificates c JOIN authorities a ON a.id=c.authority_id
        LEFT JOIN certificate_endpoint_checks e ON e.certificate_id=c.id
        WHERE c.tls_enabled=1 ORDER BY COALESCE(e.checked_at,''),c.id""")]
    findings, preserved = [], set()
    deadline = time.monotonic() + 40
    for index, row in enumerate(rows):
        key = f"deployment:{row['id']}"
        if index >= 8 or time.monotonic() >= deadline:
            preserved.update({key, key + ":expiry"})
            continue
        observed = {}
        try:
            observed = inspect_endpoint(row["tls_host"], row["tls_port"], row["tls_server_name"], row["issuer_pem"] + row["parent_chain_pem"])
            expected = x509.load_pem_x509_certificate(row["certificate_pem"].encode()).fingerprint(hashes.SHA256()).hex()
            if row["revoked_at"] or row["issuer_revoked"]:
                status, detail = "revoked", "The configured certificate or its issuing CA is revoked. Replace it on this service."
            elif observed["sha256"] != expected:
                status, detail = "mismatch", "The service presents a different certificate. Deploy the expected certificate and its chain."
            else:
                status, detail = "current", "The service presents the expected certificate with a valid hostname and trusted chain."
        except MonitoringError as exc:
            status, detail = "failed", str(exc)
        # Recheck the target after network I/O: a concurrent edit or renewal
        # must not attach a stale result to the new deployment configuration.
        db.execute("BEGIN IMMEDIATE")
        current = db.execute("""SELECT c.tls_enabled,c.tls_host,c.tls_port,c.tls_server_name,c.revoked_at,
            a.revoked_at AS issuer_revoked FROM certificates c JOIN authorities a ON a.id=c.authority_id
            WHERE c.id=?""", (row["id"],)).fetchone()
        if current is None or not current["tls_enabled"] or any(current[name] != row[name] for name in ("tls_host", "tls_port", "tls_server_name")):
            db.rollback()
            continue
        if current["revoked_at"] or current["issuer_revoked"]:
            status, detail = "revoked", "The configured certificate or its issuing CA is revoked. Replace it on this service."
        db.execute("""INSERT INTO certificate_endpoint_checks
            (certificate_id,checked_at,status,detail,observed_sha256,observed_not_after,observed_subject)
            VALUES (?,?,?,?,?,?,?) ON CONFLICT(certificate_id) DO UPDATE SET checked_at=excluded.checked_at,
            status=excluded.status,detail=excluded.detail,observed_sha256=excluded.observed_sha256,
            observed_not_after=excluded.observed_not_after,observed_subject=excluded.observed_subject""",
            (row["id"], now.isoformat(), status, detail, observed.get("sha256", ""), observed.get("not_after", ""), observed.get("subject", "")))
        db.commit()
        title = "Deployed certificate: " + row["common_name"]
        if status != "current":
            findings.append(_finding(key, title, detail, status + ":" + observed.get("sha256", ""), "error" if status in {"failed", "revoked"} else "warning"))
        if observed.get("not_after"):
            expiry = _expiry(key + ":expiry", title, observed["not_after"], now, warning_days)
            if expiry:
                findings.append(expiry)
    return findings, preserved
