"""CA deletion removes deployment alerts and late network results cannot recreate them."""
from datetime import UTC, datetime, timedelta
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import create_app, get_db
from monitoring import _finding, _record_findings, delete_authority_monitoring
from tls_monitoring import collect_endpoint_findings


class DeploymentCleanupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": directory.name})
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.db = get_db()
        self.now = datetime.now(UTC)
        # These fixtures exercise database ownership only; no TLS certificate
        # parsing or network operation is needed to reproduce the deletion race.
        for ca_id, certificate_id in ((1, 1), (2, 10)):
            self.db.execute("""INSERT INTO authorities
                (id,name,role,common_name,certificate_pem,private_key_pem,serial_number,not_before,not_after,revoked_at)
                VALUES (?,?,'issuing',?,'fixture','',?,?,?,?)""",
                (ca_id, f"CA {ca_id}", f"CA {ca_id}", str(ca_id), self.now.isoformat(),
                 (self.now + timedelta(days=365)).isoformat(), self.now.isoformat()))
            self.db.execute("""INSERT INTO certificates
                (id,common_name,authority_id,certificate_pem,private_key_pem,serial_number,not_before,not_after)
                VALUES (?,?,?,'fixture','',?,?,?)""",
                (certificate_id, f"service-{certificate_id}.example", ca_id, str(certificate_id),
                 self.now.isoformat(), (self.now + timedelta(days=30)).isoformat()))
        self.findings = [_finding(key, "Deployment", "Fixture finding", "failed", "error") for key in (
            "deployment:1", "deployment:1:expiry", "certificate:1:expiry",
            "deployment:10", "deployment:10:expiry", "certificate:10:expiry")]
        _record_findings(self.db, self.findings, self.now, 0)
        self.db.commit()

    def keys(self):
        return {row[0] for row in self.db.execute("SELECT finding_key FROM monitoring_findings")}

    def test_cleanup_removes_all_owned_deployment_findings_without_prefix_collision(self):
        self.db.execute("BEGIN IMMEDIATE")
        delete_authority_monitoring(self.db, 1)
        self.db.commit()
        self.assertEqual(self.keys(), {"deployment:10", "deployment:10:expiry", "certificate:10:expiry"})

    def test_late_tls_results_do_not_recreate_deleted_certificate_findings(self):
        self.db.execute("BEGIN IMMEDIATE")
        delete_authority_monitoring(self.db, 1)
        self.db.execute("DELETE FROM certificates WHERE id=1")
        self.db.execute("DELETE FROM authorities WHERE id=1")
        self.db.commit()
        # A network result captured before deletion arrives after the records
        # and their findings have already been removed.
        self.db.execute("BEGIN IMMEDIATE")
        _record_findings(self.db, self.findings, self.now, 0)
        self.db.commit()
        self.assertEqual(self.keys(), {"deployment:10", "deployment:10:expiry", "certificate:10:expiry"})
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM monitoring_findings WHERE active=1").fetchone()[0], 3)

    def test_revocation_during_tls_handshake_is_recorded_instead_of_current(self):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.example")])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                       .serial_number(100).not_valid_before(self.now - timedelta(days=1))
                       .not_valid_after(self.now + timedelta(days=90)).sign(key, hashes.SHA256()))
        self.db.execute("UPDATE certificates SET certificate_pem=?,tls_enabled=1,tls_host='service.example' WHERE id=1",
                        (certificate.public_bytes(serialization.Encoding.PEM).decode(),))
        # Use a separate fresh, non-revoked issuer: the other two authorities in
        # this fixture intentionally model archived CAs and cannot be unrevoked.
        self.db.execute("""INSERT INTO authorities
            (id,name,role,common_name,certificate_pem,private_key_pem,serial_number,not_before,not_after)
            VALUES (3,'Current CA','issuing','Current CA','fixture','','3',?,?)""",
                        (self.now.isoformat(), (self.now + timedelta(days=365)).isoformat()))
        self.db.execute("UPDATE certificates SET authority_id=3 WHERE id=1")
        self.db.commit()
        observed = {"sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                    "not_after": certificate.not_valid_after_utc.isoformat(), "subject": "CN=service.example"}

        def complete_handshake(*_):
            self.db.execute("UPDATE certificates SET revoked_at=? WHERE id=1", (self.now.isoformat(),))
            self.db.commit()
            return observed

        with patch("tls_monitoring.inspect_endpoint", side_effect=complete_handshake):
            findings, _ = collect_endpoint_findings(self.db, self.now, [30, 7])
        self.assertEqual(self.db.execute("SELECT status FROM certificate_endpoint_checks WHERE certificate_id=1").fetchone()[0], "revoked")
        self.assertEqual(findings[0]["signature"], "revoked:" + observed["sha256"])
        self.assertEqual(findings[0]["severity"], "error")


if __name__ == "__main__":
    unittest.main()
