"""Real PKI snapshots, notification state transitions and console authorization."""
from datetime import UTC, datetime, timedelta
import json
import re
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app, get_db
from audit_integrity import AuditIntegrityError
from mfa_helpers import complete_mfa
import monitoring
from monitoring_transports import MonitoringError
import pki


class MonitoringTests(unittest.TestCase):
    password = "monitoring administrator passphrase"
    base = "https://localhost"

    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with patch("pki.generate_private_key", return_value=rsa.generate_private_key(public_exponent=65537, key_size=3072)):
            cls.parent = pki.create_ca_certificate("Monitoring parent", 365, "root")

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        generator = patch("pki.generate_private_key", return_value=self.key)
        generator.start()
        self.addCleanup(generator.stop)
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": directory.name})
        self.client = self.app.test_client()
        self.post("/setup", {"username": "admin", "password": self.password, "password_confirm": self.password,
                             "organization": "Monitor tests", "public_base_url": "https://pki.example"})
        complete_mfa(self.client, self.app)

    def get(self, path, client=None):
        return (client or self.client).get(path, base_url=self.base, follow_redirects=True)

    def post(self, path, values=None, client=None):
        client = client or self.client
        page = self.get("/", client)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        return client.post(path, base_url=self.base, data={"csrf_token": token, **(values or {})}, follow_redirects=True)

    def create_ca(self, days=365, role="root"):
        response = self.post("/authorities", {"name": "Monitor CA", "common_name": "Monitor CA", "role": role, "validity_days": str(days)})
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            return dict(get_db().execute("SELECT * FROM authorities").fetchone())

    def configure(self, **updates):
        data = {"channel": "none", "warning_days": "30,14,7", "crl_warning_hours": "24"}
        data.update(updates)
        response = self.post("/monitoring/settings", data)
        self.assertEqual(response.status_code, 200, response.data)
        return response

    def cycle(self):
        with self.app.app_context():
            return monitoring.run_monitoring_cycle()

    def findings(self, active=True):
        with self.app.app_context():
            return [dict(row) for row in get_db().execute("SELECT * FROM monitoring_findings WHERE active=?", (int(active),))]

    def execute(self, sql, parameters=()):
        with self.app.app_context():
            get_db().execute(sql, parameters)
            get_db().commit()

    def test_fresh_installation_checks_without_network_or_notifications(self):
        with patch("monitoring.http_request") as retrieve, patch("monitoring.deliver") as deliver:
            self.assertEqual(self.cycle(), {"status": "checked", "active": 0, "delivered": 0})
        retrieve.assert_not_called()
        deliver.assert_not_called()
        self.assertIn(b"No active findings", self.get("/monitoring").data)

    def test_expiry_escalates_deduplicates_recovers_and_recurs(self):
        self.create_ca(days=20)
        self.configure(channel="webhook", webhook_url="https://hooks.example/events", webhook_token="monitor-token")
        with patch("monitoring.deliver") as deliver:
            self.assertEqual(self.cycle()["delivered"], 1)
            initial = deliver.call_args.args[1][0]
            self.assertEqual(initial["status"], "active")
            self.assertEqual(self.cycle()["delivered"], 0)
            self.execute("UPDATE authorities SET not_after=?", ((datetime.now(UTC) + timedelta(days=6)).isoformat(),))
            self.assertEqual(self.cycle()["delivered"], 1)
            self.assertIn("within 7 days", deliver.call_args.args[1][0]["detail"])
            self.execute("UPDATE authorities SET not_after=?", ((datetime.now(UTC) + timedelta(days=90)).isoformat(),))
            self.assertEqual(self.cycle()["delivered"], 1)
            self.assertEqual(deliver.call_args.args[1][0]["status"], "resolved")
            self.execute("UPDATE authorities SET not_after=?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),))
            self.assertEqual(self.cycle()["delivered"], 1)
            latest = deliver.call_args.args[1][0]
            self.assertEqual(latest["severity"], "error")
            self.assertNotEqual(latest["id"], initial["id"])
            self.assertEqual(deliver.call_count, 4)

    def test_delivery_failure_retries_same_event_with_backoff(self):
        self.create_ca(days=20)
        self.configure(channel="webhook", webhook_url="https://hooks.example/events")
        with patch("monitoring.deliver", side_effect=MonitoringError("Delivery unavailable.")) as deliver:
            self.assertEqual(self.cycle()["status"], "failed")
            first = deliver.call_args.args[1]
            self.assertEqual(self.cycle()["delivered"], 0)
            self.assertEqual(deliver.call_count, 1)
        self.execute("UPDATE monitoring_state SET next_attempt_at=0")
        with patch("monitoring.deliver") as deliver:
            self.assertEqual(self.cycle()["delivered"], 1)
            self.assertEqual(deliver.call_args.args[1], first)
        with self.app.app_context():
            state = get_db().execute("SELECT * FROM monitoring_state").fetchone()
            self.assertEqual((state["failures"], state["notification_error"]), (0, ""))

    def test_enabling_notifications_sends_existing_active_findings_only(self):
        self.create_ca(days=20)
        self.configure()
        self.cycle()
        self.configure(channel="webhook", webhook_url="https://hooks.example/events")
        with patch("monitoring.deliver") as deliver:
            self.assertEqual(self.cycle()["delivered"], 1)
            self.assertEqual(deliver.call_args.args[1][0]["status"], "active")
        self.configure()
        self.execute("UPDATE authorities SET not_after=?", ((datetime.now(UTC) + timedelta(days=100)).isoformat(),))
        self.cycle()
        self.configure(channel="webhook", webhook_url="https://other.example/events")
        with patch("monitoring.deliver") as deliver:
            self.cycle()
            # A delivered active finding still requires its recovery notice.
            self.assertEqual(deliver.call_args.args[1][0]["status"], "resolved")

    def test_unsent_condition_resolved_while_disabled_is_not_notified(self):
        self.create_ca(days=20)
        self.configure()
        self.cycle()
        self.execute("UPDATE authorities SET not_after=?", ((datetime.now(UTC) + timedelta(days=100)).isoformat(),))
        self.cycle()
        self.configure(channel="webhook", webhook_url="https://hooks.example/events")
        with patch("monitoring.deliver") as deliver:
            self.cycle()
        deliver.assert_not_called()

    def test_real_public_crl_is_checked_and_wrong_content_is_a_finding(self):
        self.create_ca()
        content = self.get("/crl/1.crl").data
        with patch("monitoring.http_request", return_value=content) as retrieve:
            self.assertEqual(self.cycle()["active"], 0)
            retrieve.assert_called_once_with("https://pki.example/crl/1.crl")
        with patch("monitoring.http_request", return_value=b"<html>successful web server response</html>"):
            self.assertEqual(self.cycle()["active"], 1)
        self.assertIn("supported signed CRL", self.findings()[0]["detail"])

    def test_successful_sftp_does_not_hide_unavailable_public_endpoint(self):
        self.create_ca()
        self.execute("UPDATE publication_state SET last_success=?,last_error=''", (datetime.now(UTC).isoformat(),))
        with patch("monitoring.http_request", side_effect=MonitoringError("Public retrieval unavailable.")):
            self.assertEqual(self.cycle()["active"], 1)
        self.assertEqual(self.findings()[0]["detail"], "Public retrieval unavailable.")

    def test_old_signed_crl_and_omitted_local_revocations_are_rejected(self):
        authority = self.create_ca()
        content = self.get("/crl/1.crl").data
        now = datetime.now(UTC)
        with self.app.app_context():
            cached = dict(get_db().execute("SELECT * FROM crls").fetchone())
        with self.assertRaisesRegex(MonitoringError, "older than"):
            monitoring.validate_public_crl(content, authority, {**cached, "number": cached["number"] + 1}, set(), now)
        with self.assertRaisesRegex(MonitoringError, "omits locally"):
            monitoring.validate_public_crl(content, authority, cached, {999}, now)

    def test_wrong_signer_expired_and_scoped_crls_are_rejected(self):
        authority = self.create_ca()
        wrong = pki.build_crl(self.parent[0], self.parent[1], [], 1, 7)
        now = datetime.now(UTC)
        with self.assertRaisesRegex(MonitoringError, "wrong issuer"):
            monitoring.validate_public_crl(wrong, authority, None, set(), now)
        cert = x509.load_pem_x509_certificate(authority["certificate_pem"].encode())
        builder = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
                   .last_update(now - timedelta(days=3)).next_update(now - timedelta(days=1))
                   .add_extension(x509.CRLNumber(2), False))
        expired = builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        with self.assertRaisesRegex(MonitoringError, "expired"):
            monitoring.validate_public_crl(expired, authority, None, set(), now)
        scoped = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject).last_update(now - timedelta(seconds=1))
                  .next_update(now + timedelta(days=1)).add_extension(x509.CRLNumber(2), False)
                  .add_extension(x509.DeltaCRLIndicator(1), True).sign(self.key, hashes.SHA256())
                  .public_bytes(serialization.Encoding.DER))
        with self.assertRaisesRegex(MonitoringError, "full, direct"):
            monitoring.validate_public_crl(scoped, authority, None, set(), now)

    def test_missing_public_url_is_explicit_and_can_be_disabled(self):
        self.create_ca()
        self.execute("UPDATE settings SET value='' WHERE key='public_base_url'")
        with patch("monitoring.http_request") as retrieve:
            self.cycle()
        retrieve.assert_not_called()
        self.assertIn("No public CRL URL", self.findings()[0]["detail"])
        self.configure()
        self.assertEqual(self.cycle()["active"], 1)
        self.assertIn(b"retain their last observed state", self.get("/monitoring").data)

    def test_disabled_public_check_does_not_claim_recovery(self):
        self.create_ca()
        content = self.get("/crl/1.crl").data
        self.configure(channel="webhook", webhook_url="https://hooks.example/events", public_checks="on")
        with patch("monitoring.http_request", side_effect=MonitoringError("Public retrieval unavailable.")), patch("monitoring.deliver"):
            self.assertEqual(self.cycle()["delivered"], 1)
        before = self.findings()[0]
        self.configure(channel="webhook", webhook_url="https://hooks.example/events")
        with patch("monitoring.http_request") as retrieve, patch("monitoring.deliver") as deliver:
            result = self.cycle()
        self.assertEqual((result["active"], result["delivered"]), (1, 0))
        self.assertEqual(self.findings()[0]["last_seen"], before["last_seen"])
        retrieve.assert_not_called()
        deliver.assert_not_called()
        self.configure(channel="webhook", webhook_url="https://hooks.example/events", public_checks="on")
        with patch("monitoring.http_request", return_value=content), patch("monitoring.deliver") as deliver:
            self.assertEqual(self.cycle()["delivered"], 1)
        self.assertEqual(deliver.call_args.args[1][0]["status"], "resolved")

    def test_deferred_check_preserves_observation_and_deduplicates_coverage_warning(self):
        self.create_ca()
        content = self.get("/crl/1.crl").data
        self.configure(channel="webhook", webhook_url="https://hooks.example/events", public_checks="on")
        with patch("monitoring.http_request", side_effect=MonitoringError("Public retrieval unavailable.")), patch("monitoring.deliver"):
            self.cycle()
        before = self.findings()[0]
        for expected in (1, 0):
            with patch("monitoring.time.monotonic", side_effect=[0, 50]), patch("monitoring.http_request") as retrieve:
                with patch("monitoring.deliver"):
                    result = self.cycle()
            retrieve.assert_not_called()
            self.assertEqual((result["active"], result["delivered"]), (2, expected))
        public = next(row for row in self.findings() if row["finding_key"].endswith(":public"))
        self.assertEqual((public["event_id"], public["last_seen"]), (before["event_id"], before["last_seen"]))
        self.assertEqual(self.findings(active=False), [])
        with patch("monitoring.http_request", return_value=content), patch("monitoring.deliver") as deliver:
            self.assertEqual(self.cycle()["delivered"], 2)
        self.assertTrue(all(event["status"] == "resolved" for event in deliver.call_args.args[1]))

    def test_parent_chain_and_crl_expiry_report_operational_blocker(self):
        authority = self.create_ca(role="issuing")
        signed = pki.sign_ca_request(authority["csr_pem"], "issuing", 90, "root", self.parent[0], self.parent[1])
        root = x509.load_pem_x509_certificate(self.parent[0].encode())
        response = self.post("/ca/activate", {"certificate_pem": signed[0], "chain_pem": self.parent[0],
                                             "trusted_root_sha256": root.fingerprint(hashes.SHA256()).hex()})
        self.assertIn(b"CA certificate imported", response.data)
        self.configure()
        self.cycle()
        self.assertTrue(any("Parent status" in row["title"] for row in self.findings()))
        crl = pki.build_crl(self.parent[0], self.parent[1], [], 1, 1)
        self.post("/ca/parent-crls", {"parent_crls_pem": x509.load_der_x509_crl(crl).public_bytes(serialization.Encoding.PEM).decode()})
        self.cycle()
        findings = self.findings()
        self.assertTrue(any("Parent CRL" in row["title"] for row in findings))
        self.assertFalse(any("Parent status" in row["title"] for row in findings))

    def test_thresholds_and_notification_configuration_are_validated(self):
        for update in ({"warning_days": "0"}, {"warning_days": "1,2,3,4,5,6,7,8,9"},
                       {"crl_warning_hours": "169"}, {"channel": "webhook", "webhook_url": "http://hooks.example"},
                       {"channel": "webhook", "webhook_url": "https://user:secret@hooks.example"},
                       {"channel": "email", "smtp_host": "mail.example", "smtp_security": "none"}):
            with self.subTest(update=update):
                response = self.post("/monitoring/settings", {"warning_days": "30,14,7", "crl_warning_hours": "24", **update})
                self.assertEqual(response.status_code, 400)

    def test_secrets_are_encrypted_preserved_and_not_moved_to_another_destination(self):
        secret = "private-monitoring-webhook-token"
        self.configure(channel="webhook", webhook_url="https://hooks.example/events", webhook_token=secret)
        response = self.configure(channel="webhook", webhook_url="https://hooks.example/events")
        with self.app.app_context():
            self.assertEqual(monitoring.configuration()["webhook_token"], secret)
            stored = get_db().execute("SELECT value FROM settings WHERE key='monitoring_config'").fetchone()[0]
            audit = json.dumps([dict(row) for row in get_db().execute("SELECT * FROM audit_events")])
        for content in (stored, audit, response.data.decode()):
            self.assertNotIn(secret, content)
        response = self.post("/monitoring/settings", {"channel": "webhook", "webhook_url": "https://elsewhere.example/events"})
        self.assertEqual(response.status_code, 400)
        self.configure(channel="webhook", webhook_url="https://elsewhere.example/events", clear_webhook_token="on")
        with self.app.app_context():
            self.assertEqual(monitoring.configuration()["webhook_token"], "")

    def test_read_access_for_all_roles_but_changes_and_checks_require_admin_and_csrf(self):
        self.assertEqual(self.client.post("/monitoring/check", base_url=self.base).status_code, 403)
        self.assertEqual(self.client.post("/monitoring/settings", base_url=self.base).status_code, 403)
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/monitoring", base_url=self.base).status_code, 302)
        for role in ("operator", "auditor"):
            self.post("/users", {"username": role, "role": role, "password": self.password})
            client = self.app.test_client()
            self.post("/login", {"username": role, "password": self.password}, client)
            complete_mfa(client, self.app, role)
            self.assertEqual(self.get("/monitoring", client).status_code, 200)
            self.assertEqual(self.get("/monitoring/settings", client).status_code, 403)
            self.assertEqual(self.post("/monitoring/check", client=client).status_code, 403)

    def test_pending_restore_and_concurrent_worker_do_no_network_work(self):
        with self.app.app_context():
            with monitoring.monitoring_lock():
                self.assertEqual(monitoring.run_monitoring_cycle(), {"status": "busy"})
            with patch("backup.restore_pending", return_value=True), patch("monitoring.http_request") as retrieve:
                self.assertEqual(monitoring.run_monitoring_cycle(), {"status": "restore_pending"})
        retrieve.assert_not_called()

    def test_broken_audit_chain_stops_checks_and_delivery(self):
        with patch("audit_integrity.verify_chain", side_effect=AuditIntegrityError("broken")), patch("monitoring.deliver") as deliver:
            with self.assertRaises(AuditIntegrityError):
                self.cycle()
        deliver.assert_not_called()

    def test_ca_deletion_removes_active_and_resolved_findings_without_snapshot_resurrection(self):
        authority = self.create_ca(days=20)
        # Linked inventory rows exercise every deletion category. The check only
        # consumes inventory identity and validity, not their certificate bodies.
        self.execute("""INSERT INTO certificates(common_name,authority_id,certificate_pem,private_key_pem,serial_number,not_before,not_after)
                        VALUES ('leaf.example',1,?,'','abc',?,?)""",
                     (authority["certificate_pem"], authority["not_before"], authority["not_after"]))
        self.execute("""INSERT INTO issued_authorities(common_name,authority_id,role,certificate_pem,serial_number,not_before,not_after)
                        VALUES ('Child CA',1,'issuing',?,'def',?,?)""",
                     (authority["certificate_pem"], authority["not_before"], authority["not_after"]))
        self.configure()
        self.assertEqual(self.cycle()["active"], 3)
        with self.app.app_context():
            stale, _, _ = monitoring.collect_findings(monitoring._snapshot(get_db()), monitoring.configuration(), datetime.now(UTC))
        self.execute("UPDATE issued_authorities SET not_after=?", ((datetime.now(UTC) + timedelta(days=90)).isoformat(),))
        self.assertEqual(self.cycle()["active"], 2)
        self.assertEqual(len(self.findings(active=False)), 1)
        self.post("/authorities/1/revoke", {"reason": "superseded"})
        response = self.post("/authorities/1/delete", {"confirmation_name": "Monitor CA"})
        self.assertIn(b"Deleted CA", response.data)
        with self.app.app_context():
            db = get_db()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM monitoring_findings").fetchone()[0], 0)
            db.execute("BEGIN IMMEDIATE")
            monitoring._record_findings(db, stale, datetime.now(UTC), 0)
            db.commit()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM monitoring_findings").fetchone()[0], 0)
            self.assertGreater(db.execute("SELECT COUNT(*) FROM audit_events WHERE action='monitoring.alert'").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
