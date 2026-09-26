import re
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from app import create_app


class PKIMasterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.app = create_app(
            {
                "TESTING": True,
                "ADMIN_TOKEN": "admin-token",
                "SECRET_KEY": "test-secret",
                "DATABASE": str(Path(self.temp_dir.name) / "pkimaster.sqlite"),
                "INSTANCE_PATH": self.temp_dir.name,
            }
        )
        self.client = self.app.test_client()

    def csrf_token(self) -> str:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode("utf-8")

    def post(self, path: str, data: dict[str, str]) -> object:
        return self.client.post(path, data={"csrf_token": self.csrf_token(), **data}, follow_redirects=True)

    def validity_days(self, certificate_pem: str) -> int:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        delta = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        return round(delta.total_seconds() / 86400)

    def test_dashboard_and_health_endpoint(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Manage Root, Intermediate, and Issuing CAs", response.data)

        health = self.client.get("/healthz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json["status"], "ok")

    def test_root_intermediate_and_certificate_flow(self) -> None:
        root_response = self.post(
            "/authorities",
            {
                "name": "Operations Root",
                "role": "root",
                "common_name": "Operations Root CA",
                "parent_id": "",
                "validity_days": "3650",
            },
        )
        self.assertEqual(root_response.status_code, 200)
        self.assertIn(b"Created root CA", root_response.data)

        with self.app.app_context():
            import app as app_module

            root = app_module.get_db().execute("SELECT id FROM authorities WHERE name = ?", ("Operations Root",)).fetchone()

        intermediate_response = self.post(
            "/authorities",
            {
                "name": "Operations Intermediate",
                "role": "intermediate",
                "common_name": "Operations Intermediate CA",
                "parent_id": str(root["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(intermediate_response.status_code, 200)
        self.assertIn(b"Created intermediate CA", intermediate_response.data)

        with self.app.app_context():
            import app as app_module

            intermediate = app_module.get_db().execute(
                "SELECT id, certificate_pem FROM authorities WHERE name = ?", ("Operations Intermediate",)
            ).fetchone()

        intermediate_chain = self.client.get(f"/authorities/{intermediate['id']}/chain")
        self.assertEqual(intermediate_chain.status_code, 200)
        self.assertEqual(intermediate_chain.data.count(b"BEGIN CERTIFICATE"), 2)

        intermediate_cert = x509.load_pem_x509_certificate(intermediate["certificate_pem"].encode("utf-8"))
        intermediate_constraints = intermediate_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        self.assertEqual(intermediate_constraints.path_length, 1)
        root_chain = self.client.get(f"/authorities/{root['id']}/cert")
        root_cert = x509.load_pem_x509_certificate(root_chain.data)
        self.assertEqual(intermediate_cert.issuer, root_cert.subject)

        issuing_response = self.post(
            "/authorities",
            {
                "name": "Operations Issuing",
                "role": "issuing",
                "common_name": "Operations Issuing CA",
                "parent_id": str(intermediate["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(issuing_response.status_code, 200)
        self.assertIn(b"Created issuing CA", issuing_response.data)

        with self.app.app_context():
            import app as app_module

            issuing = app_module.get_db().execute(
                "SELECT id, certificate_pem FROM authorities WHERE name = ?", ("Operations Issuing",)
            ).fetchone()

        rejected_issue = self.post(
            "/certificates",
            {
                "common_name": "blocked.internal",
                "authority_id": str(intermediate["id"]),
                "subject_alt_names": "blocked.internal",
                "validity_days": "397",
            },
        )
        self.assertEqual(rejected_issue.status_code, 200)
        self.assertIn(b"must be issued by an Issuing CA", rejected_issue.data)

        certificate_response = self.post(
            "/certificates",
            {
                "common_name": "service.internal",
                "authority_id": str(issuing["id"]),
                "subject_alt_names": "service.internal,api.service.internal",
                "validity_days": "397",
            },
        )
        self.assertEqual(certificate_response.status_code, 200)
        self.assertIn(b"Issued certificate", certificate_response.data)

        chain = self.client.get("/certificates/1/chain")
        self.assertEqual(chain.status_code, 200)
        self.assertIn(b"BEGIN CERTIFICATE", chain.data)

        forbidden_key = self.client.get("/certificates/1/key")
        self.assertEqual(forbidden_key.status_code, 403)

        unlock = self.post("/unlock-private-keys", {"token": "admin-token"})
        self.assertEqual(unlock.status_code, 200)
        self.assertIn(b"unlocked for this session", unlock.data)

        allowed_key = self.client.get("/certificates/1/key")
        self.assertEqual(allowed_key.status_code, 200)
        self.assertIn(b"BEGIN RSA PRIVATE KEY", allowed_key.data)

        issued_cert = x509.load_pem_x509_certificate(chain.data.split(b"-----END CERTIFICATE-----\n")[0] + b"-----END CERTIFICATE-----\n")
        sans = issued_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        self.assertIn("api.service.internal", sans.get_values_for_type(x509.DNSName))

        issuing_cert = x509.load_pem_x509_certificate(issuing["certificate_pem"].encode("utf-8"))
        self.assertEqual(issued_cert.issuer, issuing_cert.subject)

    def test_direct_root_to_issuing_ca_uses_zero_path_length(self) -> None:
        root_response = self.post(
            "/authorities",
            {
                "name": "Direct Root",
                "role": "root",
                "common_name": "Direct Root CA",
                "parent_id": "",
                "validity_days": "3650",
            },
        )
        self.assertEqual(root_response.status_code, 200)
        self.assertIn(b"Created root CA", root_response.data)

        with self.app.app_context():
            import app as app_module

            root = app_module.get_db().execute("SELECT id FROM authorities WHERE name = ?", ("Direct Root",)).fetchone()

        response = self.post(
            "/authorities",
            {
                "name": "Direct Issuing",
                "role": "issuing",
                "common_name": "Direct Issuing CA",
                "parent_id": str(root["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Created issuing CA", response.data)

        with self.app.app_context():
            import app as app_module

            issuing = app_module.get_db().execute(
                "SELECT certificate_pem FROM authorities WHERE name = ?", ("Direct Issuing",)
            ).fetchone()

        issuing_cert = x509.load_pem_x509_certificate(issuing["certificate_pem"].encode("utf-8"))
        basic_constraints = issuing_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        self.assertEqual(basic_constraints.path_length, 0)

    def test_invalid_ca_hierarchy_is_rejected(self) -> None:
        root_response = self.post(
            "/authorities",
            {
                "name": "Hierarchy Root",
                "role": "root",
                "common_name": "Hierarchy Root CA",
                "parent_id": "",
                "validity_days": "3650",
            },
        )
        self.assertEqual(root_response.status_code, 200)
        self.assertIn(b"Created root CA", root_response.data)

        with self.app.app_context():
            import app as app_module

            root = app_module.get_db().execute("SELECT id FROM authorities WHERE name = ?", ("Hierarchy Root",)).fetchone()

        intermediate_response = self.post(
            "/authorities",
            {
                "name": "Hierarchy Intermediate",
                "role": "intermediate",
                "common_name": "Hierarchy Intermediate CA",
                "parent_id": str(root["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(intermediate_response.status_code, 200)
        self.assertIn(b"Created intermediate CA", intermediate_response.data)

        with self.app.app_context():
            import app as app_module

            intermediate = app_module.get_db().execute(
                "SELECT id FROM authorities WHERE name = ?", ("Hierarchy Intermediate",)
            ).fetchone()

        invalid_intermediate = self.post(
            "/authorities",
            {
                "name": "Nested Intermediate",
                "role": "intermediate",
                "common_name": "Nested Intermediate CA",
                "parent_id": str(intermediate["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(invalid_intermediate.status_code, 200)
        self.assertIn(b"Invalid CA hierarchy", invalid_intermediate.data)

        issuing_response = self.post(
            "/authorities",
            {
                "name": "Hierarchy Issuing",
                "role": "issuing",
                "common_name": "Hierarchy Issuing CA",
                "parent_id": str(root["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(issuing_response.status_code, 200)
        self.assertIn(b"Created issuing CA", issuing_response.data)

        with self.app.app_context():
            import app as app_module

            issuing = app_module.get_db().execute(
                "SELECT id FROM authorities WHERE name = ?", ("Hierarchy Issuing",)
            ).fetchone()

        invalid_issuing = self.post(
            "/authorities",
            {
                "name": "Nested Issuing",
                "role": "issuing",
                "common_name": "Nested Issuing CA",
                "parent_id": str(issuing["id"]),
                "validity_days": "1825",
            },
        )
        self.assertEqual(invalid_issuing.status_code, 200)
        self.assertIn(b"Invalid CA hierarchy", invalid_issuing.data)

    def test_invalid_admin_token_keeps_private_key_downloads_locked(self) -> None:
        root_response = self.post(
            "/authorities",
            {
                "name": "Locked Root",
                "role": "root",
                "common_name": "Locked Root CA",
                "parent_id": "",
                "validity_days": "3650",
            },
        )
        self.assertEqual(root_response.status_code, 200)

        invalid_unlock = self.post("/unlock-private-keys", {"token": "wrong-token"})
        self.assertEqual(invalid_unlock.status_code, 200)
        self.assertIn(b"Invalid admin token", invalid_unlock.data)

        forbidden_key = self.client.get("/authorities/1/key")
        self.assertEqual(forbidden_key.status_code, 403)

    def test_validity_days_are_clamped_for_ca_and_certificate_requests(self) -> None:
        lower_bound_root = self.post(
            "/authorities",
            {
                "name": "One Day Root",
                "role": "root",
                "common_name": "One Day Root CA",
                "parent_id": "",
                "validity_days": "0",
            },
        )
        self.assertEqual(lower_bound_root.status_code, 200)

        default_root = self.post(
            "/authorities",
            {
                "name": "Default Root",
                "role": "root",
                "common_name": "Default Root CA",
                "parent_id": "",
                "validity_days": "not-a-number",
            },
        )
        self.assertEqual(default_root.status_code, 200)

        with self.app.app_context():
            import app as app_module

            one_day_root = app_module.get_db().execute(
                "SELECT id, certificate_pem FROM authorities WHERE name = ?", ("One Day Root",)
            ).fetchone()
            default_root_row = app_module.get_db().execute(
                "SELECT id, certificate_pem FROM authorities WHERE name = ?", ("Default Root",)
            ).fetchone()

        self.assertEqual(self.validity_days(one_day_root["certificate_pem"]), 1)
        self.assertEqual(self.validity_days(default_root_row["certificate_pem"]), 3650)

        issuing_response = self.post(
            "/authorities",
            {
                "name": "Clamped Issuing",
                "role": "issuing",
                "common_name": "Clamped Issuing CA",
                "parent_id": str(default_root_row["id"]),
                "validity_days": "365",
            },
        )
        self.assertEqual(issuing_response.status_code, 200)

        with self.app.app_context():
            import app as app_module

            issuing = app_module.get_db().execute(
                "SELECT id FROM authorities WHERE name = ?", ("Clamped Issuing",)
            ).fetchone()

        upper_bound_cert = self.post(
            "/certificates",
            {
                "common_name": "upper.internal",
                "authority_id": str(issuing["id"]),
                "subject_alt_names": "upper.internal",
                "validity_days": "5000",
            },
        )
        self.assertEqual(upper_bound_cert.status_code, 200)

        default_cert = self.post(
            "/certificates",
            {
                "common_name": "default.internal",
                "authority_id": str(issuing["id"]),
                "subject_alt_names": "default.internal",
                "validity_days": "invalid",
            },
        )
        self.assertEqual(default_cert.status_code, 200)

        with self.app.app_context():
            import app as app_module

            upper_cert = app_module.get_db().execute(
                "SELECT certificate_pem FROM certificates WHERE common_name = ?", ("upper.internal",)
            ).fetchone()
            default_cert_row = app_module.get_db().execute(
                "SELECT certificate_pem FROM certificates WHERE common_name = ?", ("default.internal",)
            ).fetchone()

        self.assertEqual(self.validity_days(upper_cert["certificate_pem"]), 825)
        self.assertEqual(self.validity_days(default_cert_row["certificate_pem"]), 397)


if __name__ == "__main__":
    unittest.main()
