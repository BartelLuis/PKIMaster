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

    def test_dashboard_and_health_endpoint(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Manage Root, Intermediate, and Issuing CAs", response.data)

        health = self.client.get("/healthz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json["status"], "ok")

    def test_root_intermediate_and_certificate_flow(self) -> None:
        root_response = self.client.post(
            "/authorities",
            data={
                "name": "Operations Root",
                "role": "root",
                "common_name": "Operations Root CA",
                "parent_id": "",
                "validity_days": "3650",
            },
            follow_redirects=True,
        )
        self.assertEqual(root_response.status_code, 200)
        self.assertIn(b"Created root CA", root_response.data)

        with self.app.app_context():
            import app as app_module

            root = app_module.get_db().execute("SELECT id FROM authorities WHERE name = ?", ("Operations Root",)).fetchone()

        intermediate_response = self.client.post(
            "/authorities",
            data={
                "name": "Operations Intermediate",
                "role": "intermediate",
                "common_name": "Operations Intermediate CA",
                "parent_id": str(root["id"]),
                "validity_days": "1825",
            },
            follow_redirects=True,
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
        root_chain = self.client.get(f"/authorities/{root['id']}/cert")
        root_cert = x509.load_pem_x509_certificate(root_chain.data)
        self.assertEqual(intermediate_cert.issuer, root_cert.subject)

        issuing_response = self.client.post(
            "/authorities",
            data={
                "name": "Operations Issuing",
                "role": "issuing",
                "common_name": "Operations Issuing CA",
                "parent_id": str(intermediate["id"]),
                "validity_days": "1825",
            },
            follow_redirects=True,
        )
        self.assertEqual(issuing_response.status_code, 200)
        self.assertIn(b"Created issuing CA", issuing_response.data)

        with self.app.app_context():
            import app as app_module

            issuing = app_module.get_db().execute(
                "SELECT id, certificate_pem FROM authorities WHERE name = ?", ("Operations Issuing",)
            ).fetchone()

        rejected_issue = self.client.post(
            "/certificates",
            data={
                "common_name": "blocked.internal",
                "authority_id": str(intermediate["id"]),
                "subject_alt_names": "blocked.internal",
                "validity_days": "397",
            },
            follow_redirects=True,
        )
        self.assertEqual(rejected_issue.status_code, 200)
        self.assertIn(b"must be issued by an Issuing CA", rejected_issue.data)

        certificate_response = self.client.post(
            "/certificates",
            data={
                "common_name": "service.internal",
                "authority_id": str(issuing["id"]),
                "subject_alt_names": "service.internal,api.service.internal",
                "validity_days": "397",
            },
            follow_redirects=True,
        )
        self.assertEqual(certificate_response.status_code, 200)
        self.assertIn(b"Issued certificate", certificate_response.data)

        chain = self.client.get("/certificates/1/chain")
        self.assertEqual(chain.status_code, 200)
        self.assertIn(b"BEGIN CERTIFICATE", chain.data)

        forbidden_key = self.client.get("/certificates/1/key")
        self.assertEqual(forbidden_key.status_code, 403)

        unlock = self.client.post(
            "/unlock-private-keys",
            data={"token": "admin-token"},
            follow_redirects=True,
        )
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


if __name__ == "__main__":
    unittest.main()
