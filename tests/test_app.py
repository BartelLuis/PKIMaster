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
                "name": "Operations Issuing",
                "role": "issuing",
                "common_name": "Operations Issuing CA",
                "parent_id": str(root["id"]),
                "validity_days": "1825",
            },
            follow_redirects=True,
        )
        self.assertEqual(intermediate_response.status_code, 200)
        self.assertIn(b"Created issuing CA", intermediate_response.data)

        with self.app.app_context():
            import app as app_module

            issuing = app_module.get_db().execute(
                "SELECT id, certificate_pem FROM authorities WHERE name = ?", ("Operations Issuing",)
            ).fetchone()

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

        issued_cert = x509.load_pem_x509_certificate(chain.data.split(b"-----END CERTIFICATE-----\n")[0] + b"-----END CERTIFICATE-----\n")
        sans = issued_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        self.assertIn("api.service.internal", sans.get_values_for_type(x509.DNSName))

        issuing_cert = x509.load_pem_x509_certificate(issuing["certificate_pem"].encode("utf-8"))
        self.assertEqual(issued_cert.issuer, issuing_cert.subject)


if __name__ == "__main__":
    unittest.main()
