"""Browser and database enforcement for one local CA per installation."""
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import re
import sqlite3
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app import authority_is_active, create_app, get_db
from mfa_helpers import complete_mfa
import pki


class PKIMasterTestCase(unittest.TestCase):
    base_url = "https://localhost"

    @classmethod
    def setUpClass(cls):
        with patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072)):
            cls.external_root = pki.create_ca_certificate("External Root CA", 90, "root")
        cls.external_root_key = serialization.load_pem_private_key(cls.external_root[1].encode(), None)
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())
        cls.leaf_csr = (x509.CertificateSigningRequestBuilder().subject_name(pki.build_subject("service.example"))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("service.example")]), critical=False)
            .sign(cls.leaf_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.config = {"TESTING": True, "INSTANCE_PATH": self.temp_dir.name}
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        token = self.form_token(self.get("/setup"))
        response = self.client.post("/setup", base_url=self.base_url, follow_redirects=True, data={
            "csrf_token": token, "username": "admin", "password": "test-passphrase-123",
            "password_confirm": "test-passphrase-123", "organization": "Test PKI",
            "public_base_url": "https://pki.example", "max_leaf_days": "397",
        })
        self.assertEqual(response.status_code, 200)
        complete_mfa(self.client, self.app)

    def get(self, path, **kwargs):
        return self.client.get(path, base_url=self.base_url, **kwargs)

    def form_token(self, response):
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def post(self, path, data=None):
        return self.client.post(path, base_url=self.base_url, follow_redirects=True,
            data={"csrf_token": self.form_token(self.get("/")), **(data or {})})

    def local_ca(self):
        with self.app.app_context():
            row = get_db().execute("SELECT * FROM authorities").fetchone()
            return dict(row) if row else None

    def test_public_gets_do_not_verify_the_complete_audit_history(self):
        token = self.form_token(self.get("/"))
        with self.app.app_context():
            db = get_db()
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit_events SET detail = 'tampered' WHERE id = (SELECT MIN(id) FROM audit_events)")
            db.commit()

        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/auth/oidc/callback", base_url=self.base_url).status_code, 400)
        self.assertEqual(anonymous.get("/crl/9223372036854775807.crl", base_url=self.base_url).status_code, 404)
        self.assertEqual(self.client.post("/logout", base_url=self.base_url,
                                         data={"csrf_token": token}).status_code, 503)

    def count(self, table):
        with self.app.app_context():
            return get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def create_ca(self, role="root", name="Local CA", days=365):
        response = self.post("/authorities", {"name": name, "role": role, "common_name": name, "validity_days": str(days)})
        self.assertEqual(response.status_code, 200)
        authority = self.local_ca()
        self.assertIsNotNone(authority)
        self.assertEqual(authority["common_name"], name)
        return authority

    def activate_issuer(self, days=30, import_crl=True):
        authority = self.create_ca("issuing", "Local Issuing CA")
        signed = pki.sign_ca_request(authority["csr_pem"], "issuing", days, "root", self.external_root[0], self.external_root[1])
        fingerprint = x509.load_pem_x509_certificate(self.external_root[0].encode()).fingerprint(hashes.SHA256()).hex()
        response = self.post("/ca/activate", {"certificate_pem": signed[0], "chain_pem": self.external_root[0],
                                             "trusted_root_sha256": fingerprint})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.local_ca()["state"], "active")
        if import_crl:
            self.import_root_crl()
        return self.local_ca()

    def import_root_crl(self, entries=(), number=1):
        der = pki.build_crl(self.external_root[0], self.external_root[1], entries, number, 7)
        pem = x509.load_der_x509_crl(der).public_bytes(serialization.Encoding.PEM).decode()
        response = self.post("/ca/parent-crls", {"parent_crls_pem": pem})
        self.assertEqual(response.status_code, 200)
        return response

    def issue_leaf(self, authority_id=1, **changes):
        return self.post("/certificates", {"authority_id": str(authority_id), "common_name": "service.example",
            "validity_days": "397", "csr_pem": self.leaf_csr, "profile": "server", **changes})

    def test_dashboard_and_public_health_endpoint(self):
        response = self.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Local CA", response.data)
        self.assertIn(b"0 / 1", response.data)
        anonymous = self.app.test_client()
        health = anonymous.get("/healthz", base_url=self.base_url)
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json, {"status": "ok"})
        self.assertEqual(anonymous.get("/", base_url=self.base_url).status_code, 302)

    def test_root_creation_and_second_local_ca_rejection(self):
        first = self.create_ca()
        certificate = x509.load_pem_x509_certificate(self.get("/authorities/1/cert").data)
        certificate.verify_directly_issued_by(certificate)
        self.assertEqual(first["state"], "active")
        self.assertIsNone(first["parent_id"])
        self.assertEqual(first["csr_pem"], "")
        response = self.post("/authorities", {"name": "Another CA", "role": "issuing", "common_name": "Another CA"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Only one CA", response.data)
        self.assertEqual(self.count("authorities"), 1)
        self.assertEqual(self.local_ca()["private_key_pem"], first["private_key_pem"])
        self.assertEqual(len(x509.load_pem_x509_certificates(self.get("/authorities/1/chain").data)), 1)

    def test_local_parent_identifiers_are_rejected_before_creation(self):
        response = self.post("/authorities", {"name": "Invalid CA", "role": "issuing", "common_name": "Invalid CA", "parent_id": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"separate server", response.data)
        self.assertEqual(self.count("authorities"), 0)

    def test_subordinate_starts_pending_and_exposes_only_its_csr(self):
        authority = self.create_ca("issuing", "Local Issuing CA")
        self.assertEqual(authority["state"], "pending")
        self.assertEqual(authority["certificate_pem"], "")
        self.assertNotIn("PRIVATE KEY", authority["private_key_pem"])
        request = x509.load_pem_x509_csr(self.get("/authorities/1/csr").data)
        self.assertTrue(request.is_signature_valid)
        self.assertEqual(request.public_key().key_size, 3072)
        self.assertEqual(request.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        for path in ("/authorities/1/cert", "/authorities/1/chain", "/crl/1.crl"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 409)
        self.assertEqual(self.get("/authorities/1/key").status_code, 403)
        response = self.issue_leaf()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Awaiting", response.data)
        self.assertEqual(self.count("certificates"), 0)

    def test_invalid_activation_preserves_pending_identity_and_key(self):
        original = self.create_ca("issuing", "Local Issuing CA")
        signed = pki.sign_ca_request(original["csr_pem"], "issuing", 5, "root", self.external_root[0], self.external_root[1])
        for cert, chain in (("not PEM", self.external_root[0]), (self.external_root[0], self.external_root[0]), (signed[0], "")):
            with self.subTest(lengths=(len(cert), len(chain))):
                response = self.post("/ca/activate", {"certificate_pem": cert, "chain_pem": chain})
                self.assertEqual(response.status_code, 200)
                current = self.local_ca()
                self.assertEqual(current["state"], "pending")
                self.assertEqual(current["private_key_pem"], original["private_key_pem"])
                self.assertEqual(current["csr_pem"], original["csr_pem"])
        response = self.post("/ca/activate", {"certificate_pem": signed[0], "chain_pem": self.external_root[0],
                                             "trusted_root_sha256": "00" * 32})
        self.assertIn(b"trusted verification channel", response.data)
        self.assertEqual(self.local_ca()["state"], "pending")

    def test_activation_requires_fresh_parent_crls_before_issuance(self):
        self.activate_issuer(import_crl=False)
        with self.app.app_context():
            self.assertFalse(authority_is_active(get_db().execute("SELECT * FROM authorities").fetchone()))
        self.assertIn(b"parent CRLs", self.issue_leaf().data)
        self.assertEqual(self.count("certificates"), 0)
        self.import_root_crl()
        response = self.issue_leaf()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.count("certificates"), 1)
        chain = x509.load_pem_x509_certificates(self.get("/certificates/1/chain").data)
        self.assertEqual(len(chain), 3)
        for child, parent in zip(chain, chain[1:]):
            child.verify_directly_issued_by(parent)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT private_key_pem FROM certificates").fetchone()[0], "")

    def test_stale_parent_crls_do_not_enable_signing(self):
        self.activate_issuer(import_crl=False)
        now = datetime.now(UTC)
        root = x509.load_pem_x509_certificate(self.external_root[0].encode())
        stale = (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
            .last_update(now - timedelta(days=2)).next_update(now - timedelta(days=1))
            .add_extension(x509.CRLNumber(1), critical=False)
            .sign(self.external_root_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        response = self.post("/ca/parent-crls", {"parent_crls_pem": stale})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"stale", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")
        self.issue_leaf()
        self.assertEqual(self.count("certificates"), 0)

    def test_parent_crl_upload_rejects_repeated_begin_markers(self):
        self.activate_issuer(import_crl=False)
        malicious = ("-----BEGIN X509 CRL-----\n" * 16) + "-----END X509 CRL-----\n"
        response = self.post("/ca/parent-crls", {"parent_crls_pem": malicious})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Upload only PEM-encoded parent CRLs.", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")

    def test_parent_crl_upload_rejects_empty_crl_block(self):
        self.activate_issuer(import_crl=False)
        response = self.post("/ca/parent-crls", {"parent_crls_pem": "-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Upload only PEM-encoded parent CRLs.", response.data)
        self.assertEqual(self.local_ca()["parent_crls_pem"], "")

    def test_parent_revocation_disables_signing_and_cannot_be_rolled_back(self):
        authority = self.activate_issuer()
        previous = authority["parent_crls_pem"]
        self.import_root_crl([{"serial_number": authority["serial_number"],
            "revoked_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(), "revocation_reason": "ca_compromise"}], 2)
        self.assertIsNotNone(self.local_ca()["revoked_at"])
        rejected = self.post("/ca/parent-crls", {"parent_crls_pem": previous})
        self.assertEqual(rejected.status_code, 200)
        self.assertIsNotNone(self.local_ca()["revoked_at"])
        self.issue_leaf()
        self.assertEqual(self.count("certificates"), 0)

    def test_validity_is_bounded_by_local_issuer_and_web_policy(self):
        authority = self.activate_issuer(days=5)
        self.assertEqual(self.issue_leaf().status_code, 200)
        certificate = x509.load_pem_x509_certificate(self.get("/certificates/1/cert").data)
        self.assertEqual(certificate.not_valid_after_utc, datetime.fromisoformat(authority["not_after"]))
        response = self.post("/settings", {"organization": "Test PKI", "public_base_url": "https://pki.example", "max_leaf_days": "2"})
        self.assertEqual(response.status_code, 200)
        self.issue_leaf(common_name="short.example", validity_days="825")
        second = x509.load_pem_x509_certificate(self.get("/certificates/2/cert").data)
        self.assertEqual(round((second.not_valid_after_utc - second.not_valid_before_utc).total_seconds() / 86400), 2)

    def test_ca_key_export_is_denied_even_when_leaf_export_is_enabled(self):
        self.create_ca()
        response = self.post("/settings", {"organization": "Test PKI", "allow_key_export": "on"})
        self.assertEqual(response.status_code, 200)
        response = self.get("/authorities/1/key")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"cannot be exported", response.data)
        self.assertNotIn(b"PRIVATE KEY", response.data)

    def test_database_enforces_one_immutable_undeletable_local_ca(self):
        original = self.create_ca()
        statements = [
            "INSERT INTO authorities(name,role,common_name,certificate_pem,private_key_pem,serial_number,not_before,not_after) SELECT 'Duplicate',role,common_name,certificate_pem,private_key_pem,serial_number,not_before,not_after FROM authorities",
            "UPDATE authorities SET role='issuing'", "UPDATE authorities SET common_name='Replaced'",
            "UPDATE authorities SET private_key_pem='replacement'", "UPDATE authorities SET parent_id=1",
            "DELETE FROM authorities",
        ]
        with self.app.app_context():
            db = get_db()
            for statement in statements:
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    db.execute(statement)
                db.rollback()
        self.assertEqual(self.local_ca()["private_key_pem"], original["private_key_pem"])
        self.assertEqual(self.count("authorities"), 1)

    def test_concurrent_ca_creation_commits_exactly_one_authority(self):
        token = self.form_token(self.get("/"))
        cookie = self.client.get_cookie(self.app.config["SESSION_COOKIE_NAME"])
        self.assertIsNotNone(cookie)
        barrier = Barrier(2)

        def submit(name):
            client = self.app.test_client()
            client.set_cookie(self.app.config["SESSION_COOKIE_NAME"], cookie.value, domain="localhost")
            barrier.wait(timeout=10)
            return client.post("/authorities", base_url=self.base_url, follow_redirects=True,
                data={"csrf_token": token, "name": name, "common_name": name, "role": "root", "validity_days": "30"})

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(submit, ("Concurrent Root A", "Concurrent Root B")))
        self.assertEqual([response.status_code for response in responses], [200, 200])
        self.assertEqual(self.count("authorities"), 1)
        self.assertEqual(sum(b"Created root CA" in response.data for response in responses), 1)
        self.assertEqual(sum(b"Only one CA" in response.data for response in responses), 1)

    def test_existing_multiple_ca_database_blocks_startup_without_deleting_records(self):
        self.create_ca()
        with self.app.app_context():
            db = get_db()
            # Reconstruct the previous schema's multi-CA state for upgrade validation.
            db.execute("DROP TRIGGER single_local_ca")
            db.execute("INSERT INTO authorities(name,role,common_name,certificate_pem,private_key_pem,serial_number,not_before,not_after) SELECT 'Legacy Second',role,'Legacy Second',certificate_pem,private_key_pem,serial_number,not_before,not_after FROM authorities")
            db.commit()
            before = [tuple(row) for row in db.execute("SELECT id,private_key_pem FROM authorities ORDER BY id")]
        with self.assertRaisesRegex(RuntimeError, "multiple local CAs"):
            create_app(self.config)
        with self.app.app_context():
            after = [tuple(row) for row in get_db().execute("SELECT id,private_key_pem FROM authorities ORDER BY id")]
        self.assertEqual(before, after)

    def test_root_cannot_issue_leaf_certificates(self):
        self.create_ca()
        response = self.issue_leaf()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Issuing CA", response.data)
        self.assertEqual(self.count("certificates"), 0)

    def test_invalid_csrf_and_unknown_or_large_ids_fail_without_mutation(self):
        response = self.client.post("/authorities", base_url=self.base_url,
            data={"csrf_token": "invalid", "name": "Forbidden", "common_name": "Forbidden", "role": "root"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.count("authorities"), 0)
        huge_id = "9" * 100
        for path in (f"/crl/{huge_id}.crl", f"/authorities/{huge_id}", f"/authorities/{huge_id}/cert", f"/certificates/{huge_id}/cert", "/authorities/1"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 404)


if __name__ == "__main__":
    unittest.main()
