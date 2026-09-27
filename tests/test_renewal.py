"""Renewal keeps old certificates intact and enforces normal signing policy."""
import re
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app import create_app, get_db
from audit_integrity import verify_chain
import pki
from test_distributed_ca import Node


class RenewalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = pki.create_ca_certificate("Renewal Root", 365, "root")
        cls.root_crl = x509.load_der_x509_crl(pki.build_crl(cls.root[0], cls.root[1], [], 1, 7)).public_bytes(serialization.Encoding.PEM).decode()
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "service.example")]))
            .sign(cls.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

    def setUp(self):
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.node = Node(self, "issuing")
        self.activate()
        self.assertIn(b"Issued certificate", self.node.post("/certificates", {
            "authority_id": "1", "common_name": "service.example", "profile": "dual",
            "subject_alt_names": "service.example,192.0.2.10", "validity_days": "30", "csr_pem": self.csr,
        }).data)

    def activate(self):
        authority = self.node.records("authorities")[-1]
        pem, *_ = pki.sign_ca_request(authority["csr_pem"], "issuing", 180, "root", self.root[0], self.root[1])
        result = self.node.post("/ca/activate", {"certificate_pem": pem, "chain_pem": self.root[0],
            "trusted_root_sha256": x509.load_pem_x509_certificate(self.root[0].encode()).fingerprint(hashes.SHA256()).hex()})
        self.assertIn(b"CA certificate imported", result.data)
        self.assertIn(b"Parent CRLs validated", self.node.post("/ca/parent-crls", {"parent_crls_pem": self.root_crl}).data)

    def values(self, **changes):
        values = {"authority_id": str(self.node.records("authorities")[-1]["id"]), "common_name": "service.example",
                  "subject_alt_names": "service.example,192.0.2.10", "profile": "dual", "validity_days": "60",
                  "key_source": "csr", "csr_pem": self.csr}
        return values | changes

    def test_prefill_csr_successor_history_and_restart(self):
        original = self.node.records("certificates")[0]
        page = self.node.get("/certificates/1/renew")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'value="service.example"', page.data)
        self.assertIn(b"service.example, 192.0.2.10", page.data)
        response = self.node.post("/certificates/1/renew", self.values())
        self.assertEqual(response.status_code, 200)
        old, new = self.node.records("certificates")
        self.assertEqual(old, original)
        self.assertEqual(new["renewed_from_id"], old["id"])
        self.assertNotEqual(new["serial_number"], old["serial_number"])
        self.assertEqual(new["private_key_pem"], "")
        cert = x509.load_pem_x509_certificate(new["certificate_pem"].encode())
        self.assertEqual(cert.public_key(), self.key.public_key())
        self.assertEqual(new["subject_alt_names"], old["subject_alt_names"])
        self.assertGreater(new["not_after"], old["not_after"])
        self.assertIn(b'href="/certificates/1"', response.data)
        self.assertIn(b'href="/certificates/2"', self.node.get("/certificates/1").data)
        restarted = create_app({"TESTING": True, "INSTANCE_PATH": self.node.app.config["INSTANCE_PATH"]})
        with restarted.app_context():
            db = get_db()
            self.assertEqual(db.execute("SELECT renewed_from_id FROM certificates WHERE id=2").fetchone()[0], 1)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE certificates SET renewed_from_id=NULL WHERE id=2")
            db.rollback()
            verify_chain(db, restarted.config["KEY_ENCRYPTION_SECRET"])
        self.assertTrue(any(event["action"] == "certificate.renewed" for event in self.node.records("audit_events")))

    def test_generated_new_key_and_repeated_submit(self):
        self.assertEqual(self.node.post("/certificates/1/renew", self.values(key_source="generated", csr_pem="")).status_code, 200)
        new = self.node.records("certificates")[-1]
        self.assertTrue(new["private_key_pem"])
        self.assertNotEqual(x509.load_pem_x509_certificate(new["certificate_pem"].encode()).public_key(), self.key.public_key())
        self.node.post("/certificates/1/renew", self.values())
        self.assertEqual(len(self.node.records("certificates")), 2)

    def test_validation_roles_csrf_and_issuer_policy(self):
        for changes in ({"validity_days": "91"}, {"csr_pem": "invalid"}, {"csr_pem": ""},
                        {"key_source": "invalid"}, {"authority_id": "2"}, {"profile": "ca"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.node.post("/certificates/1/renew", self.values(**changes)).status_code, 400)
                self.assertEqual(len(self.node.records("certificates")), 1)
        self.assertEqual(self.node.client.post("/certificates/1/renew", base_url=self.node.base, data=self.values()).status_code, 403)
        with self.node.app.app_context():
            db = get_db()
            db.execute("UPDATE users SET role='auditor' WHERE username='admin'")
            db.commit()
        self.assertEqual(self.node.get("/certificates/1").status_code, 200)
        self.assertEqual(self.node.get("/certificates/1/renew").status_code, 403)
        self.assertEqual(self.node.post("/certificates/1/renew", self.values()).status_code, 403)
        with self.node.app.app_context():
            db = get_db()
            db.execute("UPDATE users SET role='operator' WHERE username='admin'")
            db.execute("UPDATE authorities SET parent_crls_pem=''")
            db.commit()
        self.assertEqual(self.node.post("/certificates/1/renew", self.values()).status_code, 400)
        self.assertEqual(len(self.node.records("certificates")), 1)

    def test_revoked_source_rejected_and_expired_source_allowed(self):
        with self.node.app.app_context():
            db = get_db()
            db.execute("UPDATE certificates SET not_after='2000-01-01T00:00:00+00:00' WHERE id=1")
            db.commit()
        self.assertEqual(self.node.post("/certificates/1/renew", self.values()).status_code, 200)
        self.node.post("/certificates/2/revoke", {"reason": "key_compromise"})
        self.assertEqual(self.node.post("/certificates/2/renew", self.values()).status_code, 400)
        self.assertEqual(len(self.node.records("certificates")), 2)

    def test_new_issuer_and_deletion_of_predecessor_ca(self):
        self.node.post("/authorities/1/revoke", {"reason": "superseded"})
        self.node.post("/authorities", {"name": "Replacement", "common_name": "Replacement", "role": "issuing", "validity_days": "365"})
        self.activate()
        self.assertIn(b"issuer changes", self.node.get("/certificates/1/renew").data)
        self.assertEqual(self.node.post("/certificates/1/renew", self.values()).status_code, 200)
        result = self.node.post("/authorities/1/delete", {"confirmation_name": "issuing CA"})
        self.assertIn(b"Deleted CA", result.data)
        remaining = self.node.records("certificates")
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["authority_id"], 2)
        self.assertIsNone(remaining[0]["renewed_from_id"])
        self.assertEqual(self.node.get("/certificates/2").status_code, 200)

    def test_parallel_requests_create_only_one_successor(self):
        token = re.search(rb'name="csrf_token" value="([^"]+)"', self.node.get("/").data).group(1).decode()
        cookie = self.node.client.get_cookie("session", domain="localhost").value
        def submit(_):
            client = self.node.app.test_client()
            client.set_cookie("session", cookie, domain="localhost")
            return client.post("/certificates/1/renew", base_url=self.node.base, data=self.values() | {"csrf_token": token}).status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(list(executor.map(submit, range(2))), [302, 302])
        self.assertEqual(len(self.node.records("certificates")), 2)


if __name__ == "__main__":
    unittest.main()
