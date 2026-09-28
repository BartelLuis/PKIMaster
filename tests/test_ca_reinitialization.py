"""Browser regression coverage for replacing a revoked CA without losing history."""

import sqlite3
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app, get_db
import pki
from test_distributed_ca import Node


class CAReinitializationTests(unittest.TestCase):
    def setUp(self):
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(
            public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.node = Node(self, "root")

    def initialize(self, name, role="root"):
        response = self.node.post("/authorities", {
            "name": name, "common_name": name, "role": role, "validity_days": "90",
        })
        self.assertEqual(response.status_code, 200)
        record = self.node.records("authorities")[-1]
        self.assertEqual(record["name"], name)
        self.assertIsNone(record["revoked_at"])
        return record

    def revoke(self, authority_id):
        response = self.node.post(f"/authorities/{authority_id}/revoke", {"reason": "superseded"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This CA is archived", response.data)

    def test_revoked_root_can_be_replaced_without_losing_public_artifacts(self):
        previous = self.node.records("authorities")[0]
        certificate = self.node.get("/authorities/1/cert").data
        chain = self.node.get("/authorities/1/chain").data
        self.revoke(previous["id"])

        page = self.node.get("/").data
        self.assertIn(b"0 / 1", page)
        self.assertIn(b"Initialize this server's CA", page)
        self.assertIn(b"Revoked CA archive", page)
        self.assertIn(b'href="/authorities/1"', page)
        self.assertIn(b'href="/authorities/1/cert"', page)
        self.assertNotIn(b"Request subordinate CA signing", page)
        self.assertIn(b"Local CA boundary</span><strong>0 / 1</strong>", self.node.get("/security").data)

        replacement = self.initialize("Replacement Root")
        self.assertEqual(replacement["id"], 2)
        self.assertNotEqual(replacement["private_key_pem"], previous["private_key_pem"])
        self.assertNotEqual(replacement["serial_number"], previous["serial_number"])
        archived = self.node.records("authorities")[0]
        for field in ("name", "certificate_pem", "private_key_pem", "serial_number"):
            self.assertEqual(archived[field], previous[field], field)
        self.assertTrue(archived["revoked_at"])
        self.assertEqual(self.node.get("/authorities/1/cert").data, certificate)
        self.assertEqual(self.node.get("/authorities/1/chain").data, chain)
        page = self.node.get("/").data
        self.assertIn(b"1 / 1", page)
        self.assertNotIn(b"2 / 1", page)
        self.assertNotIn(b"Initialize this server's CA", page)
        self.assertIn(b"Request subordinate CA signing", page)
        self.assertIn(b"Replacement Root", page)
        self.assertIn(b"Local CA boundary</span><strong>1 / 1</strong>", self.node.get("/security").data)

        anonymous = self.node.app.test_client()
        old_crl = self.node.get("/crl/1.crl", anonymous)
        self.assertEqual(old_crl.status_code, 200)
        self.assertTrue(x509.load_der_x509_crl(old_crl.data).is_signature_valid(
            x509.load_pem_x509_certificate(certificate).public_key()))
        self.assertEqual(self.node.get("/aia/1.cer", anonymous).status_code, 200)
        self.assertEqual(self.node.get("/authorities/1/key").status_code, 403)

        restarted = create_app({"TESTING": True, "INSTANCE_PATH": self.node.app.config["INSTANCE_PATH"]})
        self.assertEqual(restarted.test_client().get("/aia/1.cer").status_code, 200)
        self.assertEqual(restarted.test_client().get("/aia/2.cer").status_code, 200)
        events = {(row["action"], row["object_id"]) for row in self.node.records("audit_events")}
        self.assertTrue({("authority.created", "1"), ("authority.revoked", "1"),
                         ("authority.created", "2")}.issubset(events))

    def test_archived_revocation_cannot_be_changed_with_or_without_a_replacement(self):
        self.revoke(1)
        revoked_at = self.node.records("authorities")[0]["revoked_at"]
        for replacement in (False, True):
            if replacement:
                self.initialize("Replacement Root")
            for timestamp in (None, "", "2000-01-01T00:00:00+00:00"):
                with self.subTest(replacement=replacement, timestamp=timestamp), self.node.app.app_context():
                    db = get_db()
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "revoked CA"):
                        db.execute("UPDATE authorities SET revoked_at=? WHERE id=1", (timestamp,))
                    db.rollback()
                    self.assertEqual(db.execute("SELECT revoked_at FROM authorities WHERE id=1").fetchone()[0], revoked_at)

    def test_revoked_pending_ca_can_be_replaced_and_new_csr_activated(self):
        self.revoke(1)
        pending = self.initialize("Abandoned Issuing", "issuing")
        self.revoke(pending["id"])
        replacement = self.initialize("Replacement Issuing", "issuing")
        self.assertEqual(replacement["id"], 3)
        self.assertNotEqual(replacement["csr_pem"], pending["csr_pem"])
        self.assertIn(b'href="/authorities/2/csr"', self.node.get("/").data)
        self.assertEqual(self.node.get("/authorities/2/csr").data.decode(), pending["csr_pem"])

        external = pki.create_ca_certificate("External Parent", 365, "root")
        signed = pki.sign_ca_request(replacement["csr_pem"], "issuing", 30, "root", external[0], external[1])
        response = self.node.post("/ca/activate", {
            "certificate_pem": signed[0], "chain_pem": external[0],
            "trusted_root_sha256": x509.load_pem_x509_certificate(external[0].encode()).fingerprint(hashes.SHA256()).hex(),
        })
        self.assertIn(b"CA certificate imported", response.data)
        crl = x509.load_der_x509_crl(pki.build_crl(external[0], external[1], [], 1, 7))
        response = self.node.post("/ca/parent-crls", {
            "parent_crls_pem": crl.public_bytes(serialization.Encoding.PEM).decode(),
        })
        self.assertIn(b"Parent CRLs validated and imported", response.data)
        records = self.node.records("authorities")
        self.assertEqual(records[1]["state"], "pending")
        self.assertTrue(records[1]["revoked_at"])
        self.assertEqual(records[2]["state"], "active")
        self.assertEqual(records[2]["certificate_pem"], signed[0])
        self.assertIn(b"Operational", self.node.get("/").data)
        self.assertNotIn(b"Request subordinate CA signing", self.node.get("/").data)

        response = self.node.post("/certificates", {
            "authority_id": "3", "common_name": "history.example", "profile": "server",
            "subject_alt_names": "history.example", "validity_days": "10",
        })
        self.assertIn(b"Issued certificate", response.data)
        original_chain = self.node.get("/certificates/1/chain").data
        self.revoke(3)
        self.initialize("Final Root")
        self.assertEqual(self.node.get("/certificates/1/chain").data, original_chain)
        self.assertIn(b"history.example", self.node.get("/").data)
        self.assertIn(b"Issuer inactive", self.node.get("/").data)
        self.node.post("/certificates", {
            "authority_id": "3", "common_name": "forbidden.example", "profile": "server",
            "subject_alt_names": "forbidden.example", "validity_days": "10",
        })
        self.assertEqual(len(self.node.records("certificates")), 1)

    def test_historical_ca_requests_and_chains_survive_a_change_of_role(self):
        self.node.add_reviewer()
        for common_name in ("Signed Remote CA", "Pending Remote CA"):
            csr, _ = pki.create_ca_request(common_name, "issuing")
            response = self.node.post("/ca/requests", {
                "csr_pem": csr, "role": "issuing", "validity_days": "30",
            })
            self.assertIn(b"CA request recorded", response.data)
        response = self.node.post("/ca/requests/1/approve", client=self.node.reviewer)
        self.assertIn(b"Subordinate CA certificate signed", response.data)
        previous_chain = self.node.get("/subordinates/1/parents").data
        previous_certificate = self.node.get("/subordinates/1/cert").data
        self.revoke(1)
        self.initialize("New Issuing Role", "issuing")

        page = self.node.get("/", self.node.reviewer).data
        for visible in (b"CA signing requests", b"Signed Remote CA", b"Pending Remote CA",
                        b"Issued subordinate CA certificates", b"Issuer inactive"):
            self.assertIn(visible, page)
        self.assertNotIn(b"Request subordinate CA signing", page)
        self.assertNotIn(b'action="/ca/requests/2/approve"', page)
        self.assertNotIn(b'action="/ca/requests/2/reject"', page)
        self.assertEqual(self.node.get("/subordinates/1/cert").data, previous_certificate)
        self.assertEqual(self.node.get("/subordinates/1/parents").data, previous_chain)
        self.assertIn(b"Signed Remote CA", self.node.get("/authorities/1").data)

        # Even with another operational root, old requests belong to the revoked issuer.
        self.revoke(2)
        self.initialize("Third Root")
        self.node.post("/ca/requests/2/approve", client=self.node.reviewer)
        self.assertEqual(len(self.node.records("issued_authorities")), 1)
        pending = self.node.records("ca_requests")[1]
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["authority_id"], 1)


if __name__ == "__main__":
    unittest.main()
