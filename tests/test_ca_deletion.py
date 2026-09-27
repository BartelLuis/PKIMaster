"""Administrator-confirmed deletion of retired CA data and name reuse."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
import re
import sqlite3
from threading import Event
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import has_request_context, request

from app import create_app, get_authority, get_db
from audit_integrity import verify_chain
import pki
from test_distributed_ca import Node


class CADeletionTests(unittest.TestCase):
    def setUp(self):
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(
            public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.node = Node(self, "root")

    def revoke(self, node=None, authority_id=1):
        node = node or self.node
        response = node.post(f"/authorities/{authority_id}/revoke", {"reason": "superseded"})
        self.assertEqual(response.status_code, 200)
        with node.app.app_context():
            self.assertTrue(get_db().execute("SELECT revoked_at FROM authorities WHERE id=?", (authority_id,)).fetchone()[0])

    def delete(self, node=None, authority_id=1, name="root CA"):
        return (node or self.node).post(f"/authorities/{authority_id}/delete", {"confirmation_name": name})

    def initialize(self, name, role="root"):
        response = self.node.post("/authorities", {
            "name": name, "common_name": name, "role": role, "validity_days": "90",
        })
        self.assertEqual(response.status_code, 200)
        records = self.node.records("authorities")
        self.assertEqual(records[-1]["name"], name)
        return records[-1]

    def request_child(self, name):
        csr, _ = pki.create_ca_request(name, "issuing")
        response = self.node.post("/ca/requests", {
            "csr_pem": csr, "role": "issuing", "validity_days": "30",
        })
        self.assertIn(b"CA request recorded", response.data)
        return self.node.records("ca_requests")[-1]

    def assert_audit_valid(self, node=None):
        node = node or self.node
        with node.app.app_context():
            verify_chain(get_db(), node.app.config["KEY_ENCRYPTION_SECRET"])

    def test_deleted_root_name_can_be_reused_with_fresh_id_and_key_after_restart(self):
        original = self.node.records("authorities")[0]
        self.assertEqual(self.node.get("/crl/1.crl").status_code, 200)
        self.revoke()
        self.assertIn(b'action="/authorities/1/delete"', self.node.get("/authorities/1").data)
        before = self.node.records("audit_events")

        response = self.delete()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.node.records("authorities"), [])
        self.assertIn(b"Initialize this server's CA", response.data)
        with self.node.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM crls").fetchone()[0], 0)
            self.assertEqual(get_db().execute("PRAGMA foreign_key_check").fetchall(), [])
        audit = self.node.records("audit_events")
        self.assertEqual(audit[:len(before)], before)
        deleted = [row for row in audit if row["action"] == "authority.deleted"]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["object_id"], "1")
        self.assertIn(original["name"], deleted[0]["detail"])
        self.assert_audit_valid()
        for path in ("/authorities/1", "/authorities/1/cert", "/authorities/1/chain", "/crl/1.crl", "/aia/1.cer"):
            with self.subTest(path=path):
                self.assertEqual(self.node.get(path).status_code, 404)

        restarted = create_app({"TESTING": True, "INSTANCE_PATH": self.node.app.config["INSTANCE_PATH"]})
        with restarted.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM authorities").fetchone()[0], 0)
            verify_chain(get_db(), restarted.config["KEY_ENCRYPTION_SECRET"])
        replacement = self.initialize(original["name"])
        self.assertGreater(replacement["id"], original["id"])
        self.assertNotEqual(replacement["serial_number"], original["serial_number"])
        public_keys = [x509.load_pem_x509_certificate(record["certificate_pem"].encode()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for record in (original, replacement)]
        self.assertNotEqual(*public_keys)
        self.assertEqual(len(self.node.records("authorities")), 1)
        self.assertEqual(self.node.get("/aia/1.cer").status_code, 404)
        self.assertEqual(self.node.get(f"/aia/{replacement['id']}.cer").status_code, 200)

    def test_active_and_pending_nonrevoked_cas_cannot_be_deleted(self):
        pending = Node(self, "issuing")
        for node, name in ((self.node, "root CA"), (pending, "issuing CA")):
            with self.subTest(name=name):
                before = node.records("authorities")
                self.assertNotIn(b'action="/authorities/1/delete"', node.get("/authorities/1").data)
                self.assertEqual(self.delete(node=node, name=name).status_code, 200)
                self.assertEqual(node.records("authorities"), before)
                self.assertNotIn("authority.deleted", [row["action"] for row in node.records("audit_events")])
                with node.app.app_context():
                    db = get_db()
                    with self.assertRaises(sqlite3.IntegrityError):
                        db.execute("DELETE FROM authorities WHERE id=1")
                    db.rollback()

    def test_confirmation_must_match_name_exactly(self):
        self.revoke()
        before = self.node.records("authorities")
        for confirmation in ("", "ROOT CA", "different", " root CA", "root CA "):
            with self.subTest(confirmation=confirmation):
                self.assertEqual(self.delete(name=confirmation).status_code, 200)
                self.assertEqual(self.node.records("authorities"), before)
        self.assertNotIn("authority.deleted", [row["action"] for row in self.node.records("audit_events")])

    def test_deletion_requires_csrf_and_administrator_role(self):
        self.revoke()
        for token in (None, "invalid"):
            data = {"confirmation_name": "root CA"}
            if token is not None:
                data["csrf_token"] = token
            response = self.node.client.post("/authorities/1/delete", base_url=self.node.base, data=data)
            self.assertEqual(response.status_code, 403)
        for role in ("operator", "auditor"):
            with self.subTest(role=role):
                with self.node.app.app_context():
                    db = get_db()
                    db.execute("UPDATE users SET role=? WHERE username='admin'", (role,))
                    db.commit()
                self.assertNotIn(b'action="/authorities/1/delete"', self.node.get("/authorities/1").data)
                self.assertEqual(self.delete().status_code, 403)
        self.assertEqual(len(self.node.records("authorities")), 1)
        self.assertNotIn("authority.deleted", [row["action"] for row in self.node.records("audit_events")])

    def test_deleting_archive_removes_its_requests_and_subordinates_only(self):
        self.node.add_reviewer()
        signed_request = self.request_child("Old Signed Issuing")
        self.assertIn(b"Subordinate CA certificate signed", self.node.post(
            f"/ca/requests/{signed_request['id']}/approve", client=self.node.reviewer).data)
        pending_request = self.request_child("Old Pending Issuing")
        signed_id = self.node.records("issued_authorities")[0]["id"]
        self.assertEqual(self.node.get("/crl/1.crl").status_code, 200)
        self.revoke()
        current = self.initialize("Current Root")
        current_request = self.request_child("Current Pending Issuing")
        before_audit = self.node.records("audit_events")

        self.assertEqual(self.delete().status_code, 200)

        self.assertEqual(self.node.records("authorities"), [current])
        self.assertEqual(self.node.records("ca_requests"), [current_request])
        self.assertEqual(self.node.records("issued_authorities"), [])
        self.assertEqual(self.node.records("audit_events")[:len(before_audit)], before_audit)
        with self.node.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM crls WHERE authority_id=1").fetchone()[0], 0)
            self.assertEqual(get_db().execute("PRAGMA foreign_key_check").fetchall(), [])
        for artifact in ("cert", "parents"):
            self.assertEqual(self.node.get(f"/subordinates/{signed_id}/{artifact}").status_code, 404)
        for record in (signed_request, pending_request):
            response = self.node.post(f"/ca/requests/{record['id']}/approve", client=self.node.reviewer)
            self.assertIn(b"not pending", response.data)
        self.assertEqual(self.node.records("issued_authorities"), [])
        self.assertEqual(self.node.get(f"/aia/{current['id']}.cer").status_code, 200)
        self.assert_audit_valid()

    def test_deleting_revoked_issuer_removes_leaf_keys_and_cached_crl(self):
        self.node.add_reviewer()
        issuer = Node(self, "issuing")
        self.node.activate_child(issuer)
        response = issuer.post("/certificates", {"authority_id": "1", "common_name": "deleted.example",
            "subject_alt_names": "deleted.example", "profile": "server", "validity_days": "10"})
        self.assertIn(b"Issued certificate", response.data)
        self.assertTrue(issuer.records("certificates")[0]["private_key_pem"])
        self.assertEqual(issuer.get("/crl/1.crl").status_code, 200)
        self.revoke(node=issuer)
        before = issuer.records("audit_events")

        self.assertEqual(self.delete(node=issuer, name="issuing CA").status_code, 200)

        self.assertEqual(issuer.records("authorities"), [])
        self.assertEqual(issuer.records("certificates"), [])
        with issuer.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM crls").fetchone()[0], 0)
            self.assertEqual(get_db().execute("PRAGMA foreign_key_check").fetchall(), [])
        for artifact in ("cert", "chain"):
            self.assertEqual(issuer.get(f"/certificates/1/{artifact}").status_code, 404)
        self.assertEqual(issuer.records("audit_events")[:len(before)], before)
        self.assert_audit_valid(issuer)
        # Deletion is local: the parent's issued certificate and request remain.
        self.assertEqual(len(self.node.records("issued_authorities")), 1)
        self.assertEqual(len(self.node.records("ca_requests")), 1)

    def test_revoked_pending_ca_can_be_deleted_and_its_name_reused(self):
        pending = Node(self, "issuing")
        original = pending.records("authorities")[0]
        self.revoke(node=pending)

        self.assertEqual(self.delete(node=pending, name="issuing CA").status_code, 200)

        self.assertEqual(pending.records("authorities"), [])
        self.assertEqual(pending.get("/authorities/1/csr").status_code, 404)
        response = pending.post("/authorities", {"name": "issuing CA", "common_name": "issuing CA",
            "role": "issuing", "validity_days": "90"})
        self.assertEqual(response.status_code, 200)
        replacement = pending.records("authorities")[0]
        self.assertGreater(replacement["id"], original["id"])
        self.assertEqual(replacement["state"], "pending")
        self.assertNotEqual(replacement["csr_pem"], original["csr_pem"])
        self.assertNotEqual(replacement["private_key_pem"], original["private_key_pem"])
        self.assert_audit_valid(pending)

    def test_failure_to_record_deletion_rolls_back_all_local_changes(self):
        self.request_child("Pending Archived Issuing")
        self.assertEqual(self.node.get("/crl/1.crl").status_code, 200)
        self.revoke()
        tables = ("authorities", "ca_requests", "issued_authorities", "certificates", "crls", "settings",
                  "retired_ca_keys", "publication_state", "audit_events")

        def snapshot():
            with self.node.app.app_context():
                return {table: [tuple(row) for row in get_db().execute(f"SELECT * FROM {table} ORDER BY 1")]
                        for table in tables}

        before = snapshot()
        with patch("app.audit_event", side_effect=ValueError("Deletion audit refused")):
            response = self.delete()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(snapshot(), before)
        self.assert_audit_valid()

    def test_crl_read_and_deletion_serialize_before_the_authority_lookup(self):
        original = self.node.records("authorities")[0]
        self.revoke()
        token = re.search(rb'name="csrf_token" value="([^"]+)"', self.node.get("/").data).group(1).decode()
        cookie = self.node.client.get_cookie(self.node.app.config["SESSION_COOKIE_NAME"])
        deletion_client = self.node.app.test_client()
        deletion_client.set_cookie(self.node.app.config["SESSION_COOKIE_NAME"], cookie.value, domain="localhost")
        reader_client = self.node.app.test_client()
        lookup_complete, release_reader, deletion_attempted = Event(), Event(), Event()

        def gated_lookup(authority_id):
            authority = get_authority(authority_id)
            if has_request_context() and request.endpoint == "download_crl":
                lookup_complete.set()
                if not release_reader.wait(timeout=10):
                    raise RuntimeError("The concurrency test did not release the CRL reader.")
            return authority

        def traced_database():
            db = get_db()
            if has_request_context() and request.endpoint == "delete_authority":
                db.set_trace_callback(lambda sql: deletion_attempted.set() if sql == "BEGIN IMMEDIATE" else None)
            return db

        with patch("app.get_authority", side_effect=gated_lookup), patch("app.get_db", side_effect=traced_database):
            with ThreadPoolExecutor(max_workers=2) as pool:
                reader = pool.submit(reader_client.get, "/crl/1.crl", base_url=self.node.base)
                try:
                    self.assertTrue(lookup_complete.wait(timeout=5))
                    deletion = pool.submit(deletion_client.post, "/authorities/1/delete", base_url=self.node.base,
                        data={"csrf_token": token, "confirmation_name": "root CA"}, follow_redirects=True)
                    self.assertTrue(deletion_attempted.wait(timeout=5))
                    # SQLite must hold deletion until the in-flight CRL has finished.
                    with self.assertRaises(TimeoutError):
                        deletion.result(timeout=0.15)
                finally:
                    release_reader.set()
                crl_response = reader.result(timeout=10)
                deletion_response = deletion.result(timeout=10)

        self.assertEqual(crl_response.status_code, 200)
        self.assertTrue(x509.load_der_x509_crl(crl_response.data).is_signature_valid(
            x509.load_pem_x509_certificate(original["certificate_pem"].encode()).public_key()))
        self.assertEqual(deletion_response.status_code, 200)
        self.assertEqual(self.node.records("authorities"), [])
        self.assertEqual(self.node.get("/crl/1.crl").status_code, 404)
        self.assert_audit_valid()

    def test_upgrade_replaces_the_old_unconditional_ca_deletion_guard(self):
        self.revoke()
        with self.node.app.app_context():
            db = get_db()
            db.executescript("""
                DROP TRIGGER preserve_local_ca;
                CREATE TRIGGER preserve_local_ca BEFORE DELETE ON authorities
                BEGIN SELECT RAISE(ABORT, 'The local CA cannot be deleted or replaced'); END;
            """)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                db.execute("DELETE FROM authorities WHERE id=1")
            db.rollback()

        restarted = create_app({"TESTING": True, "INSTANCE_PATH": self.node.app.config["INSTANCE_PATH"]})
        restarted_client = restarted.test_client()
        cookie = self.node.client.get_cookie(self.node.app.config["SESSION_COOKIE_NAME"])
        restarted_client.set_cookie(restarted.config["SESSION_COOKIE_NAME"], cookie.value, domain="localhost")
        page = restarted_client.get("/authorities/1", base_url=self.node.base)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()

        response = restarted_client.post("/authorities/1/delete", base_url=self.node.base,
            data={"csrf_token": token, "confirmation_name": "root CA"}, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.node.records("authorities"), [])
        self.assertIn("authority.deleted", [row["action"] for row in self.node.records("audit_events")])
        self.assert_audit_valid()


if __name__ == "__main__":
    unittest.main()
