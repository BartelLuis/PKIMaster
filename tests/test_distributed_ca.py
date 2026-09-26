"""End-to-end browser operations across physically separate CA state directories."""
import re
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app import create_app, get_db
from mfa_helpers import complete_mfa


class Node:
    password = "a separate secure administrator passphrase"
    base = "https://localhost"

    def __init__(self, case, role):
        directory = tempfile.TemporaryDirectory()
        case.addCleanup(directory.cleanup)
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": directory.name})
        self.client = self.app.test_client()
        response = self.post("/setup", {"username": "admin", "password": self.password,
            "password_confirm": self.password, "organization": "Distributed test",
            "public_base_url": "https://" + role + ".example", "max_leaf_days": "90"})
        assert response.status_code == 200
        complete_mfa(self.client, self.app)
        self.post("/authorities", {"name": role + " CA", "common_name": role + " CA", "role": role, "validity_days": "365"})

    def get(self, path, client=None):
        return (client or self.client).get(path, base_url=self.base, follow_redirects=True)

    def post(self, path, data=None, client=None):
        client = client or self.client
        page = self.get("/", client)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        return client.post(path, base_url=self.base, data={"csrf_token": token, **(data or {})}, follow_redirects=True)

    def records(self, table):
        with self.app.app_context():
            return [dict(row) for row in get_db().execute(f"SELECT * FROM {table} ORDER BY id")]

    def add_reviewer(self):
        self.post("/users", {"action": "create", "username": "reviewer", "role": "admin", "password": self.password})
        self.reviewer = self.app.test_client()
        self.post("/login", {"username": "reviewer", "password": self.password}, self.reviewer)
        complete_mfa(self.reviewer, self.app, "reviewer")

    def request_child(self, child):
        return self.post("/ca/requests", {"csr_pem": child.get("/authorities/1/csr").data.decode(),
            "role": child.records("authorities")[0]["role"], "validity_days": "180"})

    def activate_child(self, child, request_id=1, parent_crls=""):
        self.request_child(child)
        approved = self.post(f"/ca/requests/{request_id}/approve", client=self.reviewer)
        assert b"Subordinate CA certificate signed" in approved.data, approved.data
        issued_id = self.records("ca_requests")[-1]["issued_id"]
        imported = child.post("/ca/activate", {
            "certificate_pem": self.get(f"/subordinates/{issued_id}/cert").data.decode(),
            "chain_pem": self.get(f"/subordinates/{issued_id}/parents").data.decode(),
            "trusted_root_sha256": x509.load_pem_x509_certificates(self.get(f"/subordinates/{issued_id}/parents").data)[-1].fingerprint(hashes.SHA256()).hex(),
        })
        assert b"CA certificate imported" in imported.data, imported.data
        crls = self.get("/crl/1.crl?format=pem").data.decode() + parent_crls
        result = child.post("/ca/parent-crls", {"parent_crls_pem": crls})
        assert b"Parent CRLs validated" in result.data, result.data
        return crls


class DistributedCATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())
        cls.leaf_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "service.example")])).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("service.example")]), critical=False
            ).sign(cls.leaf_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    def setUp(self):
        generator = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072))
        generator.start()
        self.addCleanup(generator.stop)
        self.root = Node(self, "root")
        self.root.add_reviewer()
        self.issuing = Node(self, "issuing")

    def issue(self, **updates):
        data = {"authority_id": "1", "common_name": "service.example", "csr_pem": self.leaf_csr,
                "validity_days": "30", "profile": "server"}
        data.update(updates)
        return self.issuing.post("/certificates", data)

    def test_three_distinct_servers_chain_and_key_custody(self):
        intermediate = Node(self, "intermediate")
        intermediate.add_reviewer()
        root_crls = self.root.activate_child(intermediate)
        intermediate.activate_child(self.issuing, parent_crls=root_crls)
        self.assertIn(b"Issued certificate", self.issue().data)
        chain = x509.load_pem_x509_certificates(self.issuing.get("/certificates/1/chain").data)
        self.assertEqual(len(chain), 4)
        for child, parent in zip(chain, chain[1:]):
            child.verify_directly_issued_by(parent)
        for node in (self.root, intermediate, self.issuing):
            self.assertEqual(len(node.records("authorities")), 1)
            with node.app.app_context():
                columns = {row[1] for row in get_db().execute("PRAGMA table_info(issued_authorities)")}
                self.assertNotIn("private_key_pem", columns)
            self.assertEqual(node.get("/authorities/1/key").status_code, 403)
        self.assertEqual(self.issuing.records("certificates")[0]["private_key_pem"], "")

    def test_independent_approval_is_required_and_cannot_be_replayed(self):
        self.assertIn(b"different administrator", self.root.request_child(self.issuing).data)
        denied = self.root.post("/ca/requests/1/approve")
        self.assertIn(b"requester cannot approve", denied.data)
        self.assertEqual(self.root.records("issued_authorities"), [])
        with self.root.app.app_context():
            with self.assertRaises(sqlite3.IntegrityError):
                get_db().execute("UPDATE ca_requests SET role='intermediate' WHERE id=1")
            get_db().rollback()
        approved = self.root.post("/ca/requests/1/approve", client=self.root.reviewer)
        self.assertIn(b"Subordinate CA certificate signed", approved.data)
        self.assertIn(b"not pending", self.root.post("/ca/requests/1/approve", client=self.root.reviewer).data)
        self.assertEqual(len(self.root.records("issued_authorities")), 1)
        self.assertEqual(len(self.root.records("authorities")), 1)
        self.assertEqual(self.root.records("ca_requests")[0]["reviewed_by"], 2)

    def test_pending_ca_and_missing_parent_status_block_issuance(self):
        self.assertIn(b"Awaiting a signed CA", self.issue().data)
        self.assertEqual(self.issuing.get("/crl/1.crl").status_code, 409)
        self.root.request_child(self.issuing)
        self.root.post("/ca/requests/1/approve", client=self.root.reviewer)
        response = self.issuing.post("/ca/activate", {
            "certificate_pem": self.root.get("/subordinates/1/cert").data.decode(),
            "chain_pem": self.root.get("/subordinates/1/parents").data.decode(),
            "trusted_root_sha256": x509.load_pem_x509_certificate(self.root.get("/authorities/1/cert").data).fingerprint(hashes.SHA256()).hex()})
        self.assertIn(b"CA certificate imported", response.data)
        self.assertIn(b"Import current signed parent CRLs", self.issue().data)
        self.assertEqual(self.issuing.records("certificates"), [])

    def test_parent_revocation_propagates_and_cannot_be_undone_by_rollback(self):
        old_crl = self.root.activate_child(self.issuing)
        self.root.post("/subordinates/1/revoke", {"reason": "ca_compromise"})
        updated = self.root.get("/crl/1.crl?format=pem").data.decode()
        crl = x509.load_pem_x509_crl(updated.encode())
        cert = x509.load_pem_x509_certificate(self.issuing.get("/authorities/1/cert").data)
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(cert.serial_number))
        result = self.issuing.post("/ca/parent-crls", {"parent_crls_pem": updated})
        self.assertIn(b"CA signing is blocked", result.data)
        self.assertIn(b"local CA has been disabled", self.issue().data)
        rollback = self.issuing.post("/ca/parent-crls", {"parent_crls_pem": old_crl})
        self.assertNotIn(b"Parent CRLs validated and imported", rollback.data)
        self.assertEqual(self.issuing.records("authorities")[0]["parent_crls_pem"], updated)
        self.assertEqual(self.issuing.records("certificates"), [])

    def test_stale_or_forged_parent_crls_block_signing(self):
        self.root.activate_child(self.issuing)
        before = self.issuing.records("authorities")[0]["parent_crls_pem"]
        forged = self.issuing.get("/crl/1.crl?format=pem").data.decode()
        self.assertIn(b"signature or issuer is invalid", self.issuing.post("/ca/parent-crls", {"parent_crls_pem": forged}).data)
        self.assertEqual(self.issuing.records("authorities")[0]["parent_crls_pem"], before)
        with patch("app.utc_now", return_value=datetime.now(UTC) + timedelta(days=8)):
            self.assertIn(b"stale", self.issue().data)
        self.assertEqual(self.issuing.records("certificates"), [])

    def test_leaf_csr_policy_revocation_public_crl_and_persistence(self):
        self.root.activate_child(self.issuing)
        self.assertIn(b"Issued certificate", self.issue(validity_days="800").data)
        certificate = x509.load_pem_x509_certificate(self.issuing.get("/certificates/1/cert").data)
        self.assertEqual(round((certificate.not_valid_after_utc - certificate.not_valid_before_utc).total_seconds() / 86400), 90)
        self.assertEqual(certificate.public_key().public_numbers(), self.leaf_key.public_key().public_numbers())
        first = self.issuing.get("/crl/1.crl").data
        self.assertEqual(first, self.issuing.get("/crl/1.crl").data)
        self.issuing.post("/certificates/1/revoke", {"reason": "key_compromise"})
        anonymous = self.issuing.app.test_client()
        revoked = x509.load_der_x509_crl(self.issuing.get("/crl/1.crl", anonymous).data)
        self.assertIsNotNone(revoked.get_revoked_certificate_by_serial_number(certificate.serial_number))
        restarted = create_app({"TESTING": True, "INSTANCE_PATH": self.issuing.app.config["INSTANCE_PATH"]})
        self.assertEqual(restarted.test_client().get("/crl/1.crl").status_code, 200)

    def test_activation_is_atomic_and_bound_to_local_key(self):
        self.root.request_child(self.issuing)
        self.root.post("/ca/requests/1/approve", client=self.root.reviewer)
        original = self.issuing.records("authorities")[0]
        for certificate, chain in (("invalid", ""), (self.root.get("/authorities/1/cert").data.decode(), ""),
                                   (self.root.get("/subordinates/1/cert").data.decode(), "")):
            self.issuing.post("/ca/activate", {"certificate_pem": certificate, "chain_pem": chain})
            self.assertEqual(self.issuing.records("authorities")[0], original)

    def test_role_permissions_and_crypto_failures_are_enforced(self):
        self.root.activate_child(self.issuing)
        for invalid in ({"csr_pem": "invalid"}, {"profile": "code_signing"}, {"subject_alt_names": "https://bad.example"}, {"common_name": "a" * 65}):
            self.issue(**invalid)
            self.assertEqual(self.issuing.records("certificates"), [])
        for role in ("operator", "auditor"):
            self.issuing.post("/users", {"action": "create", "username": role, "role": role, "password": Node.password})
            client = self.issuing.app.test_client()
            self.issuing.post("/login", {"username": role, "password": Node.password}, client)
            complete_mfa(client, self.issuing.app, role)
            for path in ("/ca/activate", "/ca/parent-crls", "/ca/requests", "/ca/requests/1/approve", "/subordinates/1/revoke"):
                self.assertEqual(self.issuing.post(path, client=client).status_code, 403, path)
            data = {"authority_id": "1", "common_name": "service.example", "csr_pem": self.leaf_csr}
            result = self.issuing.post("/certificates", data, client)
            self.assertEqual(result.status_code, 403 if role == "auditor" else 200)
        self.assertEqual(len(self.issuing.records("certificates")), 1)


if __name__ == "__main__":
    unittest.main()
