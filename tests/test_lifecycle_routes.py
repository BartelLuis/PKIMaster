"""Authenticated browser journeys through issuance, revocation, and migration."""

import base64
import hashlib
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import create_app, get_db
import pki


class BrowserJourneyMixin:
    password = "correct horse battery staple"
    base_url = "https://localhost"

    @classmethod
    def setUpClass(cls):
        cls.request_key = ec.generate_private_key(ec.SECP256R1())
        cls.csr_pem = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr.example")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("service.example")]), critical=False)
            .sign(cls.request_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM).decode()
        )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        key_patch = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048))
        key_patch.start()
        self.addCleanup(key_patch.stop)
        self.config = {"TESTING": True, "INSTANCE_PATH": self.temp_dir.name}
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.bootstrap()

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=self.base_url, **kwargs)

    def csrf(self, client=None):
        response = self.get("/", client, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def post(self, path, data=None, client=None, follow_redirects=True):
        selected = client or self.client
        return selected.post(path, data={"csrf_token": self.csrf(selected), **(data or {})},
                             base_url=self.base_url, follow_redirects=follow_redirects)

    def bootstrap(self):
        response = self.post("/setup", {
            "username": "admin", "password": self.password, "password_confirm": self.password,
            "organization": "Route Test Organization", "public_base_url": "https://pki.example",
            "max_leaf_days": "90", "allow_key_export": "on",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Installation complete", response.data)

    def row(self, table, record_id):
        with self.app.app_context():
            return dict(get_db().execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,)).fetchone())

    def count(self, table):
        with self.app.app_context():
            return get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def create_authority(self, name, role, parent_id="", days=365):
        response = self.post("/authorities", {
            "name": name, "common_name": name, "role": role,
            "parent_id": str(parent_id), "validity_days": str(days),
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"Created {role} CA".encode(), response.data)
        with self.app.app_context():
            return dict(get_db().execute("SELECT * FROM authorities WHERE name = ?", (name,)).fetchone())

    def create_hierarchy(self):
        root = self.create_authority("Browser Root", "root")
        intermediate = self.create_authority("Browser Intermediate", "intermediate", root["id"])
        issuer = self.create_authority("Browser Issuing", "issuing", intermediate["id"])
        return root, intermediate, issuer

    def issue(self, authority_id, **changes):
        values = {"common_name": "service.example", "authority_id": str(authority_id),
                  "validity_days": "30", "profile": "server", "csr_pem": self.csr_pem}
        values.update(changes)
        response = self.post("/certificates", values)
        self.assertEqual(response.status_code, 200)
        return response


class LifecycleRouteTests(BrowserJourneyMixin, unittest.TestCase):
    def test_crl_remains_cached_until_expiry_when_issuer_nears_expiration(self):
        issuer = self.create_authority("Expiring Root", "root", days=1)
        near_expiry = datetime.fromisoformat(issuer["not_after"]) - timedelta(minutes=2)
        anonymous = self.app.test_client()
        path = f"/crl/{issuer['id']}.crl"
        with patch("app.utc_now", return_value=near_expiry), patch("pki.utc_now", return_value=near_expiry):
            first = self.get(path, anonymous)
            self.assertEqual(first.status_code, 200)
            crl = x509.load_der_x509_crl(first.data)
            self.assertEqual(crl.next_update_utc, datetime.fromisoformat(issuer["not_after"]))
            for _ in range(3):
                self.assertEqual(self.get(path, anonymous).data, first.data)
        with self.app.app_context():
            published = get_db().execute("SELECT COUNT(*) FROM audit_events WHERE action = 'crl.published'").fetchone()[0]
            self.assertEqual(published, 1)

    def test_authenticated_csr_revocation_and_public_crl_cache_lifecycle(self):
        root, intermediate, issuer = self.create_hierarchy()
        response = self.issue(issuer["id"])
        self.assertIn(b"Issued certificate", response.data)
        record = self.row("certificates", 1)
        self.assertEqual(record["private_key_pem"], "")
        self.assertEqual(record["profile"], "server")
        self.assertEqual(record["subject_alt_names"], "service.example")
        self.assertEqual(self.get("/certificates/1/key").status_code, 404)
        chain = x509.load_pem_x509_certificates(self.get("/certificates/1/chain").data)
        self.assertEqual(len(chain), 4)
        for child, parent in zip(chain, chain[1:]):
            child.verify_directly_issued_by(parent)
        self.assertEqual(chain[0].public_key().public_numbers(), self.request_key.public_key().public_numbers())
        self.assertEqual(list(chain[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.SERVER_AUTH])
        distribution = chain[0].extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        self.assertEqual(distribution[0].full_name[0].value, f"https://pki.example/crl/{issuer['id']}.crl")

        anonymous = self.app.test_client()
        path = f"/crl/{issuer['id']}.crl"
        initial = self.get(path, anonymous)
        self.assertEqual(initial.status_code, 200)
        self.assertEqual(initial.mimetype, "application/pkix-crl")
        first_crl = x509.load_der_x509_crl(initial.data)
        self.assertTrue(first_crl.is_signature_valid(chain[1].public_key()))
        self.assertEqual(len(first_crl), 0)
        self.assertEqual(first_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, 1)
        self.assertEqual(self.get(path, anonymous).data, initial.data)

        revoked = self.post("/certificates/1/revoke", {"reason": "key_compromise"})
        self.assertEqual(revoked.status_code, 200)
        self.assertIsNotNone(self.row("certificates", 1)["revoked_at"])
        published = self.get(path, anonymous)
        second_crl = x509.load_der_x509_crl(published.data)
        self.assertNotEqual(initial.data, published.data)
        self.assertTrue(second_crl.is_signature_valid(chain[1].public_key()))
        self.assertEqual(second_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, 2)
        entry = second_crl.get_revoked_certificate_by_serial_number(chain[0].serial_number)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.extensions.get_extension_for_class(x509.CRLReason).value.reason, x509.ReasonFlags.key_compromise)
        self.assertEqual(self.get(path, anonymous).data, published.data)
        self.post("/certificates/1/revoke", {"reason": "superseded"})
        self.assertEqual(self.row("certificates", 1)["revocation_reason"], "key_compromise")
        self.assertEqual(self.get(path, anonymous).data, published.data)
        with self.app.app_context():
            events = get_db().execute("SELECT action, actor_name FROM audit_events WHERE action IN ('certificate.issued', 'certificate.revoked') ORDER BY id").fetchall()
            self.assertEqual([(row["action"], row["actor_name"]) for row in events], [("certificate.issued", "admin"), ("certificate.revoked", "admin")])

    def test_revoked_ancestor_blocks_leaf_and_subordinate_issuance(self):
        root, intermediate, issuer = self.create_hierarchy()
        response = self.post(f"/authorities/{intermediate['id']}/revoke", {"reason": "ca_compromise"})
        self.assertEqual(response.status_code, 200)
        response = self.issue(issuer["id"])
        self.assertIn(b"ancestor is revoked", response.data)
        self.assertEqual(self.count("certificates"), 0)
        response = self.post("/authorities", {"name": "Blocked Issuer", "common_name": "Blocked Issuer",
            "role": "issuing", "parent_id": str(intermediate["id"]), "validity_days": "30"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ancestor is revoked", response.data)
        self.assertEqual(self.count("authorities"), 3)
        crl = x509.load_der_x509_crl(self.get(f"/crl/{root['id']}.crl", self.app.test_client()).data)
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(int(intermediate["serial_number"], 16)))
        # A revoked CA may continue publishing its own revocation information.
        self.assertEqual(self.get(f"/crl/{intermediate['id']}.crl", self.app.test_client()).status_code, 200)

    def test_local_root_distrust_disables_its_descendants(self):
        root, _, issuer = self.create_hierarchy()
        response = self.post(f"/authorities/{root['id']}/revoke", {"reason": "ca_compromise"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(self.row("authorities", root["id"])["revoked_at"])
        self.assertIn(b"ancestor is revoked", self.issue(issuer["id"]).data)
        self.assertEqual(self.count("certificates"), 0)

    def test_web_validity_policy_caps_requested_lifetime(self):
        root = self.create_authority("Policy Root", "root", days=365)
        issuer = self.create_authority("Policy Issuer", "issuing", root["id"], days=365)
        self.assertIn(b"Issued certificate", self.issue(issuer["id"], validity_days="825").data)
        first = x509.load_pem_x509_certificate(self.row("certificates", 1)["certificate_pem"].encode())
        self.assertEqual(round((first.not_valid_after_utc - first.not_valid_before_utc).total_seconds() / 86400), 90)
        response = self.post("/settings", {"organization": "Route Test Organization", "max_leaf_days": "5",
            "public_base_url": "https://pki.example", "crl_days": "2", "allow_key_export": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Issued certificate", self.issue(issuer["id"], validity_days="365").data)
        second = x509.load_pem_x509_certificate(self.row("certificates", 2)["certificate_pem"].encode())
        self.assertEqual(round((second.not_valid_after_utc - second.not_valid_before_utc).total_seconds() / 86400), 5)

    def test_crypto_validation_failures_are_displayed_and_rollback(self):
        root = self.create_authority("Validation Root", "root")
        issuer = self.create_authority("Validation Issuer", "issuing", root["id"])
        requests = [
            {"csr_pem": "not a PEM CSR"}, {"profile": "code_signing"},
            {"subject_alt_names": "https://invalid.example"}, {"common_name": "a" * 65},
        ]
        for changes in requests:
            with self.subTest(changes=changes):
                response = self.issue(issuer["id"], **changes)
                self.assertNotIn(b"<li>Issued certificate", response.data)
                self.assertEqual(self.count("certificates"), 0)
        response = self.issue(issuer["id"], subject_alt_names="service.example\n192.0.2.10")
        self.assertIn(b"Issued certificate", response.data)
        response = self.post("/certificates/1/revoke", {"reason": "remove_from_crl"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.row("certificates", 1)["revoked_at"])

    def test_roles_cannot_bypass_web_route_permissions(self):
        root = self.create_authority("Permission Root", "root")
        issuer = self.create_authority("Permission Issuer", "issuing", root["id"])
        self.issue(issuer["id"])
        for role in ("operator", "auditor"):
            response = self.post("/users", {"action": "create", "username": role,
                "password": self.password, "role": role})
            self.assertEqual(response.status_code, 200)
            actor = self.app.test_client()
            response = self.post("/login", {"username": role, "password": self.password}, actor)
            self.assertEqual(response.status_code, 200)
            for path, data in (
                ("/authorities", {"name": "Unauthorized", "role": "root", "common_name": "Unauthorized"}),
                (f"/authorities/{issuer['id']}/revoke", {"reason": "ca_compromise"}),
                ("/settings", {"organization": "Unauthorized"}),
                ("/users", {"action": "create", "username": "intruder", "password": self.password, "role": "admin"}),
            ):
                with self.subTest(role=role, path=path):
                    self.assertEqual(self.post(path, data, actor).status_code, 403)
            self.assertEqual(self.get(f"/authorities/{issuer['id']}/key", actor).status_code, 403)
            self.assertEqual(self.get("/certificates/1/key", actor).status_code, 403)
            if role == "auditor":
                self.assertEqual(self.post("/certificates", {"authority_id": str(issuer["id"]), "common_name": "unauthorized.example"}, actor).status_code, 403)
                self.assertEqual(self.post("/certificates/1/revoke", {"reason": "superseded"}, actor).status_code, 403)
            else:
                issued = self.post("/certificates", {"authority_id": str(issuer["id"]), "common_name": "operator.example", "csr_pem": self.csr_pem}, actor)
                self.assertIn(b"Issued certificate", issued.data)
        self.assertEqual(self.count("authorities"), 2)
        self.assertEqual(self.count("certificates"), 2)
        self.assertIsNone(self.row("certificates", 1)["revoked_at"])

    def test_setup_is_closed_and_anonymous_mutations_require_login(self):
        anonymous = self.app.test_client()
        self.assertEqual(self.get("/setup", anonymous).status_code, 404)
        response = anonymous.post("/authorities", data={"name": "Anonymous", "role": "root", "common_name": "Anonymous"}, base_url=self.base_url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))
        response = self.client.post("/authorities", data={"csrf_token": "wrong", "name": "Bad CSRF", "role": "root", "common_name": "Bad CSRF"}, base_url=self.base_url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.count("authorities"), 0)

    def test_fresh_setup_rejects_remote_clients_and_forged_forwarding_headers(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        fresh_app = create_app({"TESTING": True, "INSTANCE_PATH": directory.name})
        browser = fresh_app.test_client()
        for headers in ({}, {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}):
            with self.subTest(headers=headers):
                response = browser.get("/setup", base_url=self.base_url,
                    environ_overrides={"REMOTE_ADDR": "203.0.113.10"}, headers=headers)
                self.assertEqual(response.status_code, 403)
        local = browser.get("/setup", base_url=self.base_url)
        self.assertEqual(local.status_code, 200)
        self.assertIn(b"csrf_token", local.data)
        rejected = browser.post("/setup", base_url=self.base_url, data={
            "username": "intruder", "password": self.password, "password_confirm": self.password,
            "organization": "Forged installation",
        })
        self.assertEqual(rejected.status_code, 403)
        with fresh_app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)


class LegacyMigrationRouteTests(BrowserJourneyMixin, unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        key_patch = patch("pki.generate_private_key", side_effect=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048))
        key_patch.start()
        self.addCleanup(key_patch.stop)
        self.legacy_secret = "legacy-installation-encryption-secret"
        cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(self.legacy_secret.encode()).digest()))
        self.root = pki.create_ca_certificate("Legacy Root", 365, "root")
        self.leaf = pki.issue_end_entity_certificate("legacy.example", self.root[0], self.root[1], 90, ["legacy.example"], profile="dual")
        self.encrypted_root = cipher.encrypt(self.root[1].encode()).decode()
        self.encrypted_leaf = cipher.encrypt(self.leaf[1].encode()).decode()
        database = Path(self.temp_dir.name) / "pkimaster.sqlite"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.executescript("""
                CREATE TABLE authorities (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
                    common_name TEXT NOT NULL, parent_id INTEGER, certificate_pem TEXT NOT NULL,
                    private_key_pem TEXT NOT NULL, serial_number TEXT NOT NULL,
                    not_before TEXT NOT NULL, not_after TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                CREATE TABLE certificates (
                    id INTEGER PRIMARY KEY, common_name TEXT NOT NULL, authority_id INTEGER NOT NULL,
                    subject_alt_names TEXT NOT NULL DEFAULT '', certificate_pem TEXT NOT NULL,
                    private_key_pem TEXT NOT NULL, serial_number TEXT NOT NULL,
                    not_before TEXT NOT NULL, not_after TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            """)
            connection.execute("INSERT INTO authorities(id,name,role,common_name,certificate_pem,private_key_pem,serial_number,not_before,not_after) VALUES (1,'Legacy Root','root','Legacy Root',?,?,?,?,?)",
                (self.root[0], self.encrypted_root, *self.root[2:]))
            connection.execute("INSERT INTO certificates(id,common_name,authority_id,subject_alt_names,certificate_pem,private_key_pem,serial_number,not_before,not_after) VALUES (1,'legacy.example',1,'legacy.example',?,?,?,?,?)",
                (self.leaf[0], self.encrypted_leaf, *self.leaf[2:]))
        self.config = {"TESTING": True, "INSTANCE_PATH": self.temp_dir.name, "SECRET_KEY": self.legacy_secret}
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.bootstrap()

    def test_migration_preserves_certificates_encrypted_keys_and_restart_access(self):
        root = self.row("authorities", 1)
        leaf = self.row("certificates", 1)
        self.assertEqual(root["certificate_pem"], self.root[0])
        self.assertEqual(root["private_key_pem"], self.encrypted_root)
        self.assertEqual(leaf["certificate_pem"], self.leaf[0])
        self.assertEqual(leaf["private_key_pem"], self.encrypted_leaf)
        self.assertEqual(leaf["profile"], "dual")
        self.assertIsNone(leaf["revoked_at"])
        self.assertIsNone(root["revoked_at"])
        self.assertEqual(self.get("/authorities/1/key").data.decode(), self.root[1])
        self.assertEqual(self.get("/certificates/1/key").data.decode(), self.leaf[1])
        self.assertTrue((Path(self.temp_dir.name) / "runtime-secrets.json").is_file())

        # A later service start needs no legacy environment/configuration secrets.
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": self.temp_dir.name})
        self.client = self.app.test_client()
        response = self.post("/login", {"username": "admin", "password": self.password})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.get("/certificates/1/key").data.decode(), self.leaf[1])
        chain = x509.load_pem_x509_certificates(self.get("/certificates/1/chain").data)
        self.assertEqual(len(chain), 2)
        chain[0].verify_directly_issued_by(chain[1])


if __name__ == "__main__":
    unittest.main()
