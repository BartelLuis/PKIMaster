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
from mfa_helpers import complete_mfa


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
        complete_mfa(self.client, self.app, base_url=self.base_url)

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
        self.assertEqual(self.get("/authorities/1/key").status_code, 403)
        self.assertEqual(self.get("/certificates/1/key").data.decode(), self.leaf[1])
        self.assertTrue((Path(self.temp_dir.name) / "runtime-secrets.json").is_file())

        # A later service start needs no legacy environment/configuration secrets.
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": self.temp_dir.name})
        self.client = self.app.test_client()
        response = self.post("/login", {"username": "admin", "password": self.password})
        self.assertEqual(response.status_code, 200)
        complete_mfa(self.client, self.app, base_url=self.base_url)
        self.assertEqual(self.get("/certificates/1/key").data.decode(), self.leaf[1])
        chain = x509.load_pem_x509_certificates(self.get("/certificates/1/chain").data)
        self.assertEqual(len(chain), 2)
        chain[0].verify_directly_issued_by(chain[1])


if __name__ == "__main__":
    unittest.main()
