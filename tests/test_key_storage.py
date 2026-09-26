import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from app import create_app, get_db
from key_backends import ExternalSigner, pss_padding, public_key_fingerprint
from mfa_helpers import complete_mfa


class TestSigner(ExternalSigner):
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def public_key(self):
        return self.key.public_key()

    def _sign(self, data):
        return self.key.sign(data, pss_padding(), hashes.SHA256())


class KeyStorageWebTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": self.directory.name})
        self.client = self.app.test_client()
        self.post("/setup", {"username": "admin", "password": "a long administrator passphrase", "password_confirm": "a long administrator passphrase", "organization": "Test"})
        complete_mfa(self.client, self.app, base_url="http://localhost")

    def post(self, path, data):
        page = self.client.get("/", follow_redirects=True)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        return self.client.post(path, data={**data, "csrf_token": token})

    def azure(self):
        return {"backend": "azure", "vault_url": "https://example.vault.azure.net", "tenant_id": "tenant", "client_id": "client", "client_secret": "secret-not-for-display", "key_name": "ca-key", "key_type": "RSA-HSM"}

    def test_provider_secrets_are_encrypted_and_never_rendered(self):
        self.assertEqual(self.post("/settings/keys", self.azure()).status_code, 302)
        page = self.client.get("/settings/keys")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b"secret-not-for-display", page.data)
        with self.app.app_context():
            value = get_db().execute("SELECT value FROM settings WHERE key='key_storage_config'").fetchone()[0]
            self.assertNotIn("secret-not-for-display", value)
        self.assertEqual(self.post("/settings/keys", {**self.azure(), "vault_url": "http://untrusted.example"}).status_code, 400)

    def test_external_ca_stores_only_immutable_key_reference_and_rejects_fallback(self):
        self.post("/settings/keys", self.azure())
        signer = TestSigner()
        pinned = {**self.azure(), "key_id": "https://example.vault.azure.net/keys/ca-key/abc", "public_key_sha256": public_key_fingerprint(signer.public_key())}
        with patch("key_backends.provision_signer", return_value=(signer, pinned)):
            response = self.post("/authorities", {"name": "root", "role": "root", "common_name": "Root CA"})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            db = get_db()
            authority = db.execute("SELECT * FROM authorities").fetchone()
            self.assertEqual(authority["key_backend"], "azure")
            self.assertEqual(authority["private_key_pem"], "")
            self.assertNotIn("secret-not-for-display", authority["key_reference"])
            self.assertEqual(json.loads(authority["key_reference"])["key_id"], pinned["key_id"])
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE authorities SET key_backend='software'")
            db.rollback()
        self.assertEqual(self.post("/settings/keys", {"backend": "software"}).status_code, 400)
        with patch("key_backends.load_signer", side_effect=ValueError("Provider unavailable")):
            response = self.client.get("/crl/1.crl")
            self.assertGreaterEqual(response.status_code, 400)
        with patch("key_backends.provision_signer") as provision:
            self.post("/authorities", {"name": "second", "role": "root", "common_name": "Second"})
            provision.assert_not_called()

    def test_external_signatures_credential_rotation_and_export(self):
        self.post("/settings/keys", self.azure())
        signer = TestSigner()
        pinned = {**self.azure(), "key_id": "https://example.vault.azure.net/keys/ca-key/abc", "public_key_sha256": public_key_fingerprint(signer.public_key())}
        with patch("key_backends.provision_signer", return_value=(signer, pinned)):
            self.post("/authorities", {"name": "root", "role": "root", "common_name": "Root CA"})
        with patch("key_backends.load_signer", return_value=signer):
            self.assertEqual(self.client.get("/crl/1.crl").status_code, 200)
            self.assertEqual(self.post("/settings/keys", {"backend": "azure", "client_secret": "replacement-secret"}).status_code, 302)
        self.assertEqual(self.client.get("/authorities/1/key").status_code, 403)
        export = self.client.get("/security/audit-export")
        self.assertEqual(export.status_code, 200)
        self.assertEqual(export.json["format"], "pkimaster-audit-v1")
        self.assertNotIn(b"replacement-secret", export.data)

    def test_corrupt_audit_blocks_mutations_and_restart(self):
        with self.app.app_context():
            db = get_db()
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit_events SET detail='tampered' WHERE id=1")
            db.commit()
        response = self.post("/authorities", {"name": "root", "role": "root", "common_name": "Root CA"})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.client.get("/security/audit-export").status_code, 409)
        from audit_integrity import AuditIntegrityError
        with self.assertRaises(AuditIntegrityError):
            create_app({"TESTING": True, "INSTANCE_PATH": self.directory.name})
