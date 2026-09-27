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

    def create_external_root(self, config, signer, key_id, name="root"):
        pinned = {**config, "key_id": key_id, "public_key_sha256": public_key_fingerprint(signer.public_key())}
        with patch("key_backends.provision_signer", return_value=(signer, pinned)) as provision:
            self.assertEqual(self.post("/authorities", {"name": name, "role": "root", "common_name": name}).status_code, 302)
        return pinned, provision.call_args.args[1]

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
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.data, b"The CRL could not be generated.")
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

    def test_revoked_provider_can_be_replaced_without_losing_old_crl_credentials(self):
        self.post("/settings/keys", self.azure())
        signer = TestSigner()
        pinned, _ = self.create_external_root(self.azure(), signer, "https://example.vault.azure.net/keys/ca-key/abc")
        self.post("/authorities/1/revoke", {"reason": "ca_compromise"})
        self.assertEqual(self.post("/settings/keys", {"backend": "software"}).status_code, 302)
        self.post("/authorities", {"name": "replacement", "role": "root", "common_name": "Replacement"})
        with self.app.app_context():
            rows = get_db().execute("SELECT * FROM authorities ORDER BY id").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["key_backend"], "azure")
            self.assertEqual(json.loads(rows[0]["key_reference"])["key_id"], pinned["key_id"])
            self.assertEqual(rows[1]["key_backend"], "software")
            encrypted = get_db().execute("SELECT value FROM settings WHERE key='authority_key_storage:1'").fetchone()[0]
            self.assertNotIn("secret-not-for-display", encrypted)
        # A restart still resolves the retired CA with its original credentials.
        restarted = create_app({"TESTING": True, "INSTANCE_PATH": self.directory.name})
        with patch("key_backends.load_signer", return_value=signer) as load:
            response = restarted.test_client().get("/crl/1.crl")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(load.call_args.args[0], "azure")
        self.assertEqual(load.call_args.args[1]["client_secret"], self.azure()["client_secret"])
        self.assertEqual(load.call_args.args[1]["key_id"], pinned["key_id"])
        page = self.client.get("/settings/keys")
        self.assertIn(b'This CA is permanently bound to Encrypted software key', page.data)
        self.assertEqual(self.post("/settings/keys", self.azure()).status_code, 400)

    def check_external_replacement(self, config, old_id, new_id):
        self.assertEqual(self.post("/settings/keys", config).status_code, 302)
        old_signer, new_signer = TestSigner(), TestSigner()
        pinned, _ = self.create_external_root(config, old_signer, old_id)
        self.post("/authorities/1/revoke", {"reason": "ca_compromise"})
        page = self.client.get("/settings/keys")
        self.assertIn(b'Save key storage', page.data)
        self.assertNotIn(old_id.encode(), page.data)
        _, provisioned_config = self.create_external_root(config, new_signer, new_id, "replacement")
        self.assertNotIn("key_id", provisioned_config)
        self.assertNotIn("public_key_sha256", provisioned_config)
        with self.app.app_context():
            rows = get_db().execute("SELECT * FROM authorities ORDER BY id").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertIsNotNone(rows[0]["revoked_at"])
            self.assertIsNone(rows[1]["revoked_at"])
            self.assertEqual(json.loads(rows[0]["key_reference"])["key_id"], pinned["key_id"])
            self.assertEqual(json.loads(rows[1]["key_reference"])["key_id"], new_id)
        with patch("key_backends.load_signer", return_value=old_signer) as load:
            self.assertEqual(self.client.get("/crl/1.crl").status_code, 200)
        self.assertEqual(load.call_args.args[1]["key_id"], old_id)
        return provisioned_config

    def test_azure_replacement_creates_new_version_of_inherited_key(self):
        config = self.azure()
        config["key_name"] = ""
        old_id = "https://example.vault.azure.net/keys/ca-key/abc"
        config["azure_key_id"] = old_id
        actual = self.check_external_replacement(config, old_id, "https://example.vault.azure.net/keys/ca-key/def")
        self.assertEqual(actual["key_name"], "ca-key")
        self.assertEqual(actual["client_secret"], config["client_secret"])

    def test_pkcs11_replacement_creates_new_key_in_same_token(self):
        config = {"backend": "pkcs11", "module_path": str(Path(self.directory.name) / "pkcs11.dll"),
                  "token_label": "CA token", "token_serial": "original-token", "user_pin": "secret-user-pin"}
        actual = self.check_external_replacement(config, "abcdef12", "1234abcd")
        self.assertEqual(actual["token_serial"], config["token_serial"])
        self.assertEqual(actual["user_pin"], config["user_pin"])

    def test_revoked_key_cannot_be_explicitly_reused_for_new_ca(self):
        self.post("/settings/keys", self.azure())
        signer = TestSigner()
        old_id = "https://example.vault.azure.net/keys/ca-key/abc"
        pinned, _ = self.create_external_root(self.azure(), signer, old_id)
        self.post("/authorities/1/revoke", {"reason": "ca_compromise"})
        self.assertEqual(self.post("/settings/keys", {**self.azure(), "azure_key_id": old_id}).status_code, 302)
        with self.app.app_context():
            before = dict(get_db().execute("SELECT key, value FROM settings WHERE key='key_storage_config' OR key GLOB 'authority_key_storage:*'"))
        with patch("key_backends.provision_signer", return_value=(signer, pinned)):
            self.post("/authorities", {"name": "replacement", "role": "root", "common_name": "Replacement"})
        self.assertIn(b"selected signing key belongs to a revoked CA", self.client.get("/").data)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM authorities").fetchone()[0], 1)
            after = dict(get_db().execute("SELECT key, value FROM settings WHERE key='key_storage_config' OR key GLOB 'authority_key_storage:*'"))
            self.assertEqual(after, before)

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
