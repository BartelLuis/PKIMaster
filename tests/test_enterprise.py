import io
import json
import re
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask

from app import create_app, encrypt_private_key, get_db
from enterprise import configure_runtime, get_setting


class EnterpriseTestCase(unittest.TestCase):
    password = "a long administrator passphrase"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = {"TESTING": True, "INSTANCE_PATH": self.directory.name,
                       "DATABASE": str(Path(self.directory.name) / "pkimaster.sqlite"), "SESSION_COOKIE_SECURE": True}
        self.app = create_app(self.config)
        self.client = self.app.test_client()

    def csrf(self, client=None, path="/"):
        client = client or self.client
        response = client.get(path, follow_redirects=True)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match, response.data)
        return match.group(1).decode()

    def post(self, path, data, client=None, **kwargs):
        client = client or self.client
        return client.post(path, data={"csrf_token": self.csrf(client), **data}, **kwargs)

    def setup_admin(self):
        result = self.post("/setup", {"username": "admin", "password": self.password,
                                      "password_confirm": self.password, "organization": "Example Enterprise"})
        self.assertEqual(result.status_code, 302, result.data)

    def create_user(self, username="reader", role="auditor"):
        response = self.post("/users", {"action": "create", "username": username, "role": role, "password": self.password})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            return get_db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]

    def login_as(self, username, password=None):
        client = self.app.test_client()
        result = self.post("/login", {"username": username, "password": password or self.password}, client=client)
        self.assertEqual(result.status_code, 302, result.data)
        return client

    def settings_data(self, **updates):
        values = {"organization": "Example Enterprise", "public_base_url": "https://pki.example.com",
                  "max_leaf_days": "397", "crl_days": "7", "session_minutes": "30",
                  "listen_address": "127.0.0.1", "https_port": "8443"}
        values.update(updates)
        return values

    def test_setup_requires_loopback_and_rejects_forwarded_spoofing(self):
        response = self.client.get("/setup", environ_overrides={"REMOTE_ADDR": "192.0.2.10"}, headers={"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get("/healthz", environ_overrides={"REMOTE_ADDR": "192.0.2.10"}).status_code, 200)
        self.assertEqual(self.client.get("/setup", environ_overrides={"REMOTE_ADDR": "::1"}).status_code, 200)
        self.assertEqual(self.client.get("/setup", headers={"Host": "attacker.example"}).status_code, 403)

    def test_cross_origin_posts_rejected_even_with_csrf(self):
        token = self.csrf()
        response = self.client.post("/setup", data={"csrf_token": token}, headers={"Origin": "https://attacker.example"})
        self.assertEqual(response.status_code, 403)

    def test_setup_is_single_use_and_has_no_default_account(self):
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.setup_admin()
        self.assertEqual(self.client.get("/setup").status_code, 404)
        self.assertEqual(self.client.get("/").status_code, 200)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
            self.assertFalse(get_setting("allow_key_export"))
            user = get_db().execute("SELECT * FROM users").fetchone()
            self.assertNotEqual(user["password_hash"], self.password)
            self.assertEqual(user["role"], "admin")

    def test_setup_rejects_short_password_without_partial_installation(self):
        response = self.post("/setup", {"username": "admin", "password": "short", "password_confirm": "short", "organization": "Example"})
        self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_authentication_is_required_and_cookies_are_hardened(self):
        self.setup_admin()
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/").location, "/login")
        self.assertEqual(anonymous.get("/authorities/1/cert").location, "/login")
        response = anonymous.get("/login")
        cookie = response.headers["Set-Cookie"]
        for flag in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(flag, cookie)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_all_post_forms_require_csrf(self):
        self.assertEqual(self.client.post("/setup", data={"username": "admin"}).status_code, 403)
        self.setup_admin()
        for path in ("/logout", "/users", "/settings", "/password", "/authorities", "/certificates"):
            self.assertEqual(self.client.post(path, data={}).status_code, 403, path)

    def test_auditor_cannot_mutate_and_operator_cannot_manage_ca_or_settings(self):
        self.setup_admin()
        self.create_user()
        self.create_user("operator", "operator")
        reader = self.login_as("reader")
        operator = self.login_as("operator")
        for client in (reader, operator):
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/audit").status_code, 200)
            for path in ("/users", "/settings"):
                self.assertEqual(client.get(path).status_code, 403)
            self.assertEqual(self.post("/authorities", {}, client=client).status_code, 403)
            self.assertEqual(client.get("/certificates/1/key").status_code, 403)
        self.assertEqual(self.post("/certificates", {}, client=reader).status_code, 403)
        # The operator reaches issuance validation, which redirects for missing inputs.
        self.assertEqual(self.post("/certificates", {}, client=operator).status_code, 302)

    def test_last_administrator_cannot_be_deactivated(self):
        self.setup_admin()
        response = self.post("/users", {"action": "deactivate", "user_id": "1"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"last active administrator", response.data)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT active FROM users WHERE id=1").fetchone()[0], 1)
        self.assertEqual(self.post("/users", {"action": "deactivate", "user_id": "9" * 100}).status_code, 400)
        self.assertEqual(self.client.get("/audit?before=" + "9" * 100).status_code, 200)

    def test_disabling_account_and_password_reset_revoke_existing_sessions(self):
        self.setup_admin()
        reader_id = self.create_user()
        reader = self.login_as("reader")
        self.post("/users", {"action": "reset_password", "user_id": str(reader_id), "password": "the replacement long passphrase"})
        self.assertEqual(reader.get("/").location, "/login")
        reader = self.login_as("reader", "the replacement long passphrase")
        self.post("/users", {"action": "deactivate", "user_id": str(reader_id)})
        self.assertEqual(reader.get("/").location, "/login")

    def test_password_change_revokes_other_sessions(self):
        self.setup_admin()
        other_session = self.login_as("admin")
        response = self.post("/password", {"current_password": self.password, "password": "another secure administrator phrase", "password_confirm": "another secure administrator phrase"})
        self.assertEqual(response.location, "/login")
        self.assertEqual(other_session.get("/").location, "/login")

    def test_logout_revokes_copied_cookie(self):
        self.setup_admin()
        copied_cookie = self.client.get_cookie("session")
        self.post("/logout", {})
        replay = self.app.test_client()
        replay.set_cookie("session", copied_cookie.value)
        self.assertEqual(replay.get("/").location, "/login")

    def test_session_expires_with_policy_timeout(self):
        self.setup_admin()
        with self.client.session_transaction() as session:
            session["last_seen"] = int(time.time()) - 1801
        self.assertEqual(self.client.get("/").location, "/login")

    def test_login_throttling_survives_restart(self):
        self.setup_admin()
        attacker = self.app.test_client()
        token = self.csrf(attacker)
        for _ in range(10):
            result = attacker.post("/login", data={"csrf_token": token, "username": "admin", "password": "incorrect"})
            self.assertEqual(result.status_code, 401)
        restarted = create_app(self.config)
        client = restarted.test_client()
        response = client.get("/login")
        token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()
        result = client.post("/login", data={"csrf_token": token, "username": "admin", "password": self.password})
        self.assertEqual(result.status_code, 429)

    def test_invalid_policy_saves_are_atomic(self):
        self.setup_admin()
        for field, bad_value in (("public_base_url", "http://pki.example.com"), ("public_base_url", "https://user:password@pki.example.com"),
                                 ("public_base_url", "https://pki.example.com/?x=1"), ("max_leaf_days", "826"),
                                 ("public_base_url", "https://pki.example.com/\N{LATIN SMALL LETTER U WITH DIAERESIS}"),
                                 ("session_minutes", "0"), ("listen_address", "pki.example.com"), ("https_port", "443")):
            response = self.post("/settings", self.settings_data(**{field: bad_value, "organization": "Should not persist"}))
            self.assertEqual(response.status_code, 400, (field, response.data))
            with self.app.app_context():
                self.assertEqual(get_setting("organization"), "Example Enterprise")

    def test_settings_and_audit_persist_across_restart(self):
        self.setup_admin()
        response = self.post("/settings", self.settings_data(allow_key_export="on", listen_address="0.0.0.0", https_port="9443"))
        self.assertEqual(response.status_code, 302)
        restarted = create_app(self.config)
        with restarted.app_context():
            self.assertTrue(get_setting("allow_key_export"))
            self.assertEqual(get_setting("https_port"), "9443")
            self.assertEqual(get_setting("listen_address"), "0.0.0.0")
            actions = [row[0] for row in get_db().execute("SELECT action FROM audit_events")]
            self.assertIn("installation.completed", actions)
            self.assertIn("settings.updated", actions)

    def tls_files(self, san=None, eku=None):
        private_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pki.example.com")])
        now = datetime.now(UTC)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private_key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                       .not_valid_after(now + timedelta(days=30)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                       .add_extension(x509.SubjectAlternativeName(san if san is not None else [x509.DNSName("pki.example.com")]), False))
        if eku is not None:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), False)
        certificate = builder.sign(private_key, hashes.SHA256())
        key_bytes = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return certificate.public_bytes(serialization.Encoding.PEM), key_bytes

    def test_https_upload_installs_matching_pair_atomically(self):
        self.setup_admin()
        certificate_bytes, private_key_bytes = self.tls_files()
        response = self.post("/settings", self.settings_data(tls_certificate=(io.BytesIO(certificate_bytes), "cert.pem"), tls_private_key=(io.BytesIO(private_key_bytes), "key.pem")))
        self.assertEqual(response.status_code, 302, response.data)
        target = Path(self.directory.name) / "server-tls" / "uploaded.pem"
        self.assertEqual(target.read_bytes(), private_key_bytes + certificate_bytes)
        original = target.read_bytes()
        _, wrong_key = self.tls_files()
        response = self.post("/settings", self.settings_data(tls_certificate=(io.BytesIO(certificate_bytes), "cert.pem"), tls_private_key=(io.BytesIO(wrong_key), "key.pem")))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(target.read_bytes(), original)

    def test_https_upload_rejects_client_only_purpose_or_unusable_san(self):
        self.setup_admin()
        for options in ({"eku": [ExtendedKeyUsageOID.CLIENT_AUTH]}, {"san": [x509.RFC822Name("admin@example.com")]}, {"san": []}):
            certificate, private_key = self.tls_files(**options)
            response = self.post("/settings", self.settings_data(tls_certificate=(io.BytesIO(certificate), "cert.pem"), tls_private_key=(io.BytesIO(private_key), "key.pem")))
            self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse((Path(self.directory.name) / "server-tls" / "uploaded.pem").exists())

    def test_https_upload_preflights_native_tls_and_rolls_back_policy(self):
        self.setup_admin()
        certificate, private_key = self.tls_files(eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak legacy chain")])
        now = datetime.now(UTC)
        weak_ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(weak_key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                   .sign(weak_key, hashes.SHA256()))
        response = self.post("/settings", self.settings_data(organization="Must not save",
            tls_certificate=(io.BytesIO(certificate + weak_ca.public_bytes(serialization.Encoding.PEM)), "chain.pem"),
            tls_private_key=(io.BytesIO(private_key), "key.pem")))
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse((Path(self.directory.name) / "server-tls" / "uploaded.pem").exists())
        with self.app.app_context():
            self.assertEqual(get_setting("organization"), "Example Enterprise")

    def test_runtime_secrets_are_independent_and_stable(self):
        first = self.app.config["KEY_ENCRYPTION_SECRET"]
        self.assertNotEqual(first, self.app.config["SECRET_KEY"])
        second = create_app(self.config)
        self.assertEqual(first, second.config["KEY_ENCRYPTION_SECRET"])
        self.assertEqual(self.app.config["SECRET_KEY"], second.config["SECRET_KEY"])

    def test_missing_or_corrupt_runtime_secret_fails_closed(self):
        target = Path(self.directory.name) / "runtime-secrets.json"
        target.write_text("not json", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            create_app(self.config)
        target.unlink()
        with self.assertRaises(RuntimeError):
            create_app(self.config)

    def test_wrong_persisted_encryption_secret_fails_at_startup(self):
        with self.app.app_context():
            encrypted = encrypt_private_key("existing private key material")
            get_db().execute("""INSERT INTO authorities
                (name, role, common_name, certificate_pem, private_key_pem, serial_number, not_before, not_after)
                VALUES ('Existing Root', 'root', 'Existing Root', 'certificate', ?, '1', '2026-01-01', '2030-01-01')""", (encrypted,))
            get_db().commit()
        target = Path(self.directory.name) / "runtime-secrets.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["KEY_ENCRYPTION_SECRET"] = "different but syntactically valid encryption secret"
        target.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "cannot decrypt"):
            create_app(self.config)

    def test_explicit_secret_conflict_fails_at_startup(self):
        with self.assertRaisesRegex(RuntimeError, "conflicts"):
            create_app({**self.config, "KEY_ENCRYPTION_SECRET": "incorrect override"})

    def test_existing_encryption_secret_migrates_without_changing_keys(self):
        with self.app.app_context():
            encrypted = encrypt_private_key("private key payload")
        # Minimal legacy schema is enough to verify migration before schema initialization.
        legacy_db = Path(self.directory.name) / "legacy.sqlite"
        with closing(sqlite3.connect(legacy_db)) as connection, connection:
            connection.execute("CREATE TABLE authorities (private_key_pem TEXT)")
            connection.execute("INSERT INTO authorities VALUES (?)", (encrypted,))
            connection.execute("INSERT INTO authorities VALUES ('')")
        legacy_dir = Path(self.directory.name) / "legacy-state"
        application = Flask("legacy")
        application.config.update(INSTANCE_PATH=str(legacy_dir), DATABASE=str(legacy_db), KEY_ENCRYPTION_SECRET=self.app.config["KEY_ENCRYPTION_SECRET"])
        configure_runtime(application)
        self.assertEqual(application.config["KEY_ENCRYPTION_SECRET"], self.app.config["KEY_ENCRYPTION_SECRET"])
        restored = json.loads((legacy_dir / "runtime-secrets.json").read_text())
        self.assertEqual(restored["KEY_ENCRYPTION_SECRET"], self.app.config["KEY_ENCRYPTION_SECRET"])

    def test_legacy_environment_is_imported_once_and_retired(self):
        directory = Path(self.directory.name) / "environment-migration"
        application = Flask("environment")
        application.config.update(INSTANCE_PATH=str(directory), DATABASE=str(directory / "new.sqlite"))
        with patch.dict("os.environ", {"PKIMASTER_SECRET_KEY": "old-session-secret", "PKIMASTER_KEY_ENCRYPTION_SECRET": "old-encryption-secret"}):
            configure_runtime(application)
        self.assertEqual(application.config["SECRET_KEY"], "old-session-secret")
        restarted = Flask("environment-restart")
        restarted.config.update(INSTANCE_PATH=str(directory), DATABASE=str(directory / "new.sqlite"))
        with patch.dict("os.environ", {"PKIMASTER_SECRET_KEY": "ignored", "PKIMASTER_KEY_ENCRYPTION_SECRET": "ignored"}):
            configure_runtime(restarted)
        self.assertEqual(restarted.config["KEY_ENCRYPTION_SECRET"], "old-encryption-secret")

    def test_wrong_legacy_secret_does_not_create_secret_file(self):
        with self.app.app_context():
            encrypted = encrypt_private_key("private key payload")
        legacy_db = Path(self.directory.name) / "legacy.sqlite"
        with closing(sqlite3.connect(legacy_db)) as connection, connection:
            connection.execute("CREATE TABLE authorities (private_key_pem TEXT)")
            connection.execute("INSERT INTO authorities VALUES (?)", (encrypted,))
        target = Path(self.directory.name) / "wrong-state"
        application = Flask("wrong")
        application.config.update(INSTANCE_PATH=str(target), DATABASE=str(legacy_db), KEY_ENCRYPTION_SECRET="incorrect")
        with self.assertRaises(RuntimeError):
            configure_runtime(application)
        self.assertFalse((target / "runtime-secrets.json").exists())


if __name__ == "__main__":
    unittest.main()
