"""TOTP reference vectors and authentication boundary regression tests."""
import base64
import re
import tempfile
import unittest
from unittest.mock import patch

from app import create_app, get_db
from mfa import code_at_counter, decrypt_secret, time_counter, totp
from mfa_helpers import complete_mfa


class TotpVectorTests(unittest.TestCase):
    def test_rfc6238_appendix_b(self):
        # Published reference vectors: https://www.rfc-editor.org/rfc/rfc6238#appendix-B
        times = (59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000)
        vectors = {
            "sha1": (b"12345678901234567890", ("94287082", "07081804", "14050471", "89005924", "69279037", "65353130")),
            "sha256": (b"12345678901234567890123456789012", ("46119246", "68084774", "67062674", "91819424", "90698825", "77737706")),
            "sha512": (b"1234567890123456789012345678901234567890123456789012345678901234", ("90693936", "25091201", "99943326", "93441116", "38618901", "47863826")),
        }
        for algorithm, (key, expected) in vectors.items():
            for at, code in zip(times, expected):
                with self.subTest(algorithm=algorithm, at=at):
                    self.assertEqual(totp(base64.b32encode(key).decode(), at, digits=8, algorithm=algorithm), code)


class MfaAccessTests(unittest.TestCase):
    password = "a sufficiently long test passphrase"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.config = {"TESTING": True, "INSTANCE_PATH": directory.name, "SESSION_COOKIE_SECURE": False}
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.post("/setup", {"username": "admin", "password": self.password,
            "password_confirm": self.password, "organization": "MFA test"})

    def token(self, client=None):
        response = (client or self.client).get("/", follow_redirects=True)
        return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()

    def post(self, path, values=None, client=None):
        client = client or self.client
        return client.post(path, data={"csrf_token": self.token(client), **(values or {})})

    def user(self):
        with self.app.app_context():
            return dict(get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone())

    def finish(self):
        return complete_mfa(self.client, self.app, base_url="http://localhost")

    def login(self):
        client = self.app.test_client()
        self.post("/login", {"username": "admin", "password": self.password}, client)
        return client

    def test_password_only_cannot_access_or_mutate_pki(self):
        for path in ("/", "/settings", "/users", "/audit", "/authorities/1/cert"):
            self.assertEqual(self.client.get(path).location, "/mfa/enroll")
        for path in ("/authorities", "/certificates", "/ca/activate", "/ca/requests/1/approve"):
            self.assertEqual(self.post(path).location, "/mfa/enroll")
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.finish()
        self.assertEqual(self.client.get("/settings").status_code, 200)

    def test_credentials_encrypted_and_not_in_cookie_or_audit(self):
        self.client.get("/mfa/enroll")
        user = self.user()
        with self.app.app_context():
            secret = decrypt_secret(user["mfa_pending_secret"])
        with self.client.session_transaction() as session:
            self.assertNotIn(secret, str(dict(session)))
        self.assertNotIn(secret, user["mfa_pending_secret"])
        self.finish()
        self.assertIsNone(self.user()["mfa_pending_secret"])
        self.assertNotIn(secret.encode(), self.client.get("/audit").data)
        self.assertNotIn(secret.encode(), self.client.get("/mfa/enroll", follow_redirects=True).data)

    def test_password_only_browser_cannot_claim_unenrolled_account(self):
        # Consume the setup ceremony's one permitted display, then simulate an
        # attacker arriving later with only the administrator password.
        enrollment_page = self.client.get("/mfa/enroll")
        user = self.user()
        with self.app.app_context():
            secret = decrypt_secret(user["mfa_pending_secret"])
        self.assertIn(secret.encode(), enrollment_page.data)
        attacker = self.login()
        page = attacker.get("/mfa/enroll")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(secret.encode(), page.data)
        invalid = self.post("/mfa/enroll", {"code": "000000"}, attacker)
        self.assertEqual(invalid.status_code, 401)
        self.assertNotIn(secret.encode(), invalid.data)

    def test_replayed_codes_fail_and_next_code_succeeds(self):
        self.finish()
        user = self.user()
        with self.app.app_context():
            secret = decrypt_secret(user["mfa_secret"])
        client = self.login()
        used = user["mfa_last_counter"]
        with patch("mfa.time_counter", return_value=used):
            replay = self.post("/mfa/challenge", {"code": code_at_counter(secret, used)}, client)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(client.get("/").location, "/mfa/challenge")
        with patch("mfa.time_counter", return_value=used + 1):
            success = self.post("/mfa/challenge", {"code": code_at_counter(secret, used + 1)}, client)
        self.assertEqual(success.location, "/")
        self.assertEqual(client.get("/").status_code, 200)

    def test_factor_throttle_survives_new_password_login_and_restart(self):
        self.finish()
        client = self.login()
        for _ in range(5):
            self.assertEqual(self.post("/mfa/challenge", {"code": "invalid"}, client).status_code, 401)
        self.app = create_app(self.config)
        client = self.login()
        self.assertEqual(self.post("/mfa/challenge", {"code": "invalid"}, client).status_code, 429)

    def test_old_sessions_and_expired_first_factor_are_rejected(self):
        with self.client.session_transaction() as session:
            session["first_factor_at"] = 0
        self.assertEqual(self.client.get("/").location, "/login")
        client = self.login()
        with client.session_transaction() as session:
            session.pop("password_authenticated")
        self.assertEqual(client.get("/").location, "/login")

    def test_csrf_and_password_reset_do_not_bypass_mfa(self):
        self.assertEqual(self.client.post("/mfa/enroll", data={"code": "123456"}).status_code, 403)
        self.finish()
        original = self.user()["mfa_secret"]
        self.post("/users", {"action": "reset_password", "user_id": "1", "password": self.password})
        client = self.login()
        self.assertEqual(client.get("/").location, "/mfa/challenge")
        self.assertEqual(self.user()["mfa_secret"], original)

    def test_password_only_sessions_cannot_change_password_or_revoke_verified_sessions(self):
        self.finish()
        original = self.user()
        incomplete = self.login()
        self.assertEqual(incomplete.get("/password").location, "/mfa/challenge")
        response = self.post("/password", {"current_password": self.password,
            "password": "replacement passphrase of sufficient length", "password_confirm": "replacement passphrase of sufficient length"}, incomplete)
        self.assertEqual(response.location, "/mfa/challenge")
        self.assertEqual(self.user()["password_hash"], original["password_hash"])
        self.post("/logout", client=incomplete)
        self.assertEqual(self.user()["session_version"], original["session_version"])
        self.assertEqual(self.client.get("/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
