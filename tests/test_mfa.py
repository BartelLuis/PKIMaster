"""TOTP reference vectors and authentication boundary regression tests."""
import base64
from html import unescape
import re
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from app import create_app, get_db
from mfa import code_at_counter, decrypt_secret, encrypt_secret, provisioning_uri, time_counter, totp
from mfa_helpers import complete_mfa


class TotpVectorTests(unittest.TestCase):
    def test_provisioning_uri_has_explicit_parameters_and_encoded_account_label(self):
        secret = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
        uri = provisioning_uri(secret, "alice@example.com", "R&D: M\u00fcnchen <ops> / CA")
        parsed = urlsplit(uri)
        self.assertEqual((parsed.scheme, parsed.netloc), ("otpauth", "totp"))
        issuer, account = unquote(parsed.path.lstrip("/")).split(":")
        self.assertEqual(account, "alice@example.com")
        self.assertIn("M\u00fcnchen <ops> / CA", issuer)
        self.assertEqual(parse_qs(parsed.query), {"secret": [secret], "issuer": [issuer],
            "algorithm": ["SHA256"], "digits": ["6"], "period": ["30"]})
        self.assertNotIn("=", secret)
        self.assertNotIn("<", uri)
        self.assertNotIn(" ", uri)
        self.assertEqual(parsed.fragment, "")

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


class MfaTestCase(unittest.TestCase):
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

    def enrollment_details(self, response):
        html = response.get_data(as_text=True)
        uri = re.search(r'<textarea\b[^>]*\bid="mfa-setup-uri"[^>]*>(.*?)</textarea>', html, re.DOTALL)
        qr = re.search(r'<div\b[^>]*\bclass="mfa-qr"[^>]*>\s*(<svg\b.*?</svg>)\s*</div>', html, re.DOTALL)
        self.assertIsNotNone(uri, "The full authenticator setup URI must be available for manual entry")
        self.assertIsNotNone(qr, "The enrollment page must contain its locally generated QR code")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        return unescape(uri.group(1)), qr.group(1)


class MfaAccessTests(MfaTestCase):
    def test_bitwarden_defaults_fail_but_provisioned_sha256_enrolls(self):
        # Use the RFC SHA-256 key and an independent implementation to exercise
        # the same parameters an authenticator receives from the setup URI.
        key = b"12345678901234567890123456789012"
        secret = base64.b32encode(key).decode().rstrip("=")
        at_time = 1234567890
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE users SET mfa_pending_secret = ?, mfa_pending_created = ? WHERE id = 1",
                       (encrypt_secret(secret), int(time.time())))
            db.commit()
        original = self.user()
        uri, qr = self.enrollment_details(self.client.get("/mfa/enroll"))
        parameters = parse_qs(urlsplit(uri).query)
        provisioned_key = base64.b32decode(parameters["secret"][0] + "=" * (-len(parameters["secret"][0]) % 8))
        algorithms = {"SHA1": hashes.SHA1, "SHA256": hashes.SHA256, "SHA512": hashes.SHA512}
        authenticator = TOTP(provisioned_key, int(parameters["digits"][0]),
                             algorithms[parameters["algorithm"][0]](), int(parameters["period"][0]))
        code = authenticator.generate(at_time).decode()
        default_code = TOTP(provisioned_key, 6, hashes.SHA1(), 30).generate(at_time).decode()
        self.assertEqual(default_code, "012961")
        self.assertEqual(code, "819424")
        with patch("mfa.time_counter", return_value=at_time // 30):
            rejected = self.post("/mfa/enroll", {"code": default_code})
            self.assertEqual(rejected.status_code, 401)
            self.assertRegex(rejected.data, rb'<li class="flash-error">\s*<svg\b[^>]*>[\s\S]*?</svg><span role="alert">')
            self.assertIn(b"SHA-256", rejected.data)
            self.assertEqual(self.enrollment_details(rejected), (uri, qr))
            pending = self.user()
            self.assertEqual(pending["mfa_pending_secret"], original["mfa_pending_secret"])
            self.assertEqual(pending["mfa_pending_created"], original["mfa_pending_created"])
            self.assertIsNone(pending["mfa_secret"])
            self.assertEqual(pending["mfa_last_counter"], -1)
            accepted = self.post("/mfa/enroll", {"code": code})
        self.assertEqual(accepted.location, "/")
        enrolled = self.user()
        self.assertEqual(enrolled["mfa_secret"], original["mfa_pending_secret"])
        self.assertIsNone(enrolled["mfa_pending_secret"])
        self.assertEqual(enrolled["mfa_last_counter"], at_time // 30)
        self.assertRegex(self.client.get("/").data, rb'<li class="flash-success">\s*<svg\b[^>]*>[\s\S]*?</svg><span role="status">')

    def test_enrollment_details_are_hidden_without_first_factor_and_after_activation(self):
        uri, _ = self.enrollment_details(self.client.get("/mfa/enroll"))
        secret = parse_qs(urlsplit(uri).query)["secret"][0]
        anonymous = self.app.test_client()
        for path in ("/mfa/enroll", "/mfa/challenge"):
            with self.subTest(phase="anonymous", path=path):
                response = anonymous.get(path)
                self.assertEqual(response.location, "/login")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertNotIn(secret.encode(), response.data)
                self.assertNotIn(b"otpauth://", response.data)
        self.finish()
        incomplete = self.login()
        for client, phase in ((self.client, "verified"), (incomplete, "challenge")):
            for path in ("/mfa/enroll", "/mfa/challenge"):
                with self.subTest(phase=phase, path=path):
                    response = client.get(path, follow_redirects=True)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertNotIn(secret.encode(), response.data)
                    self.assertNotIn(b"otpauth://", response.data)
                    self.assertNotIn(b'class="mfa-qr"', response.data)

    def test_expired_enrollment_replaces_qr_and_uri(self):
        page = self.client.get("/mfa/enroll")
        old_uri, old_qr = self.enrollment_details(page)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE users SET mfa_pending_created = ? WHERE id = 1", (int(time.time()) - 600,))
            db.commit()
        # Submit the stale page directly; the post helper would first GET a new enrollment.
        rejected = self.client.post("/mfa/enroll", data={"csrf_token": token, "code": "123456"})
        self.assertEqual(rejected.location, "/mfa/enroll")
        refreshed = self.client.get(rejected.location)
        new_uri, new_qr = self.enrollment_details(refreshed)
        self.assertRegex(refreshed.data, rb'<li class="flash-warning">\s*<svg\b[^>]*>[\s\S]*?</svg><span role="alert">')
        self.assertNotEqual(new_uri, old_uri)
        self.assertNotEqual(new_qr, old_qr)
        self.assertNotIn(parse_qs(urlsplit(old_uri).query)["secret"][0].encode(), refreshed.data)
        self.assertIsNone(self.user()["mfa_secret"])
        self.assertEqual(self.user()["mfa_last_counter"], -1)

    def test_enrollment_escapes_organization_and_handles_long_unicode_names(self):
        for organization in ('R&D: </textarea><script>alert("x")</script>', "\U0001f512" * 200):
            with self.subTest(organization=organization[:40]):
                with self.app.app_context():
                    db = get_db()
                    db.execute("UPDATE settings SET value = ? WHERE key = 'organization'", (organization,))
                    db.commit()
                response = self.client.get("/mfa/enroll")
                self.assertEqual(response.status_code, 200)
                uri, qr = self.enrollment_details(response)
                parameters = parse_qs(urlsplit(uri).query)
                issuer, account = unquote(urlsplit(uri).path.lstrip("/")).split(":")
                self.assertEqual(parameters["issuer"], [issuer])
                self.assertEqual(account, "admin")
                self.assertNotIn('<script>alert("x")</script>', response.get_data(as_text=True))
                self.assertNotIn("<script", qr)
                self.assertNotIn("otpauth://", qr)

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
