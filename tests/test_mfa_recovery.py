"""Account recovery, factor replacement and second-factor authorization."""
from concurrent.futures import ThreadPoolExecutor
import re
import time
from unittest.mock import patch

from app import get_db
from mfa import RECOVERY_CODE_COUNT, code_at_counter, decrypt_secret, time_counter
from test_mfa import MfaTestCase


class MfaRecoveryTests(MfaTestCase):
    def setUp(self):
        super().setUp()
        self.finish()

    def fresh_code(self):
        user = self.user()
        with self.app.app_context():
            secret = decrypt_secret(user["mfa_secret"])
        counter = max(time_counter(), user["mfa_last_counter"] + 1)
        return counter, code_at_counter(secret, counter)

    def account_action(self, action, client=None):
        counter, code = self.fresh_code()
        with patch("mfa.time_counter", return_value=counter):
            return self.post("/account/security", {"action": action, "code": code}, client)

    def codes_from(self, response):
        self.assertEqual(response.status_code, 200, response.data.decode())
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        match = re.search(rb'<textarea\b[^>]*id="recovery-codes"[^>]*>(.*?)</textarea>', response.data, re.DOTALL)
        self.assertIsNotNone(match)
        codes = match.group(1).decode().splitlines()
        self.assertEqual(len(codes), RECOVERY_CODE_COUNT)
        self.assertEqual(len(set(codes)), RECOVERY_CODE_COUNT)
        for code in codes:
            self.assertRegex(code, r"^[A-F0-9]{8}(-[A-F0-9]{8}){3}$")
        return codes

    def generate(self):
        return self.codes_from(self.account_action("generate_recovery"))

    def complete_replacement(self, client):
        page = client.get("/mfa/replace")
        self.assertEqual(page.status_code, 200)
        self.enrollment_details(page)
        with self.app.app_context():
            user = get_db().execute("SELECT * FROM users WHERE id = 1").fetchone()
            secret = decrypt_secret(user["mfa_pending_secret"])
        counter = time_counter()
        with patch("mfa.time_counter", return_value=counter):
            return self.post("/mfa/replace", {"code": code_at_counter(secret, counter)}, client)

    def test_generation_requires_fresh_factor_and_recovery_codes_are_shown_once(self):
        original = self.user()
        with self.app.app_context():
            used_code = code_at_counter(decrypt_secret(original["mfa_secret"]), original["mfa_last_counter"])
        with patch("mfa.time_counter", return_value=original["mfa_last_counter"]):
            refused = self.post("/account/security", {"action": "generate_recovery", "code": used_code})
        self.assertEqual(refused.status_code, 401)
        self.assertIn(b"flash-error", refused.data)
        codes = self.generate()
        self.assertEqual(self.user()["session_version"], original["session_version"] + 1)
        with self.app.app_context():
            db = get_db()
            rows = db.execute("SELECT * FROM mfa_recovery_codes").fetchall()
            audit = str([dict(row) for row in db.execute("SELECT * FROM audit_events")])
        self.assertEqual(len(rows), RECOVERY_CODE_COUNT)
        self.assertTrue(all(row["used_at"] is None and len(row["digest"]) == 64 for row in rows))
        with self.client.session_transaction() as session:
            cookie_values = str(dict(session))
        for code in codes:
            for stored in (str([dict(row) for row in rows]), audit, cookie_values,
                           self.client.get("/account/security").data.decode(), self.client.get("/").data.decode()):
                self.assertNotIn(code, stored)
                self.assertNotIn(code.replace("-", ""), stored)
        self.assertIn(b"10</strong> unused", self.client.get("/account/security").data)

    def test_recovery_requires_first_factor_and_cannot_unlock_pki_before_reenrollment(self):
        codes = self.generate()
        original = self.user()
        anonymous = self.app.test_client()
        for path in ("/mfa/recover", "/mfa/replace", "/account/security"):
            self.assertEqual(anonymous.get(path).location, "/login")
            self.assertEqual(anonymous.post(path, data={"recovery_code": codes[0]}).location, "/login")
        client = self.login()
        used = self.post("/mfa/recover", {"recovery_code": codes[0].lower().replace("-", " ")}, client)
        self.assertEqual(used.location, "/mfa/replace")
        self.assertEqual(self.user()["mfa_secret"], original["mfa_secret"])
        self.assertEqual(self.client.get("/").location, "/login")
        self.assertEqual(client.get("/").location, "/mfa/challenge")
        self.assertEqual(client.get("/mfa/challenge").location, "/mfa/replace")
        self.assertEqual(self.post("/certificates", {"common_name": "unavailable"}, client).location, "/mfa/challenge")
        self.assertEqual(client.get("/account/security").location, "/mfa/challenge")
        with client.session_transaction() as session:
            self.assertIs(session["mfa_verified"], False)
        new_codes = self.codes_from(self.complete_replacement(client))
        self.assertNotEqual(new_codes, codes)
        self.assertNotEqual(self.user()["mfa_secret"], original["mfa_secret"])
        self.assertIsNone(self.user()["mfa_pending_secret"])
        self.assertIsNone(self.user()["mfa_pending_token_hash"])
        self.assertEqual(client.get("/").status_code, 200)
        another = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": codes[1]}, another).status_code, 401)

    def test_recovery_code_replay_rejected_even_after_new_first_factor_login(self):
        code = self.generate()[0]
        client = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": code}, client).location, "/mfa/replace")
        other = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": code}, other).status_code, 401)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM mfa_recovery_codes WHERE used_at IS NOT NULL").fetchone()[0], 1)

    def test_concurrent_recovery_consumes_code_and_audits_once(self):
        code = self.generate()[0]
        clients = [self.login(), self.login()]
        tokens = [self.token(client) for client in clients]
        def attempt(index):
            return clients[index].post("/mfa/recover", data={"csrf_token": tokens[index], "recovery_code": code})
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(attempt, (0, 1)))
        self.assertEqual(sum(response.location == "/mfa/replace" for response in responses), 1)
        self.assertTrue(all(response.status_code in {302, 401} for response in responses))
        with self.app.app_context():
            db = get_db()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM mfa_recovery_codes WHERE used_at IS NOT NULL").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_events WHERE action='user.mfa_recovery_started'").fetchone()[0], 1)

    def test_replacement_is_bound_to_browser_and_old_factor_remains_until_confirmation(self):
        codes = self.generate()
        original = self.user()
        self.assertEqual(self.account_action("replace").location, "/mfa/replace")
        pending = self.user()
        self.assertEqual(pending["mfa_secret"], original["mfa_secret"])
        self.assertTrue(pending["mfa_pending_token_hash"])
        other = self.login()
        refused = other.get("/mfa/replace")
        self.assertEqual(refused.location, "/mfa/recover")
        self.assertNotIn(b"otpauth://", refused.data)
        # The currently active factor still signs in while the replacement is pending.
        from mfa_helpers import complete_mfa
        complete_mfa(other, self.app, base_url="http://localhost")
        self.assertEqual(other.get("/mfa/replace").location, "/account/security")
        self.codes_from(self.complete_replacement(self.client))
        self.assertEqual(other.get("/").location, "/login")
        self.assertNotEqual(self.user()["mfa_secret"], original["mfa_secret"])
        fresh = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": codes[0]}, fresh).status_code, 401)

    def test_replacement_cancellation_keeps_original_authenticator(self):
        original = self.user()["mfa_secret"]
        self.account_action("replace")
        response = self.post("/mfa/replace", {"action": "cancel"})
        self.assertEqual(response.location, "/account/security")
        self.assertEqual(self.user()["mfa_secret"], original)
        self.assertIsNone(self.user()["mfa_pending_secret"])
        self.assertEqual(self.client.get("/mfa/replace").location, "/account/security")

    def test_recovery_cancellation_consumes_code_but_preserves_original_authenticator(self):
        code = self.generate()[0]
        original = self.user()["mfa_secret"]
        client = self.login()
        self.post("/mfa/recover", {"recovery_code": code}, client)
        cancelled = self.post("/mfa/replace", {"action": "cancel"}, client)
        self.assertEqual(cancelled.location, "/login")
        self.assertEqual(self.user()["mfa_secret"], original)
        self.assertIsNone(self.user()["mfa_pending_secret"])
        client = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": code}, client).status_code, 401)

    def test_expired_replacement_does_not_expose_secret_or_change_factor(self):
        original = self.user()["mfa_secret"]
        self.account_action("replace")
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE users SET mfa_pending_created = ? WHERE id=1", (int(time.time()) - 600,))
            db.commit()
        expired = self.client.get("/mfa/replace")
        self.assertEqual(expired.location, "/account/security")
        self.assertNotIn(b"otpauth://", expired.data)
        self.assertEqual(self.user()["mfa_secret"], original)

    def test_generation_invalidates_previous_codes_and_other_sessions(self):
        first = self.generate()
        other = self.login()
        from mfa_helpers import complete_mfa
        complete_mfa(other, self.app, base_url="http://localhost")
        second = self.generate()
        self.assertNotEqual(first, second)
        self.assertEqual(other.get("/").location, "/login")
        client = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": first[0]}, client).status_code, 401)
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": second[0]}, client).location, "/mfa/replace")

    def test_recovery_and_totp_share_persistent_throttle(self):
        code = self.generate()[0]
        client = self.login()
        for index in range(5):
            endpoint = "/mfa/recover" if index % 2 else "/mfa/challenge"
            self.assertEqual(self.post(endpoint, {"code": "invalid", "recovery_code": "invalid"}, client).status_code, 401)
        response = self.post("/mfa/recover", {"recovery_code": code}, client)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "900")
        from app import create_app
        self.app = create_app(self.config)
        client = self.login()
        self.assertEqual(self.post("/mfa/recover", {"recovery_code": code}, client).status_code, 429)

    def test_mutations_require_csrf_and_account_access_requires_full_mfa(self):
        codes = self.generate()
        incomplete = self.login()
        self.assertEqual(incomplete.get("/account/security").location, "/mfa/challenge")
        self.assertEqual(self.post("/account/security", {"action": "replace", "code": "123456"}, incomplete).location, "/mfa/challenge")
        for path, client, values in (("/account/security", self.client, {"action": "generate_recovery", "code": "123456"}),
                                     ("/mfa/recover", incomplete, {"recovery_code": codes[0]}),
                                     ("/mfa/replace", incomplete, {"code": "123456"})):
            with self.subTest(path=path):
                self.assertEqual(client.post(path, data=values).status_code, 403)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM mfa_recovery_codes WHERE used_at IS NOT NULL").fetchone()[0], 0)

    def test_operator_and_auditor_can_manage_own_recovery(self):
        for role in ("operator", "auditor"):
            with self.subTest(role=role):
                with self.app.app_context():
                    db = get_db()
                    db.execute("UPDATE users SET role=? WHERE id=1", (role,))
                    db.commit()
                self.assertEqual(self.client.get("/account/security").status_code, 200)
                self.generate()
                self.assertEqual(self.client.get("/users").status_code, 403)
