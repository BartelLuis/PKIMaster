"""WebAuthn enrollment and password-plus-passkey sign-in integration."""
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
import re
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.webauthn import AttestedCredentialData

from app import create_app, get_db
from mfa import code_at_counter, decrypt_secret, time_counter
from mfa_helpers import complete_mfa
from passkeys import _options_response, _server


class PasskeyTests(unittest.TestCase):
    base_url = "https://localhost"
    password = "test-passphrase-123"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": str(Path(self.directory.name).resolve())})
        self.client = self.app.test_client()
        self._post(self.client, "/setup", {
            "username": "admin", "password": self.password, "password_confirm": self.password,
            "organization": "Passkey tests", "public_base_url": self.base_url,
        })
        complete_mfa(self.client, self.app)

    def _token(self, client, path="/"):
        response = client.get(path, base_url=self.base_url, follow_redirects=True)
        found = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(found, response.data)
        return found.group(1).decode()

    def _post(self, client, path, data):
        values = {"csrf_token": self._token(client), **data}
        return client.post(path, base_url=self.base_url, data=values, follow_redirects=True)

    def _totp(self):
        with self.app.app_context():
            user = get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone()
            secret = decrypt_secret(user["mfa_secret"])
            counter = max(time_counter(), user["mfa_last_counter"] + 1)
            return code_at_counter(secret, counter), counter

    def _credential(self):
        key = ec.generate_private_key(ec.SECP256R1())
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return AttestedCredentialData.from_ctap1(b"test-passkey-id", point)

    def test_registration_options_require_canonical_https_origin_and_uv(self):
        response = self._post(self.client, "/account/security/passkeys/register/begin", {})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.json["rp"]["id"], "localhost")
        self.assertEqual(response.json["authenticatorSelection"]["userVerification"], "required")
        self.assertEqual(response.json["authenticatorSelection"]["residentKey"], "required")
        with self.app.app_context():
            server = _server()
            self.assertTrue(server._verify(self.base_url))
            self.assertFalse(server._verify("https://attacker.example"))

    def test_binary_option_fields_are_encoded_for_json(self):
        options = {"publicKey": {
            "challenge": b"\x00\xff",
            "user": {"id": b"user-id"},
            "allowCredentials": [{"id": b"credential-id"}],
        }}
        with self.app.app_context():
            response = _options_response(options)
        self.assertEqual(response.json, {
            "challenge": "AP8",
            "user": {"id": "dXNlci1pZA"},
            "allowCredentials": [{"id": "Y3JlZGVudGlhbC1pZA"}],
        })

    def test_registration_stores_credential_only_after_fresh_totp(self):
        begin = self._post(self.client, "/account/security/passkeys/register/begin", {})
        self.assertEqual(begin.status_code, 200, begin.data)
        credential = self._credential()
        fake_server = SimpleNamespace(
            register_complete=lambda state, response: SimpleNamespace(credential_data=credential, counter=0))
        bad = self._post(self.client, "/account/security/passkeys/register/complete", {
            "credential_json": "{}", "label": "Laptop", "totp_code": "000000",
        })
        self.assertEqual(bad.status_code, 401)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM passkey_credentials").fetchone()[0], 0)

        code, counter = self._totp()
        with patch("mfa.time_counter", return_value=counter), patch("passkeys._server", return_value=fake_server):
            result = self._post(self.client, "/account/security/passkeys/register/complete", {
                "credential_json": "{}", "label": "Laptop", "totp_code": code,
            })
        self.assertEqual(result.status_code, 200, result.data)
        with self.app.app_context():
            row = get_db().execute("SELECT * FROM passkey_credentials").fetchone()
            self.assertEqual(row["label"], "Laptop")
            self.assertEqual(bytes(row["credential_id"]), credential.credential_id)
            self.assertEqual(AttestedCredentialData(bytes(row["credential_data"])).credential_id,
                             credential.credential_id)

    def test_passkey_is_offered_after_password_only_login_when_registered(self):
        credential = self._credential()
        with self.app.app_context():
            get_db().execute("""INSERT INTO passkey_credentials
                (credential_id,user_id,credential_data,sign_count,label,created_at)
                VALUES (?,1,?,0,'Phone',?)""",
                (credential.credential_id, bytes(credential), datetime.now(UTC).isoformat()))
            get_db().commit()
        client = self.app.test_client()
        token = self._token(client, "/login")
        logged_in = client.post("/login", base_url=self.base_url,
                                data={"csrf_token": token, "username": "admin", "password": self.password})
        self.assertEqual(logged_in.status_code, 302)
        challenge = client.get("/mfa/challenge", base_url=self.base_url)
        self.assertEqual(challenge.status_code, 200)
        self.assertIn(b"Use a passkey", challenge.data)
        begin = client.post("/mfa/passkeys/authenticate/begin", base_url=self.base_url,
                            data={"csrf_token": self._token(client, "/mfa/challenge")})
        self.assertEqual(begin.status_code, 200, begin.data)
        self.assertEqual(begin.json["rpId"], "localhost")
        self.assertEqual(begin.json["userVerification"], "required")

    def test_passkey_assertion_completes_second_factor_and_consumes_counter(self):
        credential = self._credential()
        with self.app.app_context():
            get_db().execute("""INSERT INTO passkey_credentials
                (credential_id,user_id,credential_data,sign_count,label,created_at)
                VALUES (?,1,?,0,'Phone',?)""",
                (credential.credential_id, bytes(credential), datetime.now(UTC).isoformat()))
            get_db().commit()
        client = self.app.test_client()
        token = self._token(client, "/login")
        client.post("/login", base_url=self.base_url,
                    data={"csrf_token": token, "username": "admin", "password": self.password})
        client.get("/mfa/challenge", base_url=self.base_url)
        client.post("/mfa/passkeys/authenticate/begin", base_url=self.base_url,
                    data={"csrf_token": self._token(client, "/mfa/challenge")})
        fake_server = SimpleNamespace(authenticate_complete=lambda state, credentials, response: credential)
        authenticator_data = SimpleNamespace(counter=1)
        response_data = SimpleNamespace(response=SimpleNamespace(authenticator_data=authenticator_data))
        with patch("passkeys._server", return_value=fake_server), patch(
                "passkeys.AuthenticationResponse.from_dict", return_value=response_data):
            result = client.post(
                "/mfa/passkeys/authenticate/complete", base_url=self.base_url,
                data={"csrf_token": self._token(client, "/mfa/challenge"), "credential_json": "{}"},
            )
        self.assertEqual(result.status_code, 200, result.data)
        self.assertEqual(result.json["redirect"], "/")
        self.assertEqual(client.get("/", base_url=self.base_url).status_code, 200)
        with self.app.app_context():
            self.assertEqual(get_db().execute(
                "SELECT sign_count FROM passkey_credentials"
            ).fetchone()[0], 1)

    def test_no_passkey_authentication_without_a_password_session(self):
        anonymous = self.app.test_client()
        page = anonymous.post("/mfa/passkeys/authenticate/begin", base_url=self.base_url,
                              data={"csrf_token": self._token(anonymous, "/login")})
        self.assertEqual(page.status_code, 302)
        self.assertEqual(page.location, "/login")


if __name__ == "__main__":
    unittest.main()
