"""Identity trust boundaries: provisioned subjects, browser binding, TLS and MFA."""
import base64
import hashlib
import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app import create_app, get_db
from identity import DEFAULTS, _decrypt, _encrypt, _request_json, _verify_id_token, config, ldap_authenticate
from mfa_helpers import complete_mfa


class IdentityTests(unittest.TestCase):
    password = "a long administrator passphrase"
    base = "https://localhost"
    issuer = "https://identity.example"
    metadata = {"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "code_challenge_methods_supported": ["S256"]}

    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key())) | {"kid": "trusted", "alg": "RS256", "use": "sig"}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app_config = {"TESTING": True, "INSTANCE_PATH": self.directory.name,
                           "DATABASE": str(Path(self.directory.name) / "pki.sqlite"), "SESSION_COOKIE_SECURE": True}
        self.app = create_app(self.app_config)
        self.client = self.app.test_client()
        self.post(self.client, "/setup", username="admin", password=self.password, password_confirm=self.password, organization="Example")
        complete_mfa(self.client, self.app)

    def csrf(self, client, path="/login"):
        page = client.get(path, base_url=self.base, follow_redirects=True)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(match, page.data)
        return match[1].decode()

    def post(self, client, path, **data):
        return client.post(path, base_url=self.base, data={"csrf_token": self.csrf(client), **data})

    def provision(self, source="oidc", subject="subject-123", username="external", role="operator"):
        result = self.post(self.client, "/users", username=username, role=role, auth_source=source,
                           external_issuer=self.issuer if source == "oidc" else "ldap://directory.example", external_subject=subject)
        self.assertEqual(result.status_code, 302, result.data)

    def configure(self, mode="oidc", **updates):
        """Fixture storage bypasses network discovery, but authentication routes stay real."""
        with self.app.app_context():
            value = DEFAULTS | {"mode": mode, "oidc_issuer": self.issuer, "oidc_client_id": "pki",
                               "oidc_authorization_origin": self.issuer,
                               "oidc_redirect_uri": self.base + "/auth/oidc/callback", "oidc_client_secret": _encrypt("oidc secret"),
                               "ldap_url": "ldap://directory.example", "ldap_base_dn": "dc=example", "ldap_bind_dn": "cn=service,dc=example",
                               "ldap_bind_password": _encrypt("ldap secret"), "revision": "test-config"} | updates
            db = get_db()
            db.execute("INSERT INTO identity_settings VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (json.dumps(value),))
            db.commit()
        return value

    def start(self, client):
        with patch("identity._request_json", return_value=self.metadata):
            response = self.post(client, "/auth/oidc/start")
        self.assertEqual(response.status_code, 302, response.data)
        query = parse_qs(urlsplit(response.location).query)
        return query

    def token(self, expected_nonce, **updates):
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": "pki", "sub": "subject-123", "nonce": expected_nonce, "iat": now, "exp": now + 300} | updates
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "trusted"})

    def finish(self, client, query, **claims):
        encoded = self.token(query["nonce"][0], **claims)
        with patch("identity._request_json", side_effect=[{"id_token": encoded, "access_token": "access"}, {"keys": [self.jwk]}]) as network:
            response = client.get("/auth/oidc/callback", query_string={"state": query["state"][0], "code": "code"}, base_url=self.base)
        return response, network

    def test_oidc_flow_stores_verifier_server_side_and_requires_mfa(self):
        self.provision()
        self.configure()
        browser = self.app.test_client()
        query = self.start(browser)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        with self.app.app_context():
            row = get_db().execute("SELECT * FROM oidc_flows").fetchone()
            self.assertNotIn(query["nonce"][0], row["payload"])
            flow = json.loads(_decrypt(row["payload"]))
        expected = base64.urlsafe_b64encode(hashlib.sha256(flow["verifier"].encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(query["code_challenge"], [expected])
        with browser.session_transaction() as cookie:
            self.assertNotIn("nonce", cookie)
            self.assertNotIn("verifier", cookie)
        response, network = self.finish(browser, query)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'href="/mfa/enroll"', response.data)
        self.assertIn("SameSite=Strict", response.headers.getlist("Set-Cookie")[-1])
        self.assertEqual(network.call_args_list[0].kwargs["data"]["code_verifier"], flow["verifier"])
        self.assertEqual(browser.get("/", base_url=self.base).location, "/mfa/enroll")
        complete_mfa(browser, self.app, "external")
        self.assertEqual(browser.get("/", base_url=self.base).status_code, 200)
        self.assertEqual(browser.get("/settings/identity", base_url=self.base).status_code, 403)

    def test_oidc_state_is_bound_to_browser_and_single_use(self):
        self.provision()
        self.configure()
        browser = self.app.test_client()
        query = self.start(browser)
        other = self.app.test_client()
        self.assertEqual(other.get("/auth/oidc/callback", query_string={"state": query["state"][0], "code": "stolen"}, base_url=self.base).status_code, 400)
        self.assertEqual(self.finish(browser, query)[0].status_code, 200)
        self.assertEqual(browser.get("/auth/oidc/callback", query_string={"state": query["state"][0], "code": "replay"}, base_url=self.base).location, "/mfa/enroll")
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM oidc_flows").fetchone()[0], 0)

    def test_oidc_never_links_by_email_or_grants_provider_roles(self):
        self.configure()
        browser = self.app.test_client()
        query = self.start(browser)
        response, _ = self.finish(browser, query, email="admin", roles=["admin"], sub="unprovisioned")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(browser.get("/", base_url=self.base).location, "/login")
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_oidc_rejects_nonce_issuer_audience_expiration_and_azp(self):
        self.provision()
        self.configure()
        invalid = [{"nonce": "wrong"}, {"iss": "https://attacker.example"}, {"aud": "other"},
                   {"exp": int(time.time()) - 300}, {"iat": int(time.time()) - 1000},
                   {"aud": ["pki", "other"]}, {"azp": "other"}, {"at_hash": "incorrect"}]
        for claims in invalid:
            with self.subTest(claims=claims):
                browser = self.app.test_client()
                query = self.start(browser)
                response, _ = self.finish(browser, query, **claims)
                self.assertEqual(response.status_code, 401)

    def test_jwt_rejects_none_symmetric_and_embedded_keys(self):
        value = DEFAULTS | {"oidc_issuer": self.issuer, "oidc_client_id": "pki"}
        claims = {"iss": self.issuer, "aud": "pki", "sub": "s", "nonce": "n", "iat": int(time.time()), "exp": int(time.time()) + 300}
        tokens = [jwt.encode(claims, "", algorithm="none"), jwt.encode(claims, "a" * 32, algorithm="HS256"),
                  jwt.encode(claims, self.key, algorithm="RS256", headers={"jwk": self.jwk, "kid": "trusted"})]
        for encoded in tokens:
            with self.assertRaises(ValueError):
                _verify_id_token({"id_token": encoded}, {"keys": [self.jwk]}, value, {"nonce": "n"}, int(time.time()))
        with self.assertRaises(ValueError):
            _verify_id_token({"id_token": self.token("n")}, {"keys": []}, value, {"nonce": "n"}, int(time.time()))

    def test_oidc_enforces_provider_key_strength_and_curve_algorithm(self):
        value = DEFAULTS | {"oidc_issuer": self.issuer, "oidc_client_id": "pki"}
        claims = {"iss": self.issuer, "aud": "pki", "sub": "s", "nonce": "n", "iat": int(time.time()), "exp": int(time.time()) + 300}
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        weak_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak.public_key()))
        encoded = jwt.encode(claims, weak, algorithm="RS256")
        with self.assertRaises(ValueError):
            _verify_id_token({"id_token": encoded}, {"keys": [weak_jwk]}, value, {"nonce": "n"}, int(time.time()))
        curve_key = ec.generate_private_key(ec.SECP256R1())
        curve_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(curve_key.public_key()))
        encoded = jwt.encode(claims, curve_key, algorithm="ES256")
        result = _verify_id_token({"id_token": encoded}, {"keys": [curve_jwk]}, value, {"nonce": "n"}, int(time.time()))
        self.assertEqual(result["sub"], "s")
        # A valid but wrong curve must not be accepted merely because the library can use it.
        wrong = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP384R1()).public_key()))
        with self.assertRaises(ValueError):
            _verify_id_token({"id_token": encoded}, {"keys": [wrong]}, value, {"nonce": "n"}, int(time.time()))

    def test_oidc_rejects_ambiguous_json_fields(self):
        value = DEFAULTS | {"oidc_issuer": self.issuer, "oidc_client_id": "pki"}
        encoded = self.token("n")
        parts = encoded.split(".")
        parts[0] = base64.urlsafe_b64encode(b'{"alg":"RS256","alg":"RS256","kid":"trusted"}').rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            _verify_id_token({"id_token": ".".join(parts)}, {"keys": [self.jwk]}, value, {"nonce": "n"}, int(time.time()))

    def test_provider_ciphertext_is_verified_before_startup(self):
        self.configure()
        with self.app.app_context():
            value = json.loads(get_db().execute("SELECT payload FROM identity_settings").fetchone()[0])
            value["oidc_client_secret"] = "corrupted ciphertext"
            get_db().execute("UPDATE identity_settings SET payload = ?", (json.dumps(value),))
            get_db().commit()
        with self.assertRaisesRegex(RuntimeError, "cannot decrypt"):
            create_app(self.app_config)

    def test_oidc_flow_expiry_and_configuration_change(self):
        self.configure()
        browser = self.app.test_client()
        query = self.start(browser)
        with self.app.app_context():
            get_db().execute("UPDATE oidc_flows SET created_at = ?", (int(time.time()) - 601,))
            get_db().commit()
        self.assertEqual(browser.get("/auth/oidc/callback", query_string={"state": query["state"][0], "code": "c"}, base_url=self.base).status_code, 400)
        query = self.start(browser)
        self.configure(revision="different")
        with patch("identity._request_json") as network:
            result = browser.get("/auth/oidc/callback", query_string={"state": query["state"][0], "code": "c"}, base_url=self.base)
        self.assertEqual(result.status_code, 401)
        network.assert_not_called()

    def test_oidc_start_requires_csrf_and_rejects_insecure_discovery(self):
        self.configure()
        browser = self.app.test_client()
        self.assertEqual(browser.post("/auth/oidc/start", base_url=self.base).status_code, 403)
        with patch("identity._request_json", return_value=self.metadata | {"jwks_uri": "http://identity.example/keys"}):
            self.assertEqual(self.post(browser, "/auth/oidc/start").status_code, 503)

    def test_login_csp_uses_only_pinned_provider_origin_without_network(self):
        self.configure()
        browser = self.app.test_client()
        with patch("identity._request_json") as network:
            login = browser.get("/login", base_url=self.base)
        network.assert_not_called()
        self.assertIn("form-action 'self' https://identity.example;", login.headers["Content-Security-Policy"])
        settings = self.client.get("/settings/identity", base_url=self.base)
        self.assertIn("form-action 'self';", settings.headers["Content-Security-Policy"])
        self.assertNotIn(self.issuer, settings.headers["Content-Security-Policy"])
        self.configure("local")
        login = browser.get("/login", base_url=self.base)
        self.assertIn("form-action 'self';", login.headers["Content-Security-Policy"])

    def test_provider_origin_drift_requires_admin_settings_save(self):
        self.configure()
        browser = self.app.test_client()
        with patch("identity._request_json", return_value=self.metadata | {"authorization_endpoint": "https://new-provider.example/authorize"}):
            self.assertEqual(self.post(browser, "/auth/oidc/start").status_code, 503)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM oidc_flows").fetchone()[0], 0)

    def test_local_fallback_is_explicit_and_admin_only(self):
        self.post(self.client, "/users", username="reader", password=self.password, role="auditor")
        self.configure()
        reader = self.app.test_client()
        self.assertEqual(self.post(reader, "/login", username="reader", password=self.password).status_code, 401)
        admin = self.app.test_client()
        self.assertEqual(self.post(admin, "/login", username="admin", password=self.password).location, "/mfa/challenge")
        self.configure(allow_local_breakglass=False)
        other = self.app.test_client()
        self.assertEqual(self.post(other, "/login", username="admin", password=self.password).status_code, 401)

    def test_ldap_login_requires_bound_directory_and_app_mfa(self):
        self.provision("ldap", "uid=external,dc=example")
        self.configure("ldap")
        browser = self.app.test_client()
        with patch("identity.ldap_authenticate", return_value=True):
            result = self.post(browser, "/login", username="external", password="directory-password")
        self.assertEqual(result.location, "/mfa/enroll")
        self.assertEqual(browser.get("/", base_url=self.base).location, "/mfa/enroll")
        self.configure("ldap", ldap_url="ldaps://different.example")
        other = self.app.test_client()
        with patch("identity.ldap_authenticate", return_value=True) as authenticate:
            result = self.post(other, "/login", username="external", password="directory-password")
        self.assertEqual(result.status_code, 401)
        authenticate.assert_not_called()

    def test_ldap_empty_password_and_persistent_throttle(self):
        self.provision("ldap", "uid=external,dc=example")
        self.configure("ldap")
        browser = self.app.test_client()
        with patch("identity.ldap_authenticate", return_value=False) as authenticate:
            self.assertEqual(self.post(browser, "/login", username="external", password="").status_code, 401)
            authenticate.assert_not_called()
            for _ in range(9):
                self.assertEqual(self.post(browser, "/login", username="external", password="wrong").status_code, 401)
            replacement = create_app(self.app_config).test_client()
            self.assertEqual(self.post(replacement, "/login", username="external", password="wrong").status_code, 429)

    def test_ldap_starttls_precedes_binds_no_referrals_and_escaped_search(self):
        value = DEFAULTS | {"ldap_url": "ldap://directory.example", "ldap_base_dn": "dc=example", "ldap_bind_dn": "cn=svc", "ldap_bind_password": "service-secret"}
        search, bound = MagicMock(), MagicMock()
        search.start_tls.return_value = bound.start_tls.return_value = True
        search.bind.return_value = bound.bind.return_value = True
        search.entries = [SimpleNamespace(entry_dn="uid=person,dc=example")]
        with patch("identity.ldap3.Connection", side_effect=[search, bound]) as connection, patch("identity.ldap3.Server") as server:
            self.assertTrue(ldap_authenticate(value, {"external_subject": "uid=person,dc=example"}, "person*)(uid=*)", "password"))
        self.assertEqual(connection.call_args_list[0].kwargs["auto_referrals"], False)
        self.assertEqual(server.call_args.kwargs["tls"].validate, 2)
        self.assertEqual([call[0] for call in search.mock_calls[:3]], ["open", "start_tls", "bind"])
        self.assertEqual([call[0] for call in bound.mock_calls[:3]], ["open", "start_tls", "bind"])
        self.assertIn(r"\2a\29\28uid=\2a\29", search.search.call_args.args[1])

    def test_ldap_rejects_tls_failure_ambiguous_and_mismatched_dn(self):
        value = DEFAULTS | {"ldap_url": "ldap://directory.example", "ldap_base_dn": "dc=example", "ldap_bind_dn": "cn=svc", "ldap_bind_password": "service-secret"}
        failed = MagicMock()
        failed.start_tls.return_value = False
        with patch("identity.ldap3.Connection", return_value=failed), self.assertRaises(ValueError):
            ldap_authenticate(value, {"external_subject": "uid=person"}, "person", "password")
        failed.bind.assert_not_called()
        for entries in ([], [SimpleNamespace(entry_dn="uid=wrong")], [SimpleNamespace(entry_dn="uid=person")] * 2):
            search = MagicMock()
            search.entries = entries
            with patch("identity.ldap3.Connection", return_value=search) as connection:
                self.assertFalse(ldap_authenticate(value, {"external_subject": "uid=person"}, "person", "password"))
            self.assertEqual(connection.call_count, 1)

    def test_web_settings_encrypt_secrets_revoke_sessions_and_prevent_lockout(self):
        with patch("identity._request_json", return_value=self.metadata):
            result = self.post(self.client, "/settings/identity", mode="oidc", oidc_issuer=self.issuer, oidc_client_id="pki",
                               oidc_redirect_uri=self.base + "/auth/oidc/callback", oidc_client_secret="provider top secret")
        self.assertEqual(result.status_code, 400)
        with patch("identity._request_json", return_value=self.metadata):
            result = self.post(self.client, "/settings/identity", mode="oidc", allow_local_breakglass="on", oidc_issuer=self.issuer,
                               oidc_client_id="pki", oidc_redirect_uri=self.base + "/auth/oidc/callback", oidc_client_secret="provider top secret")
        self.assertEqual(result.status_code, 302)
        self.assertEqual(self.client.get("/", base_url=self.base).location, "/login")
        with self.app.app_context():
            raw = get_db().execute("SELECT payload FROM identity_settings").fetchone()[0]
            self.assertNotIn("provider top secret", raw)
            self.assertEqual(config(secrets_visible=True)["oidc_client_secret"], "provider top secret")
            self.assertEqual(config()["oidc_client_secret"], "")
            self.assertEqual(config()["oidc_authorization_origin"], self.issuer)

    def test_external_account_has_no_local_password_reset(self):
        self.provision()
        with self.app.app_context():
            user_id = get_db().execute("SELECT id FROM users WHERE username = 'external'").fetchone()[0]
        result = self.post(self.client, "/users", action="reset_password", user_id=user_id, password=self.password)
        self.assertEqual(result.status_code, 400)

    def test_https_client_has_no_redirects_proxy_or_unbounded_reads(self):
        client = MagicMock()
        response = MagicMock(status_code=302)
        client.request.return_value.__enter__.return_value = response
        with patch("identity.requests.Session") as factory:
            factory.return_value.__enter__.return_value = client
            with self.assertRaises(ValueError):
                _request_json("GET", "https://identity.example/keys")
            self.assertFalse(client.trust_env)
            self.assertFalse(client.request.call_args.kwargs["allow_redirects"])
            self.assertEqual(client.request.call_args.kwargs["timeout"], (5, 10))
            response.status_code = 200
            response.iter_content.return_value = [b"a" * (1024 * 1024 + 1)]
            with self.assertRaises(ValueError):
                _request_json("GET", "https://identity.example/keys")


if __name__ == "__main__":
    unittest.main()
