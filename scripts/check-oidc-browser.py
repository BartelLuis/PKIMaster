"""Optional real-Chromium regression for OIDC form redirects and Strict cookies.

Requires Node.js and Playwright with Chromium installed, separately from runtime
dependencies. Run from a development checkout with Python dependencies installed:

    python scripts/check-oidc-browser.py --playwright-module /path/to/node_modules/playwright

Two temporary HTTPS servers use distinct sites (127.0.0.1 and localhost). Only the
provider back-channel calls are mocked; browser navigation, provider form submit,
JWT signature/claims, PKCE, application CSRF, session cookies, and MFA are real.
The fixture never accesses a production database or external identity provider.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlencode
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from flask import Flask, redirect, request  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402
from werkzeug.serving import WSGIRequestHandler, make_server  # noqa: E402

from app import create_app, get_db  # noqa: E402
from mfa_helpers import complete_mfa  # noqa: E402


BROWSER_CHECK = r"""
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {chromium} = require(require.resolve(process.argv[3], {paths: [process.cwd()]}));
(async () => {
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({ignoreHTTPSErrors: true});
    const page = await context.newPage();
    const errors = [];
    const navigation = [];
    page.on('console', message => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('response', response => {
      if (response.request().isNavigationRequest()) {
        const url = new URL(response.url());
        navigation.push({status: response.status(), host: url.hostname, path: url.pathname});
      }
    });
    const application = process.argv[2];
    await page.goto(application + '/login');
    await page.getByRole('button', {name: 'Continue with your identity provider'}).click();
    // Commit an actual cross-site document. A redirect-only IdP mock misses the
    // SameSite=Strict failure on the callback's subsequent redirect chain.
    assert.equal(new URL(page.url()).hostname, 'localhost');
    await page.getByRole('button', {name: 'Sign in at provider'}).click();
    assert.equal(new URL(page.url()).pathname, '/auth/oidc/callback');
    assert.equal(navigation.at(-1).status, 200);
    await page.getByRole('link', {name: 'Continue to authenticator'}).click();
    assert.equal(new URL(page.url()).pathname, '/mfa/enroll');
    const secret = (await page.locator('#mfa-setup-key').innerText()).trim();
    const code = execFileSync(process.argv[4],
      ['-c', 'import sys; from mfa import totp; print(totp(sys.stdin.read().strip()))'],
      {input: secret, encoding: 'utf8'}).trim();
    await page.locator('input[name=code]').fill(code);
    await page.getByRole('button', {name: 'Verify and activate authenticator'}).click();
    await page.waitForURL(application + '/');
    assert.equal(navigation.at(-1).status, 200);
    const cookies = await context.cookies();
    assert.equal(cookies.find(cookie => cookie.name === 'session').sameSite, 'Strict');
    assert(!cookies.some(cookie => cookie.name === '__Host-pkimaster_oidc'));
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({result: 'OIDC browser flow passed', navigation}, null, 2));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--playwright-module", default="playwright", help="Playwright npm module name or absolute module directory")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pkimaster-oidc-browser-") as directory:
        app = create_app({"TESTING": True, "INSTANCE_PATH": directory,
                          "DATABASE": str(Path(directory) / "pki.sqlite"), "SESSION_COOKIE_SECURE": True})
        provider = Flask("temporary_mock_identity_provider")
        servers = [make_server("127.0.0.1", 0, application, ssl_context="adhoc", threaded=True, request_handler=QuietHandler)
                   for application in (app, provider)]
        application_url = "https://127.0.0.1:" + str(servers[0].server_port)
        provider_url = "https://localhost:" + str(servers[1].server_port)
        metadata = {"issuer": provider_url, "authorization_endpoint": provider_url + "/authorize",
                    "token_endpoint": provider_url + "/token", "jwks_uri": provider_url + "/keys",
                    "code_challenge_methods_supported": ["S256"]}
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())) | {"kid": "browser-test", "alg": "RS256"}
        codes = {}

        @provider.get("/authorize")
        def authorize():
            code = secrets.token_urlsafe(20)
            codes[code] = dict(request.args)
            return '<h1>Mock identity provider</h1><form method="post" action="/approve?code=' + code + '"><button>Sign in at provider</button></form>'

        @provider.post("/approve")
        def approve():
            code = request.args["code"]
            authorization = codes[code]
            return redirect(authorization["redirect_uri"] + "?" + urlencode({"code": code, "state": authorization["state"]}))

        def back_channel(method, url, **kwargs):
            if url.endswith("/.well-known/openid-configuration"):
                return metadata
            if url.endswith("/keys"):
                return {"keys": [public]}
            if url.endswith("/token"):
                data = kwargs["data"]
                authorization = codes.pop(data["code"])
                expected = base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest()).rstrip(b"=").decode()
                assert expected == authorization["code_challenge"]
                assert data["redirect_uri"] == authorization["redirect_uri"]
                claims = {"iss": provider_url, "sub": "browser-user", "aud": "pkimaster-browser", "nonce": authorization["nonce"],
                          "iat": int(time.time()), "exp": int(time.time()) + 300}
                return {"id_token": jwt.encode(claims, private, algorithm="RS256", headers={"kid": "browser-test"}), "access_token": "discard"}
            raise ValueError("Unexpected provider request")

        threads = []
        try:
            with patch("identity._request_json", side_effect=back_channel):
                client = app.test_client()

                def token(path):
                    response = client.get(path, base_url=application_url)
                    return re.search(rb'name="csrf_token" value="([^"]+)"', response.data)[1].decode()

                password = secrets.token_urlsafe(32)
                response = client.post("/setup", base_url=application_url,
                                       data={"csrf_token": token("/setup"), "username": "admin", "password": password,
                                             "password_confirm": password, "organization": "OIDC Browser Test"})
                assert response.status_code == 302
                complete_mfa(client, app, base_url=application_url)
                with app.app_context():
                    db = get_db()
                    db.execute("INSERT INTO users (username,password_hash,role,auth_source,external_issuer,external_subject) VALUES (?,?,'operator','oidc',?,?)",
                               ("browser-user", generate_password_hash(secrets.token_urlsafe(40)), provider_url, "browser-user"))
                    db.commit()
                response = client.post("/settings/identity", base_url=application_url,
                                       data={"csrf_token": token("/settings/identity"), "mode": "oidc", "allow_local_breakglass": "on",
                                             "oidc_issuer": provider_url, "oidc_client_id": "pkimaster-browser", "oidc_client_secret": "test-only-secret",
                                             "oidc_redirect_uri": application_url + "/auth/oidc/callback"})
                assert response.status_code == 302
                for server in servers:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    threads.append(thread)
                browser_script = Path(directory) / "browser.cjs"
                browser_script.write_text(BROWSER_CHECK, encoding="utf-8")
                subprocess.run(["node", str(browser_script), application_url, args.playwright_module, sys.executable], cwd=ROOT, check=True, timeout=90)
        finally:
            for server in servers:
                if threads:
                    server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
