"""Exercise actual MFA routes; move only the clock to obtain unused test codes."""
import re
from unittest.mock import patch

from app import get_db
from mfa import code_at_counter, decrypt_secret, time_counter


def complete_mfa(client, app, username="admin", base_url="https://localhost"):
    response = client.get("/", base_url=base_url, follow_redirects=True)
    if response.request.path not in {"/mfa/enroll", "/mfa/challenge"}:
        raise AssertionError(f"Expected an MFA step, got {response.request.path}: {response.status_code}")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    if token is None:
        raise AssertionError("MFA page has no CSRF token")
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        secret = decrypt_secret(user["mfa_secret"] or user["mfa_pending_secret"])
        counter = max(time_counter(), user["mfa_last_counter"] + 1)
        code = code_at_counter(secret, counter)
    with patch("mfa.time_counter", return_value=counter):
        response = client.post(response.request.path, base_url=base_url,
                               data={"csrf_token": token.group(1).decode(), "code": code}, follow_redirects=True)
    if response.status_code != 200 or response.request.path != "/":
        raise AssertionError(f"MFA did not complete: {response.status_code}: {response.data!r}")
    return response
