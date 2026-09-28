"""Exercise the installed HTTPS service in a disposable package smoke test."""

import http.cookiejar
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, "/usr/lib/pkimaster")
from mfa import time_counter, totp
from cryptography import x509


temporary = Path(sys.argv[1])
verify_upgrade = sys.argv[2:] == ["--verify-upgrade"]
context = ssl.create_default_context(cafile="/var/lib/pkimaster/server-tls/bootstrap.pem")
cookies = http.cookiejar.CookieJar()
client = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookies),
    urllib.request.HTTPSHandler(context=context),
)
base = "https://127.0.0.1:8443"


def get(path):
    with client.open(base + path, timeout=10) as response:
        return response.read().decode("utf-8")


def assert_not_found(path):
    try:
        get(path)
    except urllib.error.HTTPError as error:
        assert error.code == 404, f"Expected a deleted artifact at {path} to return 404, got {error.code}."
    else:
        raise AssertionError(f"Deleted artifact is still available at {path}.")


def post(path, values, token_page=None):
    page = get(token_page or path)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert token, "A CSRF token must be present in the served HTML."
    values = {"csrf_token": token.group(1), **values}
    request = urllib.request.Request(
        base + path, data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={"Origin": base},
    )
    with client.open(request, timeout=30) as response:
        return response.read().decode("utf-8")


def wait_for_listener(port):
    global base
    base = f"https://127.0.0.1:{port}"
    for _ in range(30):
        try:
            if json.loads(get("/healthz"))["status"] == "ok":
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    raise AssertionError(f"The saved HTTPS listener did not start on port {port}.")


class Inputs(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.values = {}
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("name"):
            self.values[values["name"]] = values.get("value", "")


def wait_for_rejected_listener():
    for _ in range(15):
        values = Inputs(get("/settings")).values
        if values.get("listen_address") == "127.0.0.1" and values.get("https_port") == "8443":
            return
        time.sleep(1)
    raise AssertionError("An unavailable listener must revert to the previous web settings.")


credential_file = temporary / "smoke-credentials.json"


def complete_authentication(credentials, page=None):
    page = page or get("/")
    enrollment = re.search(r'id="mfa-setup-key"[^>]*>([A-Z2-7]+)</dd>', page)
    if enrollment:
        credentials["mfa_secret"] = enrollment.group(1)
    assert credentials.get("mfa_secret"), "No authenticator enrollment credential available."
    while time_counter() <= credentials.get("last_counter", -1):
        time.sleep(1)
    code_time = int(time.time())
    credentials["last_counter"] = time_counter(code_time)
    page = post("/mfa/enroll" if enrollment else "/mfa/challenge", {"code": totp(credentials["mfa_secret"], code_time)})
    assert "Local certificate authority" in page, "Mandatory MFA did not complete."
    credential_file.write_text(json.dumps(credentials), encoding="utf-8")
    for path, expected in (("/account/security", "Recovery codes"), ("/settings/backup", "Create an encrypted backup"),
                           ("/monitoring", "Monitoring &amp; alerts"), ("/monitoring/settings", "Monitoring settings")):
        assert expected in get(path), f"Installed feature page is unavailable: {path}"


if verify_upgrade:
    credentials = json.loads(credential_file.read_text(encoding="utf-8"))
    post("/login", {key: credentials[key] for key in ("username", "password")})
    complete_authentication(credentials)
    # A fresh signed CRL proves that the retained secret decrypts the original CA key.
    original_pem = get("/authorities/1/cert")
    original_chain = get("/authorities/1/chain")
    certificate = x509.load_pem_x509_certificate(original_pem.encode())
    crl = x509.load_pem_x509_crl(get("/crl/1.crl?format=pem").encode())
    assert crl.is_signature_valid(certificate.public_key()), "Original CA signing key was not retained."
    page = post("/authorities", {
        "name": "Smoke issuing CA", "role": "issuing",
        "common_name": "Smoke issuing CA", "validity_days": "180",
    }, token_page="/")
    assert "Only one CA may be current on this server" in page, "A second current local CA must be rejected."

    # Run replacement only after checking the upgraded service's original identity.
    # The package smoke test snapshots runtime secrets and HTTPS identity; these
    # must remain unchanged while CA history grows in the retained database.
    post("/authorities/1/revoke", {"reason": "superseded"}, token_page="/authorities/1")
    page = get("/")
    assert "Initialize this server's CA" in page, "Revocation must make CA initialization available again."
    assert "Revoked CA archive" in page, "The original CA must remain visible in the archive."
    assert "Local CA boundary</span><strong>0 / 1</strong>" in get("/security"), "A revoked CA must not occupy the current CA slot."
    page = post("/authorities", {
        "name": "Smoke Replacement Root CA", "role": "root", "common_name": "Smoke Replacement Root CA",
        "validity_days": "365",
    }, token_page="/")
    assert "Created root CA" in page, "The installed package must initialize a replacement after revocation."
    assert "Revoked CA archive" in page, "Replacement must preserve the original CA archive."
    assert "Local CA boundary</span><strong>1 / 1</strong>" in get("/security"), "Only the replacement CA must occupy the current slot."
    replacement = x509.load_pem_x509_certificate(get("/authorities/2/cert").encode())
    assert replacement.serial_number != certificate.serial_number, "A replacement must receive a new certificate."
    assert replacement.public_key().public_numbers() != certificate.public_key().public_numbers(), "A replacement must receive a new key."
    replacement_crl = x509.load_pem_x509_crl(get("/crl/2.crl?format=pem").encode())
    assert replacement_crl.is_signature_valid(replacement.public_key()), "The replacement CA must sign its own CRL."
    assert get("/authorities/1/cert") == original_pem, "Replacement must preserve the original CA certificate."
    assert get("/authorities/1/chain") == original_chain, "Replacement must preserve the original CA chain."
    archived_crl = x509.load_pem_x509_crl(get("/crl/1.crl?format=pem").encode())
    assert archived_crl.is_signature_valid(certificate.public_key()), "The archived CA must retain its original CRL signing key."

    # Explicit deletion is separate from revocation and frees the old display name.
    page = get("/authorities/1")
    assert 'name="confirmation_name"' in page, "A revoked CA must offer typed-name deletion confirmation."
    post("/authorities/1/delete", {"confirmation_name": "Wrong CA"}, token_page="/authorities/1")
    assert get("/authorities/1/cert") == original_pem, "An incorrect confirmation name must not delete the CA."
    post("/authorities/1/delete", {"confirmation_name": "Smoke Root CA"}, token_page="/authorities/1")
    for path in ("/authorities/1", "/authorities/1/cert", "/authorities/1/chain", "/crl/1.crl", "/aia/1.cer"):
        assert_not_found(path)
    assert x509.load_pem_x509_certificate(get("/authorities/2/cert").encode()) == replacement, "Deleting an archive must preserve the current CA."
    post("/authorities/2/revoke", {"reason": "superseded"}, token_page="/authorities/2")
    page = post("/authorities", {
        "name": "Smoke Root CA", "role": "root", "common_name": "Smoke Root CA", "validity_days": "365",
    }, token_page="/")
    assert "Created root CA" in page, "A deleted CA's display name must be reusable."
    reused_name = x509.load_pem_x509_certificate(get("/authorities/3/cert").encode())
    assert reused_name.public_key().public_numbers() != certificate.public_key().public_numbers(), "Reusing a display name must generate a new key."
    assert get("/authorities/2/cert"), "An undeleted revoked CA must remain archived."
    print("Upgrade preserves MFA and CA keys; replacement retains archives; explicit deletion removes artifacts and frees the display name.")
else:
    credentials = {"username": "smoke-admin", "password": secrets.token_urlsafe(32)}
    credential_file.write_text(json.dumps(credentials), encoding="utf-8")
    page = post("/setup", {
        **credentials, "password_confirm": credentials["password"],
        "organization": "PKIMaster package smoke test",
    })
    assert "Installation complete" in page, "The web-only initial setup failed."
    complete_authentication(credentials, page=page)
    assert all(cookie.secure for cookie in cookies), "HTTPS sessions must use Secure cookies."
    page = post("/authorities", {
        "name": "Smoke Root CA", "role": "root", "common_name": "Smoke Root CA",
        "validity_days": "365",
    }, token_page="/")
    assert "Created root CA" in page, "A fresh installed package must create a Root CA."
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        next_port = probe.getsockname()[1]
    post("/settings", {"organization": "PKIMaster package smoke test", "https_port": str(next_port)})
    wait_for_listener(next_port)
    assert "PKIMaster package smoke test" in get("/settings"), "The session must survive a listener restart."
    post("/settings", {"organization": "PKIMaster package smoke test", "https_port": "8443"})
    wait_for_listener(8443)
    post("/settings", {
        "organization": "PKIMaster package smoke test", "listen_address": "192.0.2.123", "https_port": "8443",
    })
    wait_for_rejected_listener()
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        post("/settings", {
            "organization": "PKIMaster package smoke test", "https_port": str(occupied.getsockname()[1]),
        })
        wait_for_rejected_listener()
    assert "runtime.listener_rejected" in get("/audit"), "Rejected listener changes must be audited."
    print("HTTPS setup, CA creation, listener restart and unavailable-listener rollback passed.")
