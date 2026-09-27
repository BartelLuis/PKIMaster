"""Exercise automatic recovery through the real packaged HTTPS supervisor."""
from contextlib import closing
from http.cookiejar import CookieJar
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPSHandler, ProxyHandler, Request, build_opener

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import create_app, get_db
from audit_integrity import verify_chain
from backup import create_snapshot, encrypt_archive, restore_pending
from mfa import code_at_counter, decrypt_secret, time_counter
import pkimaster_server


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("gunicorn"), "Real supervisor requires POSIX and Gunicorn")
class AutomaticHttpsRecoveryTests(unittest.TestCase):
    def test_supervisor_restores_fresh_host_restarts_https_and_preserves_ca_identity(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        source, destination = root / "source", root / "destination"
        password = "supervisor recovery administrator passphrase"
        passphrase = "supervisor recovery encrypted archive passphrase"
        application = create_app({"TESTING": True, "INSTANCE_PATH": str(source), "SESSION_COOKIE_SECURE": False})
        client = application.test_client()

        def csrf(body):
            match = re.search(rb'name="csrf_token" value="([^"]+)"', body)
            self.assertIsNotNone(match, "The authentication or recovery form has no CSRF token")
            return match.group(1).decode()

        setup = client.get("/setup")
        response = client.post("/setup", data={"csrf_token": csrf(setup.data), "username": "admin", "password": password,
                                               "password_confirm": password, "organization": "Supervisor recovery"})
        self.assertEqual(response.status_code, 302)
        enrollment = client.get("/mfa/enroll")
        with application.app_context():
            user = get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone()
            secret = decrypt_secret(user["mfa_pending_secret"])
        # Leave the current TOTP step unused for the later real HTTPS sign-in.
        response = client.post("/mfa/enroll", data={"csrf_token": csrf(enrollment.data),
                               "code": code_at_counter(secret, time_counter() - 1)})
        self.assertEqual(response.status_code, 302)
        with patch("pki.generate_private_key", side_effect=lambda: ec.generate_private_key(ec.SECP384R1())):
            response = client.post("/authorities", data={"csrf_token": csrf(client.get("/").data), "name": "Restored root",
                                   "common_name": "Restored root", "role": "root", "validity_days": "365"})
        self.assertEqual(response.status_code, 302)
        source_tls = pkimaster_server.ensure_bootstrap_tls(source).read_bytes()
        original_cookie = client.get_cookie("session").value
        with application.app_context():
            authority = get_db().execute("SELECT id,certificate_pem FROM authorities").fetchone()
            authority_id = authority["id"]
            fingerprint = x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).fingerprint(hashes.SHA256())
            encrypted = encrypt_archive(create_snapshot(get_db()), passphrase)
        source_secrets = json.loads((source / "runtime-secrets.json").read_text())

        create_app({"TESTING": True, "INSTANCE_PATH": str(destination)})
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with closing(sqlite3.connect(destination / "pkimaster.sqlite")) as database, database:
            database.execute("UPDATE settings SET value=? WHERE key='https_port'", (str(port),))
        destination_tls = pkimaster_server.ensure_bootstrap_tls(destination).read_bytes()
        destination_secrets = json.loads((destination / "runtime-secrets.json").read_text())
        pid_file = root / "children.txt"
        wrapper = root / "supervisor.py"
        # Change only the test state directory and child entry point. Production
        # supervise(), _start_child(), serve(), Gunicorn and HTTPS remain real.
        wrapper.write_text(
            "import json, sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(Path(pkimaster_server.__file__).resolve().parent)!r})\n"
            "import pkimaster_server as server\n"
            f"state = Path({str(destination)!r})\n"
            "server.STATE_DIRECTORY = state\nserver.runtime_application.__defaults__ = (state,)\n"
            "server.__file__ = __file__\noriginal_start = server._start_child\n"
            "def record_child(configuration):\n"
            "    child = original_start(configuration)\n"
            f"    with open({str(pid_file)!r}, 'a') as output:\n"
            "        output.write(str(child.pid) + '\\n')\n"
            "    return child\n"
            "server._start_child = record_child\n"
            "if sys.argv[1:] == ['--serve']:\n"
            "    server.serve(instance_path=state, runtime_config=json.load(sys.stdin))\n"
            "else:\n    server.supervise()\n", encoding="utf-8")
        log = (root / "supervisor.log").open("w+b")
        self.addCleanup(log.close)
        process = subprocess.Popen([sys.executable, str(wrapper)], stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)

        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            # Gunicorn creates its own process group. Reap test-owned groups if
            # the supervisor could not perform its normal graceful shutdown.
            if pid_file.exists():
                for pid in {int(value) for value in pid_file.read_text().splitlines()}:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        self.addCleanup(stop)
        context = ssl.create_default_context()
        for bundle in (source_tls, destination_tls):
            certificate = x509.load_pem_x509_certificate(bundle)
            context.load_verify_locations(cadata=certificate.public_bytes(serialization.Encoding.PEM).decode())
        cookies = CookieJar()
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), HTTPCookieProcessor(cookies))
        base = f"https://127.0.0.1:{port}"
        deadline = time.monotonic() + 25

        def request(path, *, data=None, headers=None, http_client=opener):
            with http_client.open(Request(base + path, data=data, headers=headers or {}), timeout=2) as received:
                return received.status, received.read(), urlsplit(received.url).path

        def wait_for(path, expected_path):
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    self.fail("HTTPS supervisor exited: " + log.read().decode(errors="replace")[-8000:])
                try:
                    result = request(path)
                    if result[0] == 200 and result[2] == expected_path:
                        return result
                except (HTTPError, URLError, OSError):
                    pass
                time.sleep(0.1)
            log.seek(0)
            self.fail("HTTPS supervisor did not complete recovery within 25 seconds: " + log.read().decode(errors="replace")[-8000:])

        _, restore_page, _ = wait_for("/restore", "/restore")
        first_child = pid_file.read_text().splitlines()[0]
        boundary = "PKIMaster" + secrets.token_hex(16)
        fields = {"csrf_token": csrf(restore_page), "passphrase": passphrase, "source_stopped": "on"}
        parts = []
        for name, value in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        parts.extend([f'--{boundary}\r\nContent-Disposition: form-data; name="archive"; filename="recovery.pkibackup"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
                      encrypted, f"\r\n--{boundary}--\r\n".encode()])
        status, _, _ = request("/restore", data=b"".join(parts), headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
        self.assertEqual(status, 202)
        _, login_page, _ = wait_for("/login", "/login")
        self.assertFalse(restore_pending(destination))
        self.assertNotEqual(pid_file.read_text().splitlines()[-1], first_child, "Recovery must restart the HTTPS child")
        self.assertIsNone(process.poll(), "The original supervisor must survive recovery")
        restored_secrets = json.loads((destination / "runtime-secrets.json").read_text())
        self.assertEqual(restored_secrets["KEY_ENCRYPTION_SECRET"], source_secrets["KEY_ENCRYPTION_SECRET"])
        self.assertNotIn(restored_secrets["SECRET_KEY"], {source_secrets["SECRET_KEY"], destination_secrets["SECRET_KEY"]})
        self.assertEqual((destination / "server-tls" / "bootstrap.pem").read_bytes(), source_tls)
        old_session_client = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        self.assertEqual(request("/", headers={"Cookie": "session=" + original_cookie}, http_client=old_session_client)[2], "/login")
        _, challenge_page, path = request("/login", data=urlencode({"csrf_token": csrf(login_page), "username": "admin", "password": password}).encode())
        self.assertEqual(path, "/mfa/challenge")
        _, _, path = request("/mfa/challenge", data=urlencode({"csrf_token": csrf(challenge_page), "code": code_at_counter(secret, time_counter())}).encode())
        self.assertEqual(path, "/")
        _, certificate_pem, _ = request(f"/authorities/{authority_id}/cert")
        self.assertEqual(x509.load_pem_x509_certificate(certificate_pem).fingerprint(hashes.SHA256()), fingerprint)
        with closing(sqlite3.connect(destination / "pkimaster.sqlite")) as database:
            verify_chain(database, source_secrets["KEY_ENCRYPTION_SECRET"])
            self.assertEqual(database.execute("SELECT COUNT(*) FROM audit_events WHERE action='backup.restored'").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
