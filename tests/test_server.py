import ipaddress
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from pkimaster_server import _Configuration, _reject_configuration, ensure_bootstrap_tls, read_listener, tls_bundle


class PackagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)

    def test_tls_identity_is_persisted_and_is_only_a_server_certificate(self):
        bundle = ensure_bootstrap_tls(self.state)
        before = bundle.read_bytes()
        self.assertEqual(ensure_bootstrap_tls(self.state).read_bytes(), before)
        certificate = x509.load_pem_x509_certificate(before)
        key = serialization.load_pem_private_key(before, password=None)
        self.assertEqual(certificate.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertFalse(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn(ipaddress.ip_address("127.0.0.1"), names.get_values_for_type(x509.IPAddress))
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, usages)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(bundle))
        if os.name == "posix":
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)
            self.assertEqual(bundle.parent.stat().st_mode & 0o777, 0o700)

    def test_invalid_uploaded_tls_does_not_silently_fall_back(self):
        ensure_bootstrap_tls(self.state)
        uploaded = self.state / "server-tls" / "uploaded.pem"
        uploaded.write_bytes(b"not a certificate or key")
        with self.assertRaises(ssl.SSLError):
            tls_bundle(self.state)

    def test_web_listener_settings_are_persisted_and_validated(self):
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            db.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.assertEqual(read_listener(self.state), ("127.0.0.1", 8443))
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            db.executemany("INSERT INTO settings VALUES (?, ?)", [("listen_address", "::1"), ("https_port", "9443")])
        self.assertEqual(read_listener(self.state), ("::1", 9443))
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            db.execute("UPDATE settings SET value='443' WHERE key='https_port'")
        with self.assertRaises(ValueError):
            read_listener(self.state)
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            db.execute("UPDATE settings SET value='9443' WHERE key='https_port'")
            db.execute("UPDATE settings SET value='example.com' WHERE key='listen_address'")
        with self.assertRaises(ValueError):
            read_listener(self.state)

    def test_rejected_listener_is_audited_without_overwriting_a_newer_save(self):
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            db.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE audit_events (actor_name TEXT, action TEXT, object_type TEXT, detail TEXT)")
            db.executemany("INSERT INTO settings VALUES (?, ?)", [("listen_address", "192.0.2.123"), ("https_port", "8443")])
        active = _Configuration("127.0.0.1", 8443, b"previous identity")
        rejected = _Configuration("192.0.2.123", 8443, b"requested identity")
        _reject_configuration(self.state, rejected, active)
        self.assertEqual(read_listener(self.state), ("127.0.0.1", 8443))
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            self.assertEqual(db.execute("SELECT actor_name, action FROM audit_events").fetchone(), ("system", "runtime.listener_rejected"))
            db.execute("UPDATE settings SET value='9443' WHERE key='https_port'")
        _reject_configuration(self.state, rejected, active)
        self.assertEqual(read_listener(self.state), ("127.0.0.1", 9443))


if __name__ == "__main__":
    unittest.main()
