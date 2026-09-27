import ipaddress
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from pkimaster_server import _Configuration, _reject_configuration, ensure_bootstrap_tls, read_listener, runtime_application, supervise, tls_bundle


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
        from app import create_app
        create_app({"TESTING": True, "INSTANCE_PATH": str(self.state)})
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            db.executemany("UPDATE settings SET value=? WHERE key=?", [("192.0.2.123", "listen_address"), ("8443", "https_port")])
        active = _Configuration("127.0.0.1", 8443, b"previous identity")
        rejected = _Configuration("192.0.2.123", 8443, b"requested identity")
        _reject_configuration(self.state, rejected, active)
        self.assertEqual(read_listener(self.state), ("127.0.0.1", 8443))
        with closing(sqlite3.connect(self.state / "pkimaster.sqlite")) as db, db:
            self.assertEqual(db.execute("SELECT actor_name, action FROM audit_events").fetchone(), ("system", "runtime.listener_rejected"))
            db.execute("UPDATE settings SET value='9443' WHERE key='https_port'")
        _reject_configuration(self.state, rejected, active)
        self.assertEqual(read_listener(self.state), ("127.0.0.1", 9443))

    def test_application_startup_does_not_migrate_during_recovery_or_another_startup(self):
        from backup import MARKER, RestoreBusy, _worker_lock
        with _worker_lock(self.state / "runtime-startup.lock"), self.assertRaises(RestoreBusy):
            runtime_application(self.state)
        self.assertFalse((self.state / "pkimaster.sqlite").exists())
        (self.state / MARKER).write_text("{}", encoding="utf-8")
        with self.assertRaises(RestoreBusy):
            runtime_application(self.state)
        self.assertFalse((self.state / "pkimaster.sqlite").exists())

    def test_supervisor_stops_old_workers_before_installing_and_reloading_restore(self):
        configuration = _Configuration("127.0.0.1", 8443, b"TLS")
        events = []
        children = [Mock(), Mock()]
        for child in children:
            child.poll.return_value = None
        stopping = Mock()
        stopping.is_set.side_effect = [False, False, True]
        stopping.wait.return_value = False
        def start(_):
            child = children.pop(0)
            events.append(("start", child))
            return child
        def apply(_):
            events.append(("apply", None))
            return True
        def stop(child):
            events.append(("stop", child))
        with (patch("pkimaster_server.STATE_DIRECTORY", self.state),
              patch("pkimaster_server.runtime_application"),
              patch("pkimaster_server._configuration", return_value=configuration),
              patch("pkimaster_server._remembered_configuration", return_value=None),
              patch("pkimaster_server._remember_configuration"),
              patch("pkimaster_server.signal.signal"),
              patch("pkimaster_server.os.umask"),
              patch("pkimaster_server.threading.Event", return_value=stopping),
              patch("pkimaster_server._start_child", side_effect=start),
              patch("pkimaster_server._stop_child", side_effect=stop),
              patch("backup.apply_pending_restore", side_effect=apply),
              patch("backup.restore_pending", side_effect=[False, True])):
            supervise()
        self.assertEqual([name for name, _ in events], ["apply", "start", "stop", "apply", "start", "stop"])
        self.assertIs(events[1][1], events[2][1])
        self.assertIs(events[4][1], events[5][1])
        self.assertIsNot(events[1][1], events[4][1])

    def test_supervisor_retries_busy_recovery_before_starting_application(self):
        from backup import RestoreBusy
        stopping = Mock()
        stopping.is_set.return_value = True
        with (patch("pkimaster_server.STATE_DIRECTORY", self.state),
              patch("pkimaster_server.runtime_application") as application,
              patch("pkimaster_server._configuration", return_value=_Configuration("127.0.0.1", 8443, b"TLS")),
              patch("pkimaster_server._remembered_configuration", return_value=None),
              patch("pkimaster_server.signal.signal"),
              patch("pkimaster_server.os.umask"),
              patch("pkimaster_server.threading.Event", return_value=stopping),
              patch("pkimaster_server.time.sleep") as sleep,
              patch("pkimaster_server._start_child") as start,
              patch("backup.apply_pending_restore", side_effect=[RestoreBusy("busy"), True])):
            supervise()
        application.assert_called_once_with()
        sleep.assert_called_once_with(0.5)
        start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
