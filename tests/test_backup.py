"""Recovery exercises real authentication, encrypted CA material and audit checks."""
from contextlib import closing
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import create_app, decrypt_private_key, get_db
from audit_integrity import verify_chain
from backup import (BackupError, MAGIC, MARKER, RestoreBusy, _worker_lock, apply_pending_restore,
                    create_snapshot, decrypt_archive, encrypt_archive, pack_snapshot, restore_pending,
                    stage_restore, unpack_snapshot)
from mfa import code_at_counter, decrypt_secret, time_counter
from mfa_helpers import complete_mfa
from pkimaster_server import ensure_bootstrap_tls, runtime_application


PASSPHRASE = "offline disaster recovery passphrase"


class ArchiveFormatTests(unittest.TestCase):
    def test_authenticated_encryption_rejects_wrong_password_and_damage(self):
        plaintext = b"private material and audit history"
        encrypted = encrypt_archive(plaintext, PASSPHRASE)
        self.assertNotIn(plaintext, encrypted)
        self.assertEqual(decrypt_archive(encrypted, PASSPHRASE), plaintext)
        self.assertNotEqual(encrypted, encrypt_archive(plaintext, PASSPHRASE))
        for data, password in ((encrypted, "a completely incorrect passphrase"),
                               (encrypted[:-1] + bytes([encrypted[-1] ^ 1]), PASSPHRASE),
                               (MAGIC + bytes([encrypted[len(MAGIC)] ^ 1]) + encrypted[len(MAGIC) + 1:], PASSPHRASE)):
            with self.assertRaisesRegex(BackupError, "incorrect or.*damaged"):
                decrypt_archive(data, password)
        with self.assertRaises(BackupError):
            encrypt_archive(b"data", "too short")

    def test_archive_rejects_traversal_duplicates_links_compression_and_hash_damage(self):
        required = {"pkimaster.sqlite": b"database", "runtime-secrets.json": b"secrets", "pkimaster.audit-sealed": b"seal"}
        valid = pack_snapshot(required)
        self.assertEqual(unpack_snapshot(valid), required)
        for filename in ("../runtime-secrets.json", "/tmp/key", "softhsm/tokens/../../key", "softhsm/tokens/CON", "server-tls\\uploaded.pem"):
            output = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(valid)) as original, zipfile.ZipFile(output, "w") as modified:
                for info in original.infolist():
                    modified.writestr(info, original.read(info))
                modified.writestr(filename, b"unexpected")
            with self.assertRaises(BackupError, msg=filename):
                unpack_snapshot(output.getvalue())
        for mode in ("duplicate", "symlink", "compressed", "checksum"):
            output = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(valid)) as original, zipfile.ZipFile(output, "w") as modified:
                for info in original.infolist():
                    value = original.read(info)
                    if info.filename == "pkimaster.sqlite":
                        if mode == "symlink":
                            info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        elif mode == "compressed":
                            info.compress_type = zipfile.ZIP_DEFLATED
                        elif mode == "checksum":
                            value = b"modified database"
                    modified.writestr(info, value)
                if mode == "duplicate":
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        modified.writestr("pkimaster.sqlite", b"second database")
            with self.assertRaises(BackupError, msg=mode):
                unpack_snapshot(output.getvalue())


class BackupWorkflowTests(unittest.TestCase):
    password = "a long administrator passphrase"
    base = "https://localhost"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        # Windows runners may expose TEMP through an 8.3 alias. Match the
        # canonical state paths used by the recovery installer and its journal.
        self.root = Path(self.directory.name).resolve()
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": str(self.root)})
        self.client = self.app.test_client()
        response = self.post(self.client, "/setup", {"username": "admin", "password": self.password,
            "password_confirm": self.password, "organization": "Recovery tests"})
        self.assertEqual(response.status_code, 302)
        complete_mfa(self.client, self.app)
        # Archive workflow tests target file/DB integrity. The preceding crypto
        # test exercises the actual 128 MiB KDF; avoid paying that cost per case.
        patcher = patch("backup._derive_key", return_value=b"\0" * 32)
        patcher.start()
        self.addCleanup(patcher.stop)

    def csrf(self, client, path="/"):
        page = client.get(path, base_url=self.base, follow_redirects=True)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(token, page.data)
        return token.group(1).decode()

    def post(self, client, path, data, **kwargs):
        return client.post(path, base_url=self.base, data={"csrf_token": self.csrf(client), **data}, **kwargs)

    def code(self):
        with self.app.app_context():
            user = get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone()
            counter = max(time_counter(), user["mfa_last_counter"] + 1)
            return code_at_counter(decrypt_secret(user["mfa_secret"]), counter), counter

    def export(self):
        code, counter = self.code()
        with patch("mfa.time_counter", return_value=counter):
            response = self.post(self.client, "/settings/backup/export", {"passphrase": PASSPHRASE,
                "passphrase_confirm": PASSPHRASE, "totp_code": code})
        self.assertEqual(response.status_code, 200, response.data[:1000])
        return response.data

    def fresh(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        app = create_app({"TESTING": True, "INSTANCE_PATH": str(root)})
        return root, app, app.test_client()

    def restore(self, client, encrypted, **updates):
        values = {"archive": (io.BytesIO(encrypted), "backup.pkibackup"), "passphrase": PASSPHRASE, "source_stopped": "on"}
        values.update(updates)
        return self.post(client, "/restore", values)

    def test_fresh_host_restores_ca_keys_audit_tls_and_softhsm_without_source_sessions(self):
        with patch("pki.generate_private_key", side_effect=lambda: ec.generate_private_key(ec.SECP384R1())):
            response = self.post(self.client, "/authorities", {"name": "Recovered CA", "common_name": "Recovered CA", "role": "root", "validity_days": "365"})
        self.assertEqual(response.status_code, 302)
        tls = ensure_bootstrap_tls(self.root).read_bytes()
        tokens = self.root / "softhsm" / "tokens" / "token-123"
        tokens.mkdir(parents=True)
        (tokens / "object.object").write_bytes(b"opaque managed token material")
        (tokens.parent.parent / "softhsm2.conf").write_text("directories.tokendir = /original/host/tokens\n", encoding="utf-8")
        with self.app.app_context():
            authority = dict(get_db().execute("SELECT * FROM authorities").fetchone())
            key = serialization.load_pem_private_key(decrypt_private_key(authority["private_key_pem"]).encode(), password=None)
            original_key = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            original_secret = self.app.config["KEY_ENCRYPTION_SECRET"]
        old_cookie = self.client.get_cookie("session").value
        encrypted = self.export()
        self.assertNotIn(original_secret.encode(), encrypted)
        files = unpack_snapshot(decrypt_archive(encrypted, PASSPHRASE))
        self.assertEqual(files["server-tls/bootstrap.pem"], tls)
        self.assertIn("softhsm/tokens/token-123/object.object", files)
        fresh_root, fresh_app, fresh_client = self.fresh()
        staged = self.restore(fresh_client, encrypted)
        self.assertEqual(staged.status_code, 202, staged.data)
        self.assertTrue(restore_pending(fresh_root))
        self.assertEqual(fresh_client.get("/setup", base_url=self.base).status_code, 503)
        with self.assertRaises(RestoreBusy):
            runtime_application(fresh_root)
        self.assertTrue(apply_pending_restore(fresh_root))
        self.assertFalse(restore_pending(fresh_root))
        self.assertFalse(apply_pending_restore(fresh_root))
        restored_app = create_app({"TESTING": True, "INSTANCE_PATH": str(fresh_root)})
        self.assertEqual(restored_app.config["KEY_ENCRYPTION_SECRET"], original_secret)
        self.assertNotEqual(restored_app.config["SECRET_KEY"], self.app.config["SECRET_KEY"])
        with restored_app.app_context():
            restored = dict(get_db().execute("SELECT * FROM authorities").fetchone())
            self.assertEqual(restored, authority)
            key = serialization.load_pem_private_key(decrypt_private_key(restored["private_key_pem"]).encode(), password=None)
            self.assertEqual(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), original_key)
            certificate = x509.load_pem_x509_certificate(restored["certificate_pem"].encode())
            self.assertEqual(certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), original_key)
            verify_chain(get_db(), original_secret)
            actions = [row[0] for row in get_db().execute("SELECT action FROM audit_events")]
            self.assertIn("backup.created", actions)
            self.assertIn("backup.restored", actions)
            self.assertEqual(get_db().execute("SELECT value FROM settings WHERE key='listen_address'").fetchone()[0], "127.0.0.1")
        self.assertEqual((fresh_root / "server-tls" / "bootstrap.pem").read_bytes(), tls)
        self.assertIn((fresh_root / "softhsm" / "tokens").as_posix(), (fresh_root / "softhsm" / "softhsm2.conf").read_text())
        self.assertEqual((fresh_root / "softhsm/tokens/token-123/object.object").read_bytes(), b"opaque managed token material")
        restored_client = restored_app.test_client()
        restored_client.set_cookie("session", old_cookie)
        self.assertEqual(restored_client.get("/", base_url=self.base).location, "/login")
        self.assertEqual(self.post(restored_client, "/login", {"username": "admin", "password": self.password}).status_code, 302)
        complete_mfa(restored_client, restored_app)
        self.assertEqual(restored_client.get("/", base_url=self.base).status_code, 200)
        self.assertFalse(list(fresh_root.glob(".restore-*")))

    def test_export_requires_admin_fresh_totp_and_never_echoes_passphrase(self):
        response = self.post(self.client, "/settings/backup/export", {"passphrase": PASSPHRASE, "passphrase_confirm": PASSPHRASE, "totp_code": "000000"})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(PASSPHRASE.encode(), response.data)
        code, counter = self.code()
        values = {"passphrase": PASSPHRASE, "passphrase_confirm": PASSPHRASE, "totp_code": code}
        with patch("mfa.time_counter", return_value=counter):
            accepted = self.post(self.client, "/settings/backup/export", values)
            replay = self.post(self.client, "/settings/backup/export", values)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(accepted.headers["Cache-Control"], "no-store")
        self.assertIn(".pkibackup", accepted.headers["Content-Disposition"])
        with self.app.app_context():
            audit = " ".join(row[0] for row in get_db().execute("SELECT detail FROM audit_events"))
            self.assertNotIn(PASSPHRASE, audit)
            get_db().execute("UPDATE users SET role='operator' WHERE username='admin'")
            get_db().commit()
        self.assertEqual(self.client.get("/settings/backup", base_url=self.base).status_code, 403)
        self.assertEqual(self.post(self.client, "/settings/backup/export", values).status_code, 403)

    def test_failed_restore_leaves_fresh_installation_usable_and_installed_restore_is_unavailable(self):
        encrypted = self.export()
        root, app, client = self.fresh()
        original = (root / "runtime-secrets.json").read_bytes()
        result = self.restore(client, encrypted, passphrase="wrong but sufficiently long password")
        self.assertEqual(result.status_code, 400)
        self.assertIn(b"incorrect or the archive", result.data)
        self.assertEqual((root / "runtime-secrets.json").read_bytes(), original)
        self.assertFalse(restore_pending(root))
        self.assertEqual(client.get("/setup", base_url=self.base).status_code, 200)
        self.assertEqual(client.get("/restore", base_url=self.base, environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code, 403)
        self.assertEqual(client.get("/restore", base_url=self.base, headers={"Host": "attacker.example"}).status_code, 403)
        self.assertEqual(self.client.get("/restore", base_url=self.base).status_code, 404)
        self.assertEqual(self.restore(client, encrypted, source_stopped="").status_code, 400)

    def test_restore_rejects_validly_encrypted_archive_with_broken_key_or_audit(self):
        files = unpack_snapshot(decrypt_archive(self.export(), PASSPHRASE))
        broken = dict(files)
        payload = json.loads(broken["runtime-secrets.json"])
        payload["KEY_ENCRYPTION_SECRET"] = "a wrong encryption secret"
        broken["runtime-secrets.json"] = json.dumps(payload).encode()
        for candidate in (broken, {**files, "pkimaster.audit-sealed": b"invalid marker"}):
            root, app, client = self.fresh()
            response = self.restore(client, encrypt_archive(pack_snapshot(candidate), PASSPHRASE))
            self.assertEqual(response.status_code, 400, response.data)
            self.assertFalse(restore_pending(root))
            self.assertFalse(list(root.glob(".restore-*")))

    def test_large_restore_upload_uses_route_limit_and_excludes_runtime_files(self):
        tokens = self.root / "softhsm" / "tokens" / "large-token"
        tokens.mkdir(parents=True)
        (tokens / "object.object").write_bytes(os.urandom(1200 * 1024))
        (self.root / "runtime-https.json").write_text("runtime cache", encoding="utf-8")
        (self.root / "publication.lock").touch()
        encrypted = self.export()
        files = unpack_snapshot(decrypt_archive(encrypted, PASSPHRASE))
        self.assertNotIn("runtime-https.json", files)
        self.assertNotIn("publication.lock", files)
        root, app, client = self.fresh()
        self.assertEqual(self.restore(client, encrypted).status_code, 202)

    def test_recovery_waits_for_background_workers_and_resumes_interrupted_installation(self):
        encrypted = self.export()
        root, app, client = self.fresh()
        self.assertEqual(self.restore(client, encrypted).status_code, 202)
        for name in ("publication.lock", "monitoring.lock", "runtime-startup.lock"):
            with _worker_lock(root / name), self.assertRaises(RestoreBusy):
                apply_pending_restore(root)
            self.assertEqual(json.loads((root / MARKER).read_text())["phase"], "prepared")
        import backup
        real_write = backup._atomic_private
        def fail_database(path, data):
            if path == root / "pkimaster.sqlite":
                raise OSError("simulated disk failure")
            return real_write(path, data)
        with patch("backup._atomic_private", side_effect=fail_database), self.assertRaises(BackupError):
            apply_pending_restore(root)
        self.assertEqual(json.loads((root / MARKER).read_text())["phase"], "installing")
        self.assertTrue(apply_pending_restore(root))
        self.assertFalse(restore_pending(root))
        create_app({"TESTING": True, "INSTANCE_PATH": str(root)})

    def test_staging_rechecks_freshness_under_database_write_lock(self):
        files = unpack_snapshot(decrypt_archive(self.export(), PASSPHRASE))
        with self.app.app_context(), self.assertRaisesRegex(BackupError, "fresh installation"):
            stage_restore(get_db(), files)
        self.assertFalse(restore_pending(self.root))
        self.assertFalse(list(self.root.glob(".restore-*")))

    def test_sqlite_online_snapshot_contains_committed_wal_records(self):
        with self.app.app_context():
            db = get_db()
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("INSERT INTO settings(key,value) VALUES ('wal_backup_probe','committed')")
            db.commit()
            files = unpack_snapshot(create_snapshot(db))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "snapshot.sqlite"
            path.write_bytes(files["pkimaster.sqlite"])
            with closing(sqlite3.connect(path)) as snapshot:
                self.assertEqual(snapshot.execute("SELECT value FROM settings WHERE key='wal_backup_probe'").fetchone()[0], "committed")


if __name__ == "__main__":
    unittest.main()
