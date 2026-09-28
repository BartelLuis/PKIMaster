"""Real cryptography, revocation policy, scheduled delivery and retention checks."""
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app import authority_block_reason, create_app, get_db
from audit_integrity import AuditIntegrityError
import automation
from backup import (BackupError, RECIPIENT_MAGIC, decrypt_archive, encrypt_archive,
                    encrypt_recipient_archive, recipient_public_key, unpack_snapshot)
from mfa import code_at_counter, decrypt_secret, time_counter
from mfa_helpers import complete_mfa
from monitoring_transports import MonitoringError
import pki


class MemorySFTP:
    def __init__(self):
        self.files = {}
        self.modes = {}
        self.removed = []
        self.renamed = []

    def lstat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=self.modes.get(path, stat.S_IFREG | 0o600), st_size=len(self.files[path]))

    def open(self, path, mode, bufsize=0):
        if mode == "rb":
            return io.BytesIO(self.files[path])
        if path in self.files:
            raise FileExistsError(path)
        self.files[path] = b""
        destination = self.files

        class Writer(io.BytesIO):
            def flush(self):
                destination[path] = self.getvalue()

            def close(self):
                if not self.closed:
                    self.flush()
                super().close()

        return Writer()

    def chmod(self, path, mode):
        self.modes[path] = stat.S_IFREG | mode

    def rename(self, source, target):
        if target in self.files:
            raise FileExistsError(target)
        self.files[target] = self.files.pop(source)
        self.modes[target] = self.modes.pop(source, stat.S_IFREG | 0o600)
        self.renamed.append(target)

    def listdir_iter(self, directory, read_aheads=1):
        for path in list(self.files):
            info = self.lstat(path)
            yield SimpleNamespace(filename=path.rsplit("/", 1)[-1], st_mode=info.st_mode)

    def remove(self, path):
        self.removed.append(path)
        del self.files[path]


class RecipientEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        cls.private = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def test_real_envelope_roundtrip_randomization_and_authenticated_header(self):
        plaintext = b"complete installation secret material"
        value = encrypt_recipient_archive(plaintext, self.public)
        self.assertTrue(value.startswith(RECIPIENT_MAGIC))
        self.assertNotIn(plaintext, value)
        self.assertEqual(decrypt_archive(value, "", recovery_key=self.private), plaintext)
        self.assertNotEqual(value, encrypt_recipient_archive(plaintext, self.public))
        for position in (len(RECIPIENT_MAGIC) + 4, len(RECIPIENT_MAGIC) + 35, len(value) - 1):
            changed = value[:position] + bytes([value[position] ^ 1]) + value[position + 1:]
            with self.assertRaises(BackupError):
                decrypt_archive(changed, "", recovery_key=self.private)
        with self.assertRaises(BackupError):
            decrypt_archive(value, "")
        other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        wrong = other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaises(BackupError):
            decrypt_archive(value, "", recovery_key=wrong)

    def test_encrypted_recovery_private_key_and_manual_v1_remain_supported(self):
        value = encrypt_recipient_archive(b"state", self.public)
        private = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.BestAvailableEncryption(b"external key passphrase"))
        self.assertEqual(decrypt_archive(value, "external key passphrase", recovery_key=private), b"state")
        with self.assertRaises(BackupError):
            decrypt_archive(value, "wrong", recovery_key=private)
        with patch("backup._derive_key", side_effect=lambda password, salt: hashlib.sha256(password.encode() + salt).digest()):
            manual = encrypt_archive(b"manual snapshot", "original long manual passphrase")
            self.assertEqual(decrypt_archive(manual, "original long manual passphrase"), b"manual snapshot")

    def test_recipient_rejects_private_and_weak_or_non_rsa_keys(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elliptic = ec.generate_private_key(ec.SECP256R1())
        for pem in (self.private.decode(), "invalid", *[key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode() for key in (weak, elliptic)]):
            with self.assertRaises(BackupError):
                recipient_public_key(pem)


class AutomationTests(unittest.TestCase):
    base = "https://localhost"

    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.recovery = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.recovery.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        cls.private = cls.recovery.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with patch("pki.generate_private_key", return_value=cls.root_key):
            cls.parent = pki.create_ca_certificate("Automation parent", 365, "root")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.app = create_app({"TESTING": True, "INSTANCE_PATH": str(self.directory)})
        if "automation.settings" not in self.app.view_functions:
            automation.init_automation(self.app)
        self.client = self.app.test_client()
        self.post("/setup", {"username": "admin", "password": "automation administrator passphrase",
                              "password_confirm": "automation administrator passphrase", "organization": "Automation tests"})
        complete_mfa(self.client, self.app)
        self.remote = MemorySFTP()

    def post(self, path, data):
        page = self.client.get("/", base_url=self.base, follow_redirects=True)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        return self.client.post(path, base_url=self.base, data={"csrf_token": token, **data}, follow_redirects=True)

    def configure(self, **changes):
        values = {**automation.DEFAULTS, "installation_id": "a" * 32, "backup_public_key": self.public,
                  "host": "archive.example", "username": "archiver", "directory": "/archive", "auth_method": "password",
                  "host_key_sha256": "SHA256:" + "A" * 43, "password": "test-archive-secret", **changes}
        with self.app.app_context():
            automation._save(values)
            get_db().commit()
        return values

    @contextmanager
    def archive(self, config):
        yield self.remote, "/archive", time.monotonic() + 120

    def cycle(self, **arguments):
        with self.app.app_context(), patch("automation._sftp", self.archive):
            return automation.run_automation_cycle(**arguments)

    def state(self, job):
        with self.app.app_context():
            return dict(get_db().execute("SELECT * FROM automation_jobs WHERE name=?", (job,)).fetchone())

    def authority(self):
        with self.app.app_context():
            return dict(get_db().execute("SELECT * FROM authorities ORDER BY id DESC LIMIT 1").fetchone())

    def activate(self):
        with patch("pki.generate_private_key", return_value=self.key):
            self.post("/authorities", {"name": "Automation CA", "common_name": "Automation CA", "role": "issuing", "validity_days": "90"})
        authority = self.authority()
        signed = pki.sign_ca_request(authority["csr_pem"], "issuing", 90, "root", self.parent[0], self.parent[1])
        fingerprint = x509.load_pem_x509_certificate(self.parent[0].encode()).fingerprint(hashes.SHA256()).hex()
        self.post("/ca/activate", {"certificate_pem": signed[0], "chain_pem": self.parent[0], "trusted_root_sha256": fingerprint})
        self.configure(parent_enabled=True, parent_authority_id=authority["id"], parent_urls=["https://parent.example/crl"])
        return self.authority()

    def test_disabled_jobs_do_not_contact_network(self):
        with patch("automation.http_request") as http, patch("automation._sftp") as sftp:
            self.assertEqual(self.cycle(), {"status": "disabled"})
        http.assert_not_called()
        sftp.assert_not_called()

    def test_parent_crl_validation_rollback_and_permanent_revocation(self):
        authority = self.activate()
        first = pki.build_crl(self.parent[0], self.parent[1], [], 2, 7)
        with patch("automation.http_request", return_value=first) as get:
            self.assertEqual(self.cycle()["status"], "checked")
        get.assert_called_once_with("https://parent.example/crl", limit=4 * 1024 * 1024)
        saved = self.authority()["parent_crls_pem"]
        old = pki.build_crl(self.parent[0], self.parent[1], [], 1, 7)
        with patch("automation.http_request", return_value=old):
            self.assertEqual(self.cycle(force=True)["status"], "failed")
        self.assertEqual(self.authority()["parent_crls_pem"], saved)
        revocations = [{"serial_number": authority["serial_number"], "revoked_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                        "revocation_reason": "ca_compromise"}]
        revoked = pki.build_crl(self.parent[0], self.parent[1], revocations, 3, 7)
        with patch("automation.http_request", return_value=revoked):
            self.assertEqual(self.cycle(force=True)["status"], "checked")
        self.assertIsNotNone(self.authority()["revoked_at"])
        with patch("automation.http_request", return_value=first) as get:
            self.assertEqual(self.cycle(force=True)["status"], "failed")
        get.assert_not_called()
        self.assertIsNotNone(self.authority()["revoked_at"])

    def test_stale_or_wrong_signer_crls_do_not_unblock_ca(self):
        self.activate()
        now = datetime.now(UTC)
        parent = x509.load_pem_x509_certificate(self.parent[0].encode())
        for signing_key, expires in ((self.root_key, now - timedelta(days=1)), (self.key, now + timedelta(days=1))):
            crl = (x509.CertificateRevocationListBuilder().issuer_name(parent.subject)
                   .last_update(now - timedelta(days=2)).next_update(expires)
                   .add_extension(x509.CRLNumber(9), critical=False).sign(signing_key, hashes.SHA256())
                   .public_bytes(serialization.Encoding.DER))
            with patch("automation.http_request", return_value=crl):
                self.assertEqual(self.cycle(force=True)["status"], "failed")
            self.assertEqual(self.authority()["parent_crls_pem"], "")
            self.assertTrue(authority_block_reason(self.authority()))

    def test_encrypted_snapshot_delivered_with_bounded_owned_retention(self):
        self.configure(backup_enabled=True, backup_retention=1)
        foreign = "/archive/pkimaster-backup-" + "b" * 32 + "-20260101t000000000000z-" + "b" * 64 + ".pkibackup"
        unrelated = "/archive/important-document.txt"
        self.remote.files.update({foreign: b"other installation", unrelated: b"unrelated"})
        for _ in range(2):
            self.assertEqual(self.cycle(force=True)["status"], "checked")
        managed = [name for name in self.remote.files if "pkimaster-backup-" + "a" * 32 in name]
        self.assertEqual(len(managed), 1)
        self.assertIn(foreign, self.remote.files)
        self.assertIn(unrelated, self.remote.files)
        self.assertEqual(len(self.remote.removed), 1)
        encrypted = self.remote.files[managed[0]]
        files = unpack_snapshot(decrypt_archive(encrypted, "", recovery_key=self.private))
        self.assertIn("pkimaster.sqlite", files)
        self.assertNotIn(self.private, b"".join(files.values()))
        self.assertEqual(self.remote.modes[managed[0]] & 0o777, 0o600)
        self.assertTrue(self.state("backup")["last_success"])
        with self.app.app_context():
            ciphertext = get_db().execute("SELECT value FROM settings WHERE key='automation_config'").fetchone()[0]
        self.assertNotIn("test-archive-secret", ciphertext)

    def test_audit_delivery_is_verified_immutable_and_detects_external_rollback_checkpoint(self):
        self.configure(audit_enabled=True)
        self.assertEqual(self.cycle()["status"], "checked")
        first = dict(self.remote.files)
        self.assertEqual(len(first), 1)
        name, content = next(iter(first.items()))
        archive = json.loads(content)
        self.assertEqual(archive["checkpoint"]["last_id"], self.state("audit")["last_cursor"])
        self.assertEqual(archive["checkpoint"]["head_hash"], archive["events"][-1]["event_hash"])
        self.assertEqual(self.cycle(force=True)["status"], "checked")
        self.assertEqual(self.remote.files, first)
        self.assertEqual(len(self.remote.renamed), 1)
        cursor = self.state("audit")["last_cursor"]
        conflict = f"/archive/pkimaster-audit-{'a' * 32}-{cursor:020d}-{'0' * 64}.json"
        self.remote.files[conflict] = b"preserved remote evidence"
        self.assertEqual(self.cycle(force=True)["status"], "failed")
        self.assertEqual(self.remote.files[name], content)
        self.assertEqual(self.state("audit")["last_cursor"], cursor)
        self.assertIn("rollback or fork", self.state("audit")["last_error"])

    def test_browser_restores_recipient_backup_using_uploaded_private_key(self):
        self.configure(backup_enabled=True)
        self.assertEqual(self.cycle()["status"], "checked")
        encrypted = next(iter(self.remote.files.values()))
        with tempfile.TemporaryDirectory() as destination:
            restored = create_app({"TESTING": True, "INSTANCE_PATH": destination})
            client = restored.test_client()
            page = client.get("/restore", base_url=self.base)
            token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
            with patch("backup.decrypt_archive") as decrypt:
                rejected = client.post("/restore", base_url=self.base, data={
                    "csrf_token": token, "source_stopped": "on", "expected_sha256": "0" * 64,
                    "archive": (io.BytesIO(encrypted), "scheduled.pkibackup"),
                    "recovery_key": (io.BytesIO(self.private), "private-recovery.pem")})
            self.assertEqual(rejected.status_code, 400)
            decrypt.assert_not_called()
            self.assertFalse((Path(destination) / ".restore-pending.json").exists())
            response = client.post("/restore", base_url=self.base, data={
                "csrf_token": token, "source_stopped": "on", "passphrase": "",
                "expected_sha256": hashlib.sha256(encrypted).hexdigest(),
                "archive": (io.BytesIO(encrypted), "scheduled.pkibackup"),
                "recovery_key": (io.BytesIO(self.private), "private-recovery.pem")})
            self.assertEqual(response.status_code, 202, response.data)
            marker = json.loads((Path(destination) / ".restore-pending.json").read_text())
            self.assertEqual(marker["phase"], "prepared")
            stage = Path(destination) / marker["stage"]
            self.assertTrue((stage / "pkimaster.sqlite").is_file())
            self.assertFalse(any("recovery" in path.name for path in stage.iterdir()))

    def test_failed_transfer_keeps_cursor_and_retries_with_backoff_without_leaking_secrets(self):
        self.configure(audit_enabled=True)
        with patch("automation._external_audit", side_effect=OSError("SFTP secret password token")) as delivery:
            self.assertEqual(self.cycle()["status"], "failed")
            self.assertEqual(self.cycle()["checked"], 0)
            self.assertEqual(delivery.call_count, 1)
        state = self.state("audit")
        self.assertEqual(state["last_cursor"], 0)
        self.assertIsNone(state["last_success"])
        self.assertNotIn("password token", state["last_error"])
        with self.app.app_context():
            findings = automation.automation_findings()
            self.assertEqual({finding["key"] for finding in findings}, {"automation:audit:failure", "automation:audit:overdue"})
        self.assertEqual(self.cycle(force=True)["status"], "checked")
        with self.app.app_context():
            self.assertEqual(automation.automation_findings(), [])

    def test_jobs_share_publication_lock_and_pause_for_restore(self):
        from publication import publication_lock
        self.configure(audit_enabled=True)
        with self.app.app_context(), publication_lock() as acquired:
            self.assertTrue(acquired)
            self.assertEqual(automation.run_automation_cycle(), {"status": "busy"})
        with patch("backup.restore_pending", return_value=True):
            self.assertEqual(self.cycle(), {"status": "restore_pending"})

    def test_corrupt_audit_chain_prevents_external_backup_or_archive(self):
        self.configure(backup_enabled=True, audit_enabled=True)
        with self.app.app_context():
            get_db().execute("UPDATE audit_state SET head_hash=? WHERE id=1", ("0" * 64,))
            get_db().commit()
        with self.assertRaises(AuditIntegrityError):
            self.cycle()
        self.assertFalse(self.remote.files)

    def test_changed_destination_requires_reentered_credentials_and_never_renders_secrets(self):
        config = self.configure(backup_enabled=True)
        data = {**config, "backup_enabled": "on", "backup_interval_hours": "24", "backup_retention": "14",
                "host": "different.example", "password": "", "recovery_key_saved": "on"}
        with self.app.test_request_context("/settings/automation", method="POST", data=data):
            with self.assertRaises(automation.AutomationError):
                automation.form_configuration(config)
        response = self.client.get("/settings/automation", base_url=self.base)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"test-archive-secret", response.data)
        self.assertNotIn(self.private, response.data)
        with self.client.session_transaction() as session:
            session["mfa_verified"] = False
        self.assertNotEqual(self.client.get("/settings/automation", base_url=self.base).status_code, 200)

    def test_configuration_requires_fresh_totp_and_saved_recovery_key_acknowledgment(self):
        config = self.configure()
        form = {**config, "backup_enabled": "on", "recovery_key_saved": "on", "totp_code": "000000"}
        self.assertEqual(self.post("/settings/automation", form).status_code, 401)
        with self.app.app_context():
            self.assertFalse(automation.configuration()["backup_enabled"])
            user = get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone()
            counter = max(time_counter(), user["mfa_last_counter"] + 1)
            form["totp_code"] = code_at_counter(decrypt_secret(user["mfa_secret"]), counter)
        with patch("mfa.time_counter", return_value=counter):
            self.assertEqual(self.post("/settings/automation", form).status_code, 200)
        with self.app.app_context():
            self.assertTrue(automation.configuration()["backup_enabled"])


class ImmutableTransportTests(unittest.TestCase):
    def test_corrupt_readback_never_promotes_and_existing_object_never_overwrites(self):
        remote = MemorySFTP()
        name = "pkimaster-audit-test.json"
        deadline = time.monotonic() + 30
        with patch("automation._remote_digest", return_value="0" * 64):
            with self.assertRaises(automation.AutomationError):
                automation._upload_immutable(remote, "/archive", name, b"valid", deadline)
        self.assertFalse(remote.files)
        self.assertFalse(remote.renamed)
        remote.files["/archive/" + name] = b"old!!"
        with self.assertRaises(automation.AutomationError):
            automation._upload_immutable(remote, "/archive", name, b"valid", deadline)
        self.assertEqual(remote.files["/archive/" + name], b"old!!")

    def test_retention_ignores_symlinks_and_malformed_names(self):
        remote = MemorySFTP()
        installation = "a" * 32
        for index in range(3):
            name = f"/archive/pkimaster-backup-{installation}-20260928t12000{index}000000z-{'b' * 64}.pkibackup"
            remote.files[name] = b"backup"
        link = f"/archive/pkimaster-backup-{installation}-20200101t000000000000z-{'c' * 64}.pkibackup"
        remote.files[link] = b"symlink"
        remote.modes[link] = stat.S_IFLNK | 0o777
        remote.files["/archive/../not-a-backup"] = b"untouched"
        automation._retention(remote, "/archive", installation, 1, time.monotonic() + 30)
        self.assertEqual(len(remote.removed), 2)
        self.assertIn(link, remote.files)
        self.assertIn("/archive/../not-a-backup", remote.files)


if __name__ == "__main__":
    unittest.main()
