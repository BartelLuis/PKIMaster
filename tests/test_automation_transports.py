"""Exercise immutable archive transfers against a real isolated SSH/SFTP peer."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa

import automation
from publication_transports import PublicationError
from test_publication_transports import Filesystem, LocalSFTP


class ArchiveFilesystem(Filesystem):
    def open(self, path, flags, attributes):
        if not flags & (os.O_WRONLY | os.O_RDWR):
            try:
                descriptor = os.open(self.path(path), flags | getattr(os, "O_BINARY", 0))
                handle = paramiko.SFTPHandle(flags)
                handle.readfile = os.fdopen(descriptor, "rb", buffering=0)
                return handle
            except OSError as exc:
                return paramiko.SFTPServer.convert_errno(exc.errno)
        return super().open(path, flags, attributes)

    def list_folder(self, path):
        result = []
        for child in self.path(path).iterdir():
            entry = paramiko.SFTPAttributes.from_stat(child.lstat())
            entry.filename = child.name
            result.append(entry)
        return result

    def rename(self, source, destination):
        try:
            if self.path(destination).exists():
                return paramiko.SFTP_FAILURE
            self.path(source).rename(self.path(destination))
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)


class ArchiveTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey(key=rsa.generate_private_key(public_exponent=65537, key_size=3072))

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.server = LocalSFTP(directory.name, self.key)
        self.addCleanup(self.server.close)

    def test_real_sftp_verified_upload_idempotent_retry_and_non_overwrite(self):
        content = b"encrypted archive fixture" * 10000
        name = "pkimaster-backup-transfer-test.pkibackup"
        with patch("test_publication_transports.Filesystem", ArchiveFilesystem), patch("automation.resolve_address", return_value="127.0.0.1"):
            with automation._sftp(self.server.config()) as (sftp, directory, deadline):
                automation._upload_immutable(sftp, directory, name, content, deadline)
                automation._upload_immutable(sftp, directory, name, content, deadline)
                with self.assertRaises(automation.AutomationError):
                    automation._upload_immutable(sftp, directory, name, b"changed", deadline)
                self.assertEqual([entry.filename for entry in automation._remote_entries(sftp, directory, deadline)], [name])
        self.assertEqual((self.server.root / "public" / name).read_bytes(), content)
        self.assertEqual(self.server.auth_attempts, ["password"])

    def test_wrong_host_key_is_rejected_before_authentication(self):
        value = {**self.server.config(), "host_key_sha256": "SHA256:" + "A" * 43}
        with patch("automation.resolve_address", return_value="127.0.0.1"):
            with self.assertRaises(PublicationError):
                with automation._sftp(value):
                    self.fail("Connection with an incorrect host fingerprint was accepted")
        self.assertFalse(self.server.auth_attempts)
        self.assertFalse(list((self.server.root / "public").iterdir()))


if __name__ == "__main__":
    unittest.main()
