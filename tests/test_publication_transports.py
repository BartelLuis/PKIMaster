"""SFTP transport security tests, including a real isolated Paramiko server."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import paramiko
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from publication_transports import PublicationError, _StrictHostSignatureTransport, _private_key, publish, validate_transport


ARTIFACTS = [{"name": "ca.crl", "content": b"new signed CRL", "content_type": "application/pkix-crl"},
             {"name": "ca.cer", "content": b"new CA certificate", "content_type": "application/pkix-cert"},
             {"name": "chain.pem", "content": b"new certificate chain", "content_type": "application/x-pem-file"}]


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class MismatchedRSAHostKey(paramiko.RSAKey):
    """Malicious server emits a valid signature with an unnegotiated algorithm."""

    def __init__(self, private, signature_algorithm):
        super().__init__(key=private)
        self.private, self.signature_algorithm = private, signature_algorithm

    def sign_ssh_data(self, data, algorithm=None):
        # Construct the wire signature ourselves: Paramiko 5 no longer signs
        # SHA-1, but a hostile peer is not constrained by its implementation.
        digest = {"ssh-rsa": hashes.SHA1, "rsa-sha2-256": hashes.SHA256, "rsa-sha2-512": hashes.SHA512}[self.signature_algorithm]()
        signature = paramiko.Message()
        signature.add_string(self.signature_algorithm)
        signature.add_string(self.private.sign(data, padding.PKCS1v15(), digest))
        return signature


class Authentication(paramiko.ServerInterface):
    def __init__(self, fixture):
        self.fixture = fixture

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_password(self, username, password):
        self.fixture.auth_attempts.append("password")
        self.fixture.stopping.wait(self.fixture.auth_wait)
        return paramiko.AUTH_SUCCESSFUL if username == "publisher" and password == "sftp-test-password" else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.fixture.auth_attempts.append("publickey")
        return paramiko.AUTH_SUCCESSFUL if username == "publisher" and key.asbytes() == self.fixture.user_key else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, channel_id):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class FileHandle(paramiko.SFTPHandle):
    def __init__(self, flags, fixture, filename):
        super().__init__(flags)
        self.fixture, self.filename = fixture, filename

    def write(self, offset, data):
        if self.fixture.interrupt_write and b"new signed CRL" in data:
            # Simulate a partial remote file followed by a failed transfer.
            super().write(offset, data[:3])
            return paramiko.SFTP_FAILURE
        return super().write(offset, data)


class Filesystem(paramiko.SFTPServerInterface):
    def __init__(self, server, *, fixture):
        super().__init__(server)
        self.fixture = fixture

    def path(self, remote):
        path = (self.fixture.root / remote.lstrip("/")).resolve()
        if not path.is_relative_to(self.fixture.root):
            raise PermissionError("Outside fixture directory")
        return path

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(self.path(path).stat())
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    lstat = stat

    def open(self, path, flags, attributes):
        try:
            descriptor = os.open(self.path(path), flags | getattr(os, "O_BINARY", 0), 0o600)
            handle = FileHandle(flags, self.fixture, path)
            handle.writefile = os.fdopen(descriptor, "wb", buffering=0)
            return handle
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def chattr(self, path, attributes):
        try:
            if attributes.st_mode is not None:
                self.path(path).chmod(attributes.st_mode)
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def remove(self, path):
        self.fixture.removed.append(path)
        try:
            self.path(path).unlink()
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def posix_rename(self, oldpath, newpath):
        if not self.fixture.atomic_replace:
            return paramiko.SFTP_OP_UNSUPPORTED
        if self.fixture.reject_crl_promotion and newpath.endswith("/ca.crl"):
            return paramiko.SFTP_FAILURE
        try:
            os.replace(self.path(oldpath), self.path(newpath))
            if not Path(newpath).name.startswith(".pkimaster-"):
                self.fixture.promotions.append(Path(newpath).name)
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)


class LocalSFTP:
    def __init__(self, root, host_key):
        self.root = Path(root).resolve()
        (self.root / "public").mkdir()
        self.host_key, self.user_key = host_key, None
        self.host_key_algorithms = None
        self.atomic_replace, self.interrupt_write, self.reject_crl_promotion = True, False, False
        self.auth_wait = 0
        self.auth_attempts, self.removed, self.promotions, self.transports = [], [], [], []
        self.stopping = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            transport = paramiko.Transport(connection)
            if self.host_key_algorithms:
                transport.get_security_options().key_types = self.host_key_algorithms
            self.transports.append(transport)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Filesystem, fixture=self)
            try:
                transport.start_server(server=Authentication(self))
            except (paramiko.SSHException, OSError, EOFError):
                transport.close()

    def close(self):
        self.stopping.set()
        self.listener.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=5)

    def config(self):
        return {"transport": "sftp", "host": "127.0.0.1", "port": self.port, "directory": "/public",
                "username": "publisher", "password": "sftp-test-password", "host_key_sha256": fingerprint(self.host_key)}


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.host_key = paramiko.RSAKey(key=cls.host_private)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.server = LocalSFTP(self.directory.name, self.host_key)
        self.addCleanup(self.server.close)
        self.config = self.server.config()
        for artifact in ARTIFACTS:
            (self.server.root / "public" / artifact["name"]).write_bytes(b"old " + artifact["name"].encode())

    def assert_no_temporary_files(self):
        self.assertEqual(sorted(path.name for path in (self.server.root / "public").iterdir()), ["ca.cer", "ca.crl", "chain.pem"])

    def assert_old_files(self):
        for artifact in ARTIFACTS:
            self.assertEqual((self.server.root / "public" / artifact["name"]).read_bytes(), b"old " + artifact["name"].encode())

    def test_real_sftp_password_publishes_chain_and_certificate_before_crl(self):
        publish(self.config, ARTIFACTS)
        for artifact in ARTIFACTS:
            self.assertEqual((self.server.root / "public" / artifact["name"]).read_bytes(), artifact["content"])
        self.assertEqual(self.server.promotions, ["chain.pem", "ca.cer", "ca.crl"])
        self.assertEqual(self.server.auth_attempts, ["password"])
        self.assertTrue(all(Path(path).name.startswith(".pkimaster-") for path in self.server.removed))
        self.assert_no_temporary_files()

    def test_valid_rsa_sha256_and_sha512_host_signatures_publish(self):
        for algorithm in ("rsa-sha2-256", "rsa-sha2-512"):
            with self.subTest(algorithm=algorithm):
                self.server.host_key_algorithms = (algorithm,)
                publish(self.config, ARTIFACTS)
                self.assertEqual(self.server.transports[-1].host_key_type, algorithm)
                for artifact in ARTIFACTS:
                    self.assertEqual((self.server.root / "public" / artifact["name"]).read_bytes(), artifact["content"])
                self.assert_no_temporary_files()

    def test_ed25519_and_nist_ecdsa_host_signatures_publish(self):
        for private in (ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP384R1())):
            pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
            self.server.host_key = _private_key(validate_transport(self.config | {"private_key_pem": pem}))
            with self.subTest(algorithm=self.server.host_key.get_name()):
                publish(self.config | {"host_key_sha256": fingerprint(self.server.host_key)}, ARTIFACTS)
                self.assertEqual(self.server.transports[-1].host_key_type, self.server.host_key.get_name())
                self.assertEqual((self.server.root / "public" / "ca.crl").read_bytes(), b"new signed CRL")
                self.assert_no_temporary_files()

    def test_sha1_host_signature_after_sha2_negotiation_rejected_before_authentication(self):
        self.server.host_key = MismatchedRSAHostKey(self.host_private, "ssh-rsa")
        for algorithm in ("rsa-sha2-256", "rsa-sha2-512"):
            with self.subTest(algorithm=algorithm):
                self.server.host_key_algorithms = (algorithm,)
                with self.assertRaisesRegex(PublicationError, "SFTP publication failed"):
                    publish(self.config, ARTIFACTS)
                self.assertEqual(self.server.transports[-1].host_key_type, algorithm)
                self.assertEqual(self.server.auth_attempts, [])
                self.assert_old_files()
                self.assert_no_temporary_files()

    def test_different_sha2_host_signature_also_rejected_before_authentication(self):
        self.server.host_key = MismatchedRSAHostKey(self.host_private, "rsa-sha2-512")
        self.server.host_key_algorithms = ("rsa-sha2-256",)
        with self.assertRaisesRegex(PublicationError, "SFTP publication failed"):
            publish(self.config, ARTIFACTS)
        self.assertEqual(self.server.transports[-1].host_key_type, "rsa-sha2-256")
        self.assertEqual(self.server.auth_attempts, [])
        self.assert_old_files()
        self.assert_no_temporary_files()

    def test_host_key_mismatch_stops_before_sending_authentication(self):
        wrong = self.config | {"host_key_sha256": "SHA256:" + base64.b64encode(b"x" * 32).decode().rstrip("=")}
        with self.assertRaisesRegex(PublicationError, "host key does not match"):
            publish(wrong, ARTIFACTS)
        self.assertEqual(self.server.auth_attempts, [])
        self.assert_old_files()
        self.assert_no_temporary_files()

    def test_pinned_but_weak_server_key_is_rejected_before_authentication(self):
        self.server.host_key = paramiko.RSAKey(key=rsa.generate_private_key(public_exponent=65537, key_size=1024))
        with self.assertRaisesRegex(PublicationError, "at least 2048"):
            publish(self.config | {"host_key_sha256": fingerprint(self.server.host_key)}, ARTIFACTS)
        self.assertEqual(self.server.auth_attempts, [])
        self.assert_old_files()

    def test_unresponsive_authentication_is_bounded_and_preserves_public_files(self):
        self.server.auth_wait = 5
        started = time.monotonic()
        with patch("publication_transports.IO_TIMEOUT", 0.1), patch("publication_transports.PUBLISH_TIMEOUT", 1):
            with self.assertRaises(PublicationError):
                publish(self.config, ARTIFACTS)
        self.assertLess(time.monotonic() - started, 2)
        self.assert_old_files()
        self.assert_no_temporary_files()

    def test_atomic_replace_is_required_before_any_public_artifact_changes(self):
        self.server.atomic_replace = False
        with self.assertRaisesRegex(PublicationError, "atomic POSIX rename"):
            publish(self.config, ARTIFACTS)
        self.assertEqual(self.server.promotions, [])
        self.assert_old_files()
        self.assert_no_temporary_files()
        self.assertTrue(all(Path(path).name.startswith(".pkimaster-") for path in self.server.removed))

    def test_interrupted_staging_preserves_existing_public_crl_and_certificates(self):
        self.server.interrupt_write = True
        with self.assertRaises(PublicationError):
            publish(self.config, ARTIFACTS)
        self.assert_old_files()
        self.assertEqual(self.server.promotions, [])
        self.assert_no_temporary_files()

    def test_failed_crl_promotion_preserves_old_crl_and_full_retry_is_idempotent(self):
        self.server.reject_crl_promotion = True
        with self.assertRaises(PublicationError):
            publish(self.config, ARTIFACTS)
        self.assertEqual((self.server.root / "public" / "ca.crl").read_bytes(), b"old ca.crl")
        self.assertEqual(self.server.promotions, ["chain.pem", "ca.cer"])
        self.server.reject_crl_promotion = False
        publish(self.config, ARTIFACTS)
        for artifact in ARTIFACTS:
            self.assertEqual((self.server.root / "public" / artifact["name"]).read_bytes(), artifact["content"])
        self.assert_no_temporary_files()

    def test_encrypted_ssh_private_key_authentication_and_no_password_fallback(self):
        private = ed25519.Ed25519PrivateKey.generate()
        pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                    serialization.BestAvailableEncryption(b"key-test-passphrase")).decode()
        value = self.config | {"private_key_pem": pem, "private_key_passphrase": "key-test-passphrase"}
        self.server.user_key = _private_key(validate_transport(value)).asbytes()
        publish(value, ARTIFACTS)
        self.assertTrue(self.server.auth_attempts)
        self.assertTrue(all(method == "publickey" for method in self.server.auth_attempts))
        self.server.user_key = None
        self.server.auth_attempts.clear()
        with self.assertRaisesRegex(PublicationError, "authentication failed"):
            publish(value, ARTIFACTS)
        self.assertTrue(all(method == "publickey" for method in self.server.auth_attempts))

    def test_invalid_configuration_is_rejected_without_network_or_secret_echo(self):
        invalid = [{"host": "sftp://server.example"}, {"host": "server.example/path"}, {"port": 0}, {"port": 65536},
                   {"port": 22.5}, {"port": True}, {"directory": "relative"}, {"directory": "/public/../other"},
                   {"directory": "/public\\other"}, {"host_key_sha256": "MD5:abc"}, {"password": ""},
                   {"private_key_pem": "super-sensitive-invalid-key"}, {"username": "bad\nusername"}]
        for updates in invalid:
            with self.subTest(updates=tuple(updates)), patch("publication_transports.paramiko.SSHClient") as client:
                with self.assertRaises(ValueError) as error:
                    publish(self.config | updates, ARTIFACTS)
                self.assertNotIn("super-sensitive-invalid-key", str(error.exception))
                client.assert_not_called()

    def test_artifact_paths_duplicates_and_empty_data_are_rejected_before_connect(self):
        for name in ("../ca.crl", "/ca.crl", "x\\ca.crl", "private.key", "ca.crl\x00"):
            with self.subTest(name=name), patch("publication_transports.paramiko.SSHClient") as client:
                with self.assertRaises(ValueError):
                    publish(self.config, [{"name": name, "content": b"invalid"}])
                client.assert_not_called()
        for artifacts in ([ARTIFACTS[0], ARTIFACTS[0]], [{"name": "ca.crl", "content": b""}], []):
            with self.assertRaises(ValueError):
                publish(self.config, artifacts)

    def test_ssh_has_explicit_timeouts_and_disables_ambient_agent_and_key_lookup(self):
        fake = MagicMock()
        fake.connect.side_effect = OSError("remote may include password=DO-NOT-EXPOSE")
        with patch("publication_transports.paramiko.SSHClient", return_value=fake):
            with self.assertRaises(PublicationError) as error:
                publish(self.config, ARTIFACTS)
        self.assertNotIn("DO-NOT-EXPOSE", str(error.exception))
        self.assertFalse(fake.connect.call_args.kwargs["allow_agent"])
        self.assertFalse(fake.connect.call_args.kwargs["look_for_keys"])
        self.assertIs(fake.connect.call_args.kwargs["transport_factory"], _StrictHostSignatureTransport)
        for category in ("keys", "pubkeys"):
            self.assertIn("ssh-rsa", fake.connect.call_args.kwargs["disabled_algorithms"][category])
        for field in ("timeout", "banner_timeout", "auth_timeout", "channel_timeout"):
            self.assertGreater(fake.connect.call_args.kwargs[field], 0)
        fake.load_system_host_keys.assert_not_called()
        fake.load_host_keys.assert_not_called()
        fake.close.assert_called()

    def test_supported_memory_only_key_formats_and_wrong_passphrase(self):
        for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP384R1())):
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.BestAvailableEncryption(b"passphrase")).decode()
            value = validate_transport(self.config | {"private_key_pem": pem, "private_key_passphrase": "passphrase"})
            self.assertTrue(_private_key(value).can_sign())
            with self.assertRaisesRegex(ValueError, "private key or passphrase is invalid"):
                validate_transport(value | {"private_key_passphrase": "wrong secret"})


class HostSignatureTests(unittest.TestCase):
    def setUp(self):
        local, peer = socket.socketpair()
        self.addCleanup(local.close)  # An unstarted Transport.close() leaves its socket open.
        self.addCleanup(peer.close)
        self.transport = _StrictHostSignatureTransport(local)
        self.addCleanup(self.transport.close)
        self.transport.H = b"local host signature verification test"

    def test_certificate_negotiation_checks_plain_sha2_signature_algorithm(self):
        key = paramiko.RSAKey(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
        for algorithm in ("rsa-sha2-256", "rsa-sha2-512"):
            with self.subTest(algorithm=algorithm):
                self.transport.host_key_type = algorithm + "-cert-v01@openssh.com"
                signature = key.sign_ssh_data(self.transport.H, algorithm=algorithm).asbytes()
                self.transport._verify_key(key.asbytes(), signature)
                self.assertEqual(self.transport.host_key.asbytes(), key.asbytes())

    def test_legacy_unknown_and_malformed_signature_algorithms_fail_closed(self):
        for algorithm in (b"ssh-rsa", b"ssh-rsa-cert-v01@openssh.com", b"ssh-dss", b"unknown-peer-text", b"\xff", b""):
            with self.subTest(algorithm=algorithm):
                self.transport.host_key_type = "rsa-sha2-256"
                signature = paramiko.Message()
                signature.add_string(algorithm)
                signature.add_string(b"untrusted signature bytes")
                with self.assertRaises(paramiko.SSHException) as error:
                    self.transport._verify_key(b"unused host key", signature.asbytes())
                self.assertNotIn("unknown-peer-text", str(error.exception))
        # Even an accidentally enabled legacy negotiation must not permit SHA-1.
        self.transport.host_key_type = "ssh-rsa"
        signature = paramiko.Message()
        signature.add_string("ssh-rsa")
        with self.assertRaises(paramiko.SSHException):
            self.transport._verify_key(b"unused host key", signature.asbytes())


if __name__ == "__main__":
    unittest.main()
