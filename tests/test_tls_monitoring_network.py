"""Verify actual TLS handshakes, SNI, hostname checks and certificate trust."""
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from monitoring_transports import MonitoringError
from tls_monitoring import inspect_endpoint


def _test_ca(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256()))
    return key, certificate


class TLSMonitoringHandshakeTests(unittest.TestCase):
    hostname = "service.example.test"

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        issuer_key, issuer = _test_ca("TLS monitoring test root")
        _, unrelated = _test_ca("Unrelated TLS monitoring test root")
        cls.trust_pem = issuer.public_bytes(serialization.Encoding.PEM).decode()
        cls.unrelated_trust_pem = unrelated.public_bytes(serialization.Encoding.PEM).decode()
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        cls.leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cls.hostname)]))
            .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cls.hostname)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
            .sign(issuer_key, hashes.SHA256()))
        cls.certificate_path = Path(cls.directory.name) / "server-chain.pem"
        cls.key_path = Path(cls.directory.name) / "server-key.pem"
        cls.certificate_path.write_bytes(cls.leaf.public_bytes(serialization.Encoding.PEM) + cls.trust_pem.encode())
        cls.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    @contextmanager
    def tls_server(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.certificate_path, self.key_path)
        observed = {"server_names": [], "errors": []}
        context.set_servername_callback(lambda connection, name, initial: observed["server_names"].append(name))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]

        def serve():
            try:
                raw, _ = listener.accept()
                with raw:
                    raw.settimeout(3)
                    try:
                        with context.wrap_socket(raw, server_side=True):
                            pass
                    except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError):
                        # Certificate rejection sends a TLS alert. Windows may
                        # also reset the connection when the inspection client
                        # closes after reading the certificate, before the
                        # server finishes sending TLS 1.3 session tickets.
                        pass
            except BaseException as error:
                observed["errors"].append(error)

        worker = threading.Thread(target=serve, name="tls-monitoring-test-server", daemon=True)
        worker.start()
        try:
            yield port, observed
        finally:
            worker.join(timeout=5)
            listener.close()
            self.assertFalse(worker.is_alive(), "TLS fixture did not terminate.")
            self.assertEqual(observed["errors"], [])

    def test_matching_hostname_and_trusted_issuer_report_exact_deployed_fingerprint(self):
        with self.tls_server() as (port, observed), patch("tls_monitoring.resolve_address", return_value="127.0.0.1") as resolve:
            result = inspect_endpoint("configured-target.example.test", port, self.hostname, self.trust_pem)
            resolve.assert_called_once_with("configured-target.example.test", port)
        self.assertEqual(observed["server_names"], [self.hostname])
        self.assertEqual(result["sha256"], self.leaf.fingerprint(hashes.SHA256()).hex())
        self.assertEqual(result["not_after"], self.leaf.not_valid_after_utc.isoformat())
        self.assertEqual(result["subject"], self.leaf.subject.rfc4514_string())

    def test_real_handshake_rejects_hostname_mismatch(self):
        with self.tls_server() as (port, observed), patch("tls_monitoring.resolve_address", return_value="127.0.0.1"):
            with self.assertRaisesRegex(MonitoringError, "chain, hostname or validity") as caught:
                inspect_endpoint("configured-target.example.test", port, "wrong.example.test", self.trust_pem)
        self.assertIsInstance(caught.exception.__cause__, ssl.SSLCertVerificationError)
        self.assertIn("hostname", caught.exception.__cause__.verify_message.lower())
        self.assertEqual(observed["server_names"], ["wrong.example.test"])

    def test_real_handshake_rejects_unrelated_ca_even_with_matching_hostname(self):
        with self.tls_server() as (port, observed), patch("tls_monitoring.resolve_address", return_value="127.0.0.1"):
            with self.assertRaisesRegex(MonitoringError, "chain, hostname or validity") as caught:
                inspect_endpoint("configured-target.example.test", port, self.hostname, self.unrelated_trust_pem)
        self.assertIsInstance(caught.exception.__cause__, ssl.SSLCertVerificationError)
        self.assertEqual(observed["server_names"], [self.hostname])


if __name__ == "__main__":
    unittest.main()
