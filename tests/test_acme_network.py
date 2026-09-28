"""Validation performs constrained HTTP/DNS retrieval rather than trusting clients."""
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver

from acme_service import AcmeError, _allowed_address, _b64, validate_dns01, validate_http01


class AcmeNetworkTests(unittest.TestCase):
    def test_private_opt_in_never_allows_metadata_or_loopback(self):
        for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0", "240.0.0.1"):
            self.assertFalse(_allowed_address(address, True), address)
        for address in ("10.1.2.3", "192.168.1.2", "172.16.0.1", "fd00::1", "::ffff:10.1.2.3"):
            self.assertFalse(_allowed_address(address, False), address)
            self.assertTrue(_allowed_address(address, True), address)
        self.assertTrue(_allowed_address("8.8.8.8", False))

    def test_http_pins_dns_result_and_checks_exact_proof(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "identity"
        response.read.return_value = b"token.thumbprint\n"
        with patch("dns.resolver.Resolver") as constructor, patch("http.client.HTTPConnection", return_value=connection) as http, patch("socket.create_connection") as create, patch("monitoring_transports._deadline_timer"):
            constructor.return_value.resolve.side_effect = [["8.8.8.8"], dns.resolver.NoAnswer()]
            validate_http01("app.example.com", "token", "token.thumbprint")
            http.assert_called_once_with("app.example.com", 80, timeout=3)
            connection._create_connection(("attacker.invalid", 443), 3)
            create.assert_called_once_with(("8.8.8.8", 80), 3)
            connection.request.assert_called_once_with("GET", "/.well-known/acme-challenge/token", headers={"User-Agent": "PKIMaster ACME", "Accept-Encoding": "identity"})
            response.read.assert_called_once_with(1025)
            connection.close.assert_called_once()

    def test_http_mixed_private_dns_redirect_mismatch_and_size_rejected(self):
        with patch("dns.resolver.Resolver") as constructor, patch("http.client.HTTPConnection") as http:
            constructor.return_value.resolve.side_effect = [["8.8.8.8", "10.0.0.1"], dns.resolver.NoAnswer()]
            with self.assertRaisesRegex(AcmeError, "disallowed"):
                validate_http01("app.example.com", "token", "proof")
            http.assert_not_called()
        for status, body in ((302, b"proof"), (200, b"different proof"), (200, b"x" * 1025)):
            with self.subTest(status=status, size=len(body)), patch("dns.resolver.Resolver") as constructor, patch("http.client.HTTPConnection") as http, patch("monitoring_transports._deadline_timer"):
                constructor.return_value.resolve.side_effect = [["8.8.8.8"], dns.resolver.NoAnswer()]
                response = http.return_value.getresponse.return_value
                response.status = status
                response.getheader.return_value = "identity"
                response.read.return_value = body
                with self.assertRaises(AcmeError):
                    validate_http01("app.example.com", "token", "proof")

    def test_dns_queries_challenge_name_and_requires_digest_not_key_authorization(self):
        digest = _b64(hashlib.sha256(b"token.thumbprint").digest()).encode()
        with patch("dns.resolver.Resolver") as constructor:
            resolver = constructor.return_value
            resolver.resolve.return_value = [SimpleNamespace(strings=[b"unrelated"]), SimpleNamespace(strings=[digest[:20], digest[20:]])]
            validate_dns01("app.example.com", "token.thumbprint")
            resolver.resolve.assert_called_once_with("_acme-challenge.app.example.com.", "TXT", lifetime=6)
            resolver.resolve.return_value = [SimpleNamespace(strings=[b"token.thumbprint"])]
            with self.assertRaisesRegex(AcmeError, "does not match"):
                validate_dns01("app.example.com", "token.thumbprint")
            resolver.resolve.side_effect = dns.exception.Timeout()
            with self.assertRaisesRegex(AcmeError, "timed out"):
                validate_dns01("app.example.com", "token.thumbprint")


if __name__ == "__main__":
    unittest.main()
