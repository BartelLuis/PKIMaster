"""Credential boundaries, pinned retrieval, TLS, payload bounds and delivery."""
import json
import smtplib
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

import monitoring_transports as transport


class MonitoringTransportTests(unittest.TestCase):
    def resolve(self, addresses):
        answers = [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]
        with patch("monitoring_transports.socket.getaddrinfo", return_value=answers):
            return transport.resolve_address("pki.example", 443)

    def test_private_and_global_destinations_allowed_but_metadata_loopback_and_reserved_blocked(self):
        for address in ("10.4.5.6", "172.20.4.5", "192.168.1.10", "fd12::1", "8.8.8.8", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                self.assertEqual(self.resolve([address]), address)
        for address in ("127.0.0.1", "::1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "fe80::1", "::ffff:127.0.0.1"):
            with self.subTest(address=address), self.assertRaises(transport.MonitoringError):
                self.resolve([address])
        with self.assertRaises(transport.MonitoringError):
            self.resolve(["10.4.5.6", "169.254.169.254"])

    def test_dns_errors_are_sanitized(self):
        with patch("monitoring_transports.socket.getaddrinfo", side_effect=OSError("private resolver diagnostic")):
            with self.assertRaisesRegex(transport.MonitoringError, "could not be resolved") as error:
                transport.resolve_address("pki.example", 443)
        self.assertNotIn("private", str(error.exception))

    def test_url_validation_rejects_credentials_headers_unsafe_schemes_and_bad_ports(self):
        for value in ("file:///etc/passwd", "http://user:password@host/crl", "https://host:0/crl", "https://host:65536/crl",
                      "https://host/crl#fragment", "https://host/crl\r\nX-Header: secret", "https://[fe80::1%25eth0]/crl"):
            with self.subTest(value=value), self.assertRaises(transport.MonitoringError):
                transport.validate_url(value)
        self.assertEqual(transport.validate_url("http://pki.example/ca.crl").hostname, "pki.example")
        with self.assertRaises(transport.MonitoringError):
            transport.validate_url("http://hooks.example/alerts", webhook=True)

    def connection(self, status=200, chunks=(b"crl-content", b""), encoding="identity"):
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = status
        response.getheader.return_value = encoding
        response.read1.side_effect = chunks
        return connection

    def test_https_keeps_original_sni_and_pins_dns_for_the_connection(self):
        connection = self.connection()
        with patch.object(transport, "resolve_address", return_value="10.2.3.4") as resolve:
            with patch("monitoring_transports.http.client.HTTPSConnection", return_value=connection) as factory:
                self.assertEqual(transport.http_request("https://pki.example:8443/ca.crl?version=2"), b"crl-content")
                with patch("monitoring_transports.socket.create_connection") as connect:
                    connection._create_connection(("rebound.example", 8443), 5)
                    connect.assert_called_once_with(("10.2.3.4", 8443), 5, None)
        resolve.assert_called_once_with("pki.example", 8443)
        self.assertEqual(factory.call_args.args, ("pki.example", 8443))
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(connection.request.call_args.args, ("GET", "/ca.crl?version=2"))
        connection.close.assert_called_once()

    def test_redirects_compressed_content_and_oversized_bodies_are_rejected(self):
        for connection, message in ((self.connection(status=302), "redirects"),
                                    (self.connection(encoding="gzip"), "uncompressed"),
                                    (self.connection(chunks=(b"x" * 17,)), "download limit")):
            with self.subTest(message=message), patch.object(transport, "resolve_address", return_value="10.2.3.4"):
                with patch("monitoring_transports.http.client.HTTPSConnection", return_value=connection):
                    with self.assertRaisesRegex(transport.MonitoringError, message):
                        transport.http_request("https://pki.example/ca.crl", limit=16)
            self.assertEqual(connection.request.call_count, 1)

    def test_provider_exceptions_never_disclose_provider_response_or_secrets(self):
        connection = self.connection()
        connection.getresponse.side_effect = OSError("SECRET access token and internal provider diagnostic")
        with patch.object(transport, "resolve_address", return_value="10.2.3.4"):
            with patch("monitoring_transports.http.client.HTTPSConnection", return_value=connection):
                with self.assertRaises(transport.MonitoringError) as error:
                    transport.http_request("https://pki.example/ca.crl")
        self.assertNotIn("SECRET", str(error.exception))

    def events(self):
        return [{"id": "event-123", "status": "active", "severity": "warning", "title": "CA expiry", "detail": "Expires soon."}]

    def test_webhook_delivery_has_stable_event_identity_and_bearer_token(self):
        config = {"channel": "webhook", "webhook_url": "https://hooks.example/alerts", "webhook_token": "separate-secret"}
        with patch.object(transport, "http_request") as request:
            transport.deliver(config, self.events())
            first = request.call_args
            transport.deliver(config, self.events())
            self.assertEqual(request.call_args, first)
        self.assertEqual(json.loads(first.kwargs["payload"])["events"], self.events())
        self.assertEqual(first.kwargs["headers"]["Authorization"], "Bearer separate-secret")
        self.assertEqual(len(first.kwargs["headers"]["Idempotency-Key"]), 64)

    def email_config(self, **updates):
        return {"channel": "email", "smtp_host": "mail.example", "smtp_port": 587, "smtp_security": "starttls",
                "smtp_username": "pki-alerts", "smtp_password": "private-smtp-password", "smtp_sender": "pki@example.net",
                "smtp_recipients": ["ops@example.net"], **updates}

    def test_smtp_uses_verified_starttls_before_authentication_and_stable_message_id(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.send_message.return_value = {}
        with patch.object(transport, "_PinnedSMTP", return_value=client) as factory:
            transport.deliver(self.email_config(), self.events())
        factory.assert_called_once_with("mail.example", 587, timeout=transport.TIMEOUT)
        client.login.assert_called_once_with("pki-alerts", "private-smtp-password")
        self.assertEqual([call[0] for call in client.mock_calls if call[0] in {"starttls", "login", "send_message"}],
                         ["starttls", "login", "send_message"])
        context = client.starttls.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        message = client.send_message.call_args.args[0]
        self.assertIn("event-123", message.get_content())
        self.assertNotIn("private-smtp-password", str(message))
        self.assertIn("@pkimaster.local>", message["Message-ID"])

    def test_implicit_tls_and_partial_recipient_failure_are_handled(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.send_message.return_value = {"ops@example.net": (550, b"SECRET server reply")}
        with patch.object(transport, "_PinnedSMTPSSL", return_value=client) as factory:
            with self.assertRaisesRegex(transport.MonitoringError, "rejected one") as error:
                transport.deliver(self.email_config(smtp_security="tls", smtp_port=465), self.events())
        self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(factory.call_args.kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
        client.starttls.assert_not_called()

    def test_smtp_provider_diagnostics_are_sanitized(self):
        with patch.object(transport, "_PinnedSMTP", side_effect=smtplib.SMTPAuthenticationError(535, b"SECRET provider reply")):
            with self.assertRaises(transport.MonitoringError) as error:
                transport.deliver(self.email_config(), self.events())
        self.assertNotIn("SECRET", str(error.exception))

    def test_email_header_injection_and_display_names_are_rejected(self):
        for value in ("ops@example.net\r\nBcc:other@example.net", "Ops <ops@example.net>", "ops", "", "ops@example.net,other@example.net"):
            with self.subTest(value=value), self.assertRaises(transport.MonitoringError):
                transport.validate_email(value)
        self.assertEqual(transport.validate_email("ops+alerts@mail.example"), "ops+alerts@mail.example")
        with self.assertRaises(transport.MonitoringError):
            transport.validate_email("ops@" + "a" * 240 + "!")


if __name__ == "__main__":
    unittest.main()
