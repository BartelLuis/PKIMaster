"""Bounded, TLS-verified monitoring retrieval and notification delivery."""
from __future__ import annotations

from email.message import EmailMessage
import hashlib
import http.client
import ipaddress
import json
import queue
import re
import smtplib
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit


class MonitoringError(ValueError):
    """A safe diagnostic which never contains provider replies or credentials."""


MAX_DOWNLOAD = 4 * 1024 * 1024
TIMEOUT = 5
_RESOLVERS = threading.BoundedSemaphore(8)
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                          ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def validate_url(value, *, webhook=False):
    try:
        parsed = urlsplit(value)
        if (len(value) > 2048 or not value.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in value)
                or parsed.scheme not in ({"https"} if webhook else {"http", "https"})
                or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.fragment or "%" in parsed.hostname or not 1 <= (parsed.port if parsed.port is not None else 443) <= 65535):
            raise ValueError
        return parsed
    except (ValueError, TypeError) as exc:
        raise MonitoringError("Use an HTTPS URL without credentials or a fragment." if webhook else
                              "Use an HTTP(S) URL without credentials or a fragment.") from exc


def _allowed_address(value):
    address = ipaddress.ip_address(value)
    address = getattr(address, "ipv4_mapped", None) or address
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    return address.is_global or any(address.version == network.version and address in network for network in _PRIVATE_NETWORKS)


def resolve_address(host, port):
    """Resolve once, validate every answer, then pin the connection to that IP."""
    if not _RESOLVERS.acquire(blocking=False):
        raise MonitoringError("Network name resolution is busy. A later check will retry.")
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            result.put(None)
        finally:
            _RESOLVERS.release()

    threading.Thread(target=resolve, daemon=True).start()
    try:
        answers = result.get(timeout=TIMEOUT)
    except queue.Empty as exc:
        raise MonitoringError("Network name resolution timed out.") from exc
    if not answers:
        raise MonitoringError("The configured network host could not be resolved.")
    addresses = [answer[4][0] for answer in answers]
    if any(not _allowed_address(address) for address in addresses):
        raise MonitoringError("Loopback, link-local, metadata and reserved network destinations are not allowed.")
    return addresses[0]


def _deadline_timer(connection, seconds):
    def terminate():
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()
    timer = threading.Timer(max(0.01, seconds), terminate)
    timer.daemon = True
    timer.start()
    return timer


def http_request(url, *, payload=None, headers=None, limit=MAX_DOWNLOAD):
    """No proxies, redirects, ambient credentials, decompression or TLS bypass."""
    parsed = validate_url(url, webhook=payload is not None)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    address = resolve_address(parsed.hostname, port)
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    options = {"timeout": TIMEOUT}
    if parsed.scheme == "https":
        options["context"] = ssl.create_default_context()
    connection = connection_type(parsed.hostname, port, **options)
    # HTTPConnection.connect uses this callable; HTTPSConnection wraps the pinned
    # socket using the original hostname for both SNI and certificate validation.
    connection._create_connection = lambda unused, timeout, source_address=None: socket.create_connection(
        (address, port), timeout, source_address)
    deadline = time.monotonic() + 2 * TIMEOUT
    timer = None
    try:
        connection.connect()
        timer = _deadline_timer(connection.sock, deadline - time.monotonic())
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        request_headers = {"User-Agent": "PKIMaster monitoring", "Accept-Encoding": "identity", **(headers or {})}
        connection.request("GET" if payload is None else "POST", path, body=payload, headers=request_headers)
        response = connection.getresponse()
        if not (response.status == 200 if payload is None else 200 <= response.status < 300):
            raise MonitoringError(f"The configured HTTP endpoint returned status {response.status}; redirects are not followed.")
        if payload is not None:
            return b""
        if response.getheader("Content-Encoding", "identity").lower() not in {"", "identity"}:
            raise MonitoringError("The public CRL endpoint must return an uncompressed CRL.")
        content = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise MonitoringError("The public CRL download exceeded its time limit.")
            chunk = response.read1(min(65536, limit + 1 - len(content)))
            if not chunk:
                return bytes(content)
            content.extend(chunk)
            if len(content) > limit:
                raise MonitoringError("The public CRL exceeds the 4 MiB download limit.")
    except (OSError, http.client.HTTPException) as exc:
        raise MonitoringError("The configured HTTP endpoint is unavailable or its TLS certificate could not be verified.") from exc
    finally:
        if timer:
            timer.cancel()
        connection.close()


def validate_email(value):
    if len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
        raise MonitoringError("Use plain email addresses without display names or line breaks.")
    return value


class _SMTPDeadline:
    def _bound_socket(self, connection):
        self._monitoring_timer = _deadline_timer(connection, 20)
        return connection

    def close(self):
        timer = getattr(self, "_monitoring_timer", None)
        if timer:
            timer.cancel()
        super().close()


class _PinnedSMTP(_SMTPDeadline, smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return self._bound_socket(socket.create_connection((resolve_address(host, port), port), timeout))

    def starttls(self, **kwargs):
        # STARTTLS replaces the socket; the old timer must follow that replacement.
        timer = self._monitoring_timer
        result = super().starttls(**kwargs)
        timer.cancel()
        self._bound_socket(self.sock)
        return result


class _PinnedSMTPSSL(_SMTPDeadline, smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        connection = socket.create_connection((resolve_address(host, port), port), timeout)
        try:
            return self._bound_socket(self.context.wrap_socket(connection, server_hostname=host))
        except BaseException:
            connection.close()
            raise


def deliver(config, events):
    """A stable event ID permits receivers to deduplicate an ambiguous retry."""
    payload = {"application": "PKIMaster", "events": events}
    identifier = hashlib.sha256("\n".join(event["id"] for event in events).encode()).hexdigest()
    if config["channel"] == "webhook":
        headers = {"Content-Type": "application/json", "Idempotency-Key": identifier}
        if config.get("webhook_token"):
            headers["Authorization"] = "Bearer " + config["webhook_token"]
        http_request(config["webhook_url"], payload=json.dumps(payload, sort_keys=True).encode(), headers=headers)
        return
    if config["channel"] != "email":
        raise MonitoringError("Select an email or webhook notification channel.")
    message = EmailMessage()
    message["From"] = config["smtp_sender"]
    message["To"] = ", ".join(config["smtp_recipients"])
    message["Subject"] = f"PKIMaster: {len(events)} monitoring update(s)"
    message["Message-ID"] = f"<{identifier}@pkimaster.local>"
    message.set_content("\n\n".join(f"{event['status'].upper()}: {event['title']}\n{event['detail']}\nEvent: {event['id']}" for event in events))
    try:
        context = ssl.create_default_context()
        smtp_type = _PinnedSMTPSSL if config["smtp_security"] == "tls" else _PinnedSMTP
        options = {"timeout": TIMEOUT}
        if config["smtp_security"] == "tls":
            options["context"] = context
        with smtp_type(config["smtp_host"], config["smtp_port"], **options) as connection:
            if config["smtp_security"] == "starttls":
                connection.starttls(context=context)
            if config.get("smtp_username"):
                connection.login(config["smtp_username"], config["smtp_password"])
            rejected = connection.send_message(message)
            if rejected:
                raise MonitoringError("The SMTP server rejected one or more notification recipients.")
    except (OSError, smtplib.SMTPException) as exc:
        raise MonitoringError("Email delivery failed. Check the SMTP connection, TLS trust and credentials.") from exc
