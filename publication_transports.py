"""Pinned SFTP publication of public CA artifacts; no ambient SSH credentials."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import ipaddress
import posixpath
import re
import secrets
import stat
import threading
import time
from contextlib import suppress

import paramiko
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

CONNECT_TIMEOUT = 5
IO_TIMEOUT = 10
PUBLISH_TIMEOUT = 60
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
ARTIFACT_ORDER = {"chain.pem": 0, "ca.cer": 1, "ca.crl": 2}
SECRET_FIELDS = {"password", "private_key_pem", "private_key_passphrase"}


class PublicationError(RuntimeError):
    """Safe to display or store: messages never include peer text or credentials."""


def _text(config, field, maximum, *, required=False, strip=True):
    value = config.get(field, "")
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"The SFTP {field.replace('_', ' ')} is invalid or too long.")
    value = value.strip() if strip else value
    if required and not value:
        raise ValueError(f"Provide the SFTP {field.replace('_', ' ')}.")
    return value


def _fingerprint(value):
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}=?", value):
        raise ValueError("Provide the server's OpenSSH SHA256 host-key fingerprint.")
    try:
        raw = base64.b64decode(value.removeprefix("SHA256:").rstrip("=") + "=", validate=True)
    except binascii.Error:
        raise ValueError("The SFTP host-key fingerprint is invalid.") from None
    if len(raw) != 32:
        raise ValueError("The SFTP host-key fingerprint must contain a SHA-256 digest.")
    return "SHA256:" + base64.b64encode(raw).decode().rstrip("=")


def _private_key(config):
    """Parse supported PEM/OpenSSH keys entirely in memory, including PKCS#8."""
    if not config["private_key_pem"]:
        return None
    encoded = config["private_key_pem"].encode("utf-8")
    password = config["private_key_passphrase"].encode("utf-8") or None
    try:
        loader = serialization.load_ssh_private_key if encoded.lstrip().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----") else serialization.load_pem_private_key
        key = loader(encoded, password=password)
        if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
            return paramiko.RSAKey(key=key)
        if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name in {"secp256r1", "secp384r1", "secp521r1"}:
            return paramiko.ECDSAKey(vals=(key, key.public_key()))
        if isinstance(key, ed25519.Ed25519PrivateKey):
            text = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
            return paramiko.Ed25519Key.from_private_key(io.StringIO(text))
        raise ValueError("Unsupported or weak key")
    except (ValueError, TypeError, UnsupportedAlgorithm, paramiko.SSHException):
        raise ValueError("The SSH private key or passphrase is invalid. Use RSA with at least 2048 bits, NIST P-256/P-384/P-521, or Ed25519.") from None


def validate_transport(config: dict) -> dict:
    """Validate without network access. Return only supported normalized fields."""
    if not isinstance(config, dict) or config.get("transport", "sftp") != "sftp":
        raise ValueError("Select SFTP publication.")
    normalized = {"transport": "sftp"}
    host = _text(config, "host", 253, required=True)
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not host.isascii() or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", part) for part in host.rstrip(".").split(".")):
            raise ValueError("The SFTP host must be a DNS name or IP address without a URL, username, or port.") from None
        host = host.lower().rstrip(".")
    normalized["host"] = host
    try:
        port = config.get("port", 22)
        if isinstance(port, bool) or (not isinstance(port, (str, int))) or not re.fullmatch(r"[0-9]{1,5}", str(port)):
            raise ValueError
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("The SFTP port must be between 1 and 65535.") from None
    normalized["port"] = port
    directory = _text(config, "directory", 2048, required=True)
    if (not directory.startswith("/") or "\\" in directory or "//" in directory or any(ord(char) < 32 for char in directory)
            or any(part in {".", ".."} for part in directory.split("/"))):
        raise ValueError("The SFTP directory must be an absolute POSIX path without traversal components.")
    normalized["directory"] = directory.rstrip("/") or "/"
    username = _text(config, "username", 256, required=True)
    if any(ord(char) < 32 for char in username):
        raise ValueError("The SFTP username contains invalid characters.")
    normalized["username"] = username
    normalized["host_key_sha256"] = _fingerprint(_text(config, "host_key_sha256", 64, required=True))
    for field in SECRET_FIELDS:
        normalized[field] = _text(config, field, 65536 if field == "private_key_pem" else 4096, strip=False)
    if not normalized["private_key_pem"] and not normalized["password"]:
        raise ValueError("Provide an SSH private key or password for the SFTP account.")
    if not normalized["private_key_pem"] and normalized["private_key_passphrase"]:
        raise ValueError("An SSH key passphrase requires an SSH private key.")
    _private_key(normalized)
    return normalized


def _artifacts(artifacts):
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= len(ARTIFACT_ORDER):
        raise ValueError("Provide one to three public CA artifacts.")
    names, result = set(), []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str) or artifact["name"] not in ARTIFACT_ORDER or artifact["name"] in names:
            raise ValueError("Publication filenames must be unique ca.crl, ca.cer, or chain.pem.")
        content = artifact.get("content")
        if not isinstance(content, bytes) or not 1 <= len(content) <= MAX_ARTIFACT_BYTES:
            raise ValueError("Each publication artifact must contain between 1 byte and 64 MiB.")
        content_type = artifact.get("content_type", "application/octet-stream")
        if not isinstance(content_type, str) or len(content_type) > 256 or any(ord(char) < 32 for char in content_type):
            raise ValueError("The publication content type is invalid.")
        names.add(artifact["name"])
        result.append({"name": artifact["name"], "content": content})
    return sorted(result, key=lambda artifact: ARTIFACT_ORDER[artifact["name"]])


class _PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        if (key.get_name() == "ssh-rsa" and key.get_bits() < 2048) or key.get_name() not in {
                "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}:
            raise PublicationError("The SFTP server must use RSA with at least 2048 bits, NIST ECDSA, or Ed25519 host keys.")
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if not hmac.compare_digest(self.expected, actual):
            raise PublicationError("The SFTP server host key does not match the configured SHA-256 fingerprint.")
        # This policy is evaluated before SSHClient attempts user authentication.
        # No host key files, SSH agent, or automatically trusted keys are used.


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise PublicationError("SFTP publication exceeded its time limit.")


def _write_temporary(sftp, directory, content, temporary, deadline):
    path = posixpath.join(directory, ".pkimaster-" + secrets.token_hex(16) + ".tmp")
    _check_deadline(deadline)
    with sftp.open(path, "wx", bufsize=0) as output:
        temporary.add(path)  # Only remove paths whose exclusive creation succeeded.
        for offset in range(0, len(content), 32768):
            _check_deadline(deadline)
            output.write(content[offset:offset + 32768])
        output.flush()
    if sftp.stat(path).st_size != len(content):
        raise PublicationError("The SFTP server did not confirm the complete artifact size.")
    return path


def _probe_atomic_replace(sftp, directory, temporary, deadline):
    source = _write_temporary(sftp, directory, b"PKIMaster rename capability probe", temporary, deadline)
    target = _write_temporary(sftp, directory, b"old", temporary, deadline)
    try:
        sftp.posix_rename(source, target)
        temporary.discard(source)
        if sftp.stat(target).st_size != len(b"PKIMaster rename capability probe"):
            raise OSError("Rename probe mismatch")
    except OSError:
        raise PublicationError("The SFTP destination must support atomic POSIX rename over an existing file; publication was refused.") from None
    sftp.remove(target)
    temporary.discard(target)


def publish(config: dict, artifacts: list[dict]) -> None:
    """Stage every artifact, then atomically replace each file with the CRL last.

    A set of files is not one remote transaction. Callers must retry the complete
    snapshot on failure, and record success only after this function returns.
    """
    value = validate_transport(config)
    ordered = _artifacts(artifacts)
    key = _private_key(value)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_PinnedHostKey(value["host_key_sha256"]))
    deadline = time.monotonic() + PUBLISH_TIMEOUT
    timer = threading.Timer(PUBLISH_TIMEOUT, client.close)
    timer.daemon = True
    temporary, sftp = set(), None
    timer.start()
    try:
        client.connect(value["host"], port=value["port"], username=value["username"],
                       password=None if key else value["password"], pkey=key,
                       allow_agent=False, look_for_keys=False, timeout=CONNECT_TIMEOUT,
                       banner_timeout=IO_TIMEOUT, auth_timeout=IO_TIMEOUT, channel_timeout=IO_TIMEOUT,
                       disabled_algorithms={"keys": ["ssh-rsa", "ssh-dss"], "pubkeys": ["ssh-rsa", "ssh-dss"],
                                            "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]})
        _check_deadline(deadline)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(IO_TIMEOUT)
        attributes = sftp.stat(value["directory"])
        if attributes.st_mode is None or not stat.S_ISDIR(attributes.st_mode):
            raise PublicationError("The configured SFTP publication directory does not exist or is not a directory.")
        _probe_atomic_replace(sftp, value["directory"], temporary, deadline)
        staged = []
        for artifact in ordered:
            path = _write_temporary(sftp, value["directory"], artifact["content"], temporary, deadline)
            sftp.chmod(path, 0o644)  # These are public certificates and CRLs.
            staged.append((path, posixpath.join(value["directory"], artifact["name"])))
        for source, target in staged:
            _check_deadline(deadline)
            sftp.posix_rename(source, target)
            temporary.discard(source)
    except PublicationError:
        raise
    except paramiko.AuthenticationException:
        raise PublicationError("SFTP authentication failed. Check the configured account and credential.") from None
    except (paramiko.SSHException, OSError, EOFError):
        raise PublicationError("SFTP publication failed. Check connectivity, server identity, permissions, and atomic rename support.") from None
    finally:
        if sftp is not None:
            for path in temporary:
                try:
                    _check_deadline(deadline)
                    sftp.remove(path)
                except (PublicationError, paramiko.SSHException, OSError, EOFError):
                    pass  # A disconnected peer may leave a harmless uniquely named temporary file.
            with suppress(paramiko.SSHException, OSError, EOFError):
                sftp.close()
        timer.cancel()
        with suppress(paramiko.SSHException, OSError, EOFError):
            client.close()
