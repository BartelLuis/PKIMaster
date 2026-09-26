"""Packaged HTTPS runtime. Application settings are managed through the web UI."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
import ipaddress
import json
import logging
import os
from pathlib import Path
import signal
import select
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


STATE_DIRECTORY = Path("/var/lib/pkimaster")
LOGGER = logging.getLogger("pkimaster.runtime")


def runtime_application(instance_path: Path = STATE_DIRECTORY):
    from app import create_app

    return create_app({
        "INSTANCE_PATH": str(instance_path),
        "DATABASE": str(instance_path / "pkimaster.sqlite"),
        "SESSION_COOKIE_SECURE": True,
    })


def _atomic_write(path: Path, contents: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".tls-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def ensure_bootstrap_tls(instance_path: Path) -> Path:
    """Create a separate local web identity; never reuse a managed CA key."""
    tls_directory = instance_path / "server-tls"
    tls_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    bundle = tls_directory / "bootstrap.pem"
    now = datetime.now(timezone.utc)
    if bundle.exists():
        certificate = x509.load_pem_x509_certificate(bundle.read_bytes())
        if certificate.not_valid_after_utc > now + timedelta(days=30):
            return bundle
        private_key = serialization.load_pem_private_key(bundle.read_bytes(), password=None)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PKIMaster local console")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    _atomic_write(bundle, private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ) + certificate.public_bytes(serialization.Encoding.PEM))
    return bundle


def read_listener(instance_path: Path) -> tuple[str, int]:
    database = instance_path / "pkimaster.sqlite"
    with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True, timeout=5)) as connection:
        values = dict(connection.execute(
            "SELECT key, value FROM settings WHERE key IN ('listen_address', 'https_port')"
        ).fetchall())
    host = str(ipaddress.ip_address(values.get("listen_address", "127.0.0.1")))
    port = int(values.get("https_port", "8443"))
    if not 1024 <= port <= 65535:
        raise ValueError("The HTTPS listener port must be between 1024 and 65535.")
    return host, port


def tls_bundle(instance_path: Path) -> Path:
    uploaded = instance_path / "server-tls" / "uploaded.pem"
    bundle = uploaded if uploaded.exists() else ensure_bootstrap_tls(instance_path)
    # Also reject malformed certificates and mismatched private keys before restart.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(bundle))
    return bundle


def _ssl_context(config, default_ssl_context_factory):
    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def serve(instance_path: Path = STATE_DIRECTORY, runtime_config: dict | None = None) -> None:
    from gunicorn.app.base import BaseApplication

    application = runtime_application(instance_path)
    if runtime_config is None:
        host, port = read_listener(instance_path)
        bundle = tls_bundle(instance_path)
    else:
        host = str(ipaddress.ip_address(runtime_config["host"]))
        port = int(runtime_config["port"])
        bundle = instance_path / "server-tls" / "runtime.pem"
    options = {
        "bind": f"[{host}]:{port}" if ":" in host else f"{host}:{port}",
        "workers": 2,
        "worker_class": "gthread",
        "threads": 2,
        "timeout": 60,
        "graceful_timeout": 30,
        "keyfile": str(bundle),
        "certfile": str(bundle),
        "ssl_context": _ssl_context,
        "accesslog": "-",
        # Query strings and referers can contain confidential enrollment information.
        "access_log_format": '%(h)s %(t)s "%(m)s %(U)s" %(s)s %(b)s',
        "errorlog": "-",
        "umask": 0o077,
        "forwarded_allow_ips": "",
        "secure_scheme_headers": {},
    }
    if runtime_config is not None:
        def ready(server):
            # Gunicorn calls this only after binding the requested listener.
            os.write(runtime_config["ready_fd"], b"1")
            os.close(runtime_config["ready_fd"])
        options["when_ready"] = ready

    class PKIMasterApplication(BaseApplication):
        def load_config(self):
            for name, value in options.items():
                self.cfg.set(name, value)

        def load(self):
            return application

    PKIMasterApplication().run()


@dataclass(frozen=True)
class _Configuration:
    host: str
    port: int
    pem: bytes = field(repr=False)


def _configuration(instance_path: Path) -> _Configuration:
    host, port = read_listener(instance_path)
    bundle = tls_bundle(instance_path)
    return _Configuration(host, port, bundle.read_bytes())


def _remember_configuration(instance_path: Path, configuration: _Configuration) -> None:
    _atomic_write(instance_path / "runtime-https.json", json.dumps({
        "host": configuration.host, "port": configuration.port,
        "pem": configuration.pem.decode("ascii"),
    }).encode("utf-8"))


def _remembered_configuration(instance_path: Path) -> _Configuration | None:
    path = instance_path / "runtime-https.json"
    if not path.exists():
        return None
    values = json.loads(path.read_text(encoding="utf-8"))
    host = str(ipaddress.ip_address(values["host"]))
    port = int(values["port"])
    if not 1024 <= port <= 65535:
        raise ValueError("The last accepted HTTPS listener has an invalid port.")
    return _Configuration(host, port, values["pem"].encode("ascii"))


def _reject_configuration(instance_path: Path, rejected: _Configuration, active: _Configuration) -> None:
    """Revert a failed web change without overwriting a newer administrator save."""
    with closing(sqlite3.connect(instance_path / "pkimaster.sqlite", timeout=5)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        values = dict(db.execute("SELECT key, value FROM settings WHERE key IN ('listen_address', 'https_port')"))
        if (values.get("listen_address", "127.0.0.1"), values.get("https_port", "8443")) != (rejected.host, str(rejected.port)):
            return
        db.executemany("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [
            ("listen_address", active.host), ("https_port", str(active.port)),
        ])
        # The web handler holds this same database write lock while installing
        # an upload, so a concurrent administrator upload cannot be overwritten.
        uploaded = instance_path / "server-tls" / "uploaded.pem"
        if uploaded.exists() and uploaded.read_bytes() == rejected.pem:
            _atomic_write(uploaded, active.pem)
        from audit_integrity import append_event, verify_chain
        secrets = json.loads((instance_path / "runtime-secrets.json").read_text(encoding="utf-8"))
        verify_chain(db, secrets["KEY_ENCRYPTION_SECRET"])
        append_event(db, secrets["KEY_ENCRYPTION_SECRET"], actor_name="system", action="runtime.listener_rejected", object_type="settings", detail=json.dumps({
                "rejected_address": rejected.host, "rejected_port": rejected.port,
                "restored_address": active.host, "restored_port": active.port,
            }, sort_keys=True))


def _check_bind(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))


def _stop_child(child: subprocess.Popen) -> None:
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=35)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def _start_child(configuration: _Configuration) -> subprocess.Popen:
    # Snapshot the accepted identity, so a subsequent web upload cannot change
    # this process's certificate before the supervisor validates the upload.
    _atomic_write(STATE_DIRECTORY / "server-tls" / "runtime.pem", configuration.pem)
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(STATE_DIRECTORY / "server-tls" / "runtime.pem"))
    read_fd, write_fd = os.pipe()
    try:
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--serve"],
            stdin=subprocess.PIPE, pass_fds=(write_fd,), start_new_session=True,
        )
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
    try:
        child.stdin.write(json.dumps({
            "host": configuration.host, "port": configuration.port, "ready_fd": write_fd,
        }).encode("utf-8"))
        child.stdin.close()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("Gunicorn exited before binding the HTTPS listener.")
            readable, _, _ = select.select([read_fd], [], [], 0.2)
            if readable:
                if os.read(read_fd, 1) == b"1":
                    return child
                raise RuntimeError("Gunicorn closed its readiness channel before starting.")
        raise RuntimeError("Gunicorn did not start its HTTPS listener within 15 seconds.")
    except BaseException:
        _stop_child(child)
        raise
    finally:
        os.close(read_fd)


def supervise() -> None:
    """Apply saved web listener/TLS changes without granting the app root access."""
    os.umask(0o077)
    runtime_application()
    remembered = _remembered_configuration(STATE_DIRECTORY)
    try:
        active = _configuration(STATE_DIRECTORY)
    except (OSError, ValueError, sqlite3.Error):
        if remembered is None:
            raise
        LOGGER.exception("Saved HTTPS settings are unusable; restoring the last accepted listener.")
        active = remembered
    stopping = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopping.set())
    child = None
    rejected = None
    try:
        while not stopping.is_set():
            if child is None or child.poll() is not None:
                if child is not None:
                    LOGGER.error("HTTPS worker exited with status %s; restarting.", child.returncode)
                try:
                    child = _start_child(active)
                except (OSError, RuntimeError):
                    if remembered is None or remembered == active:
                        raise
                    LOGGER.exception("Saved HTTPS listener cannot start; restoring the last accepted listener.")
                    _reject_configuration(STATE_DIRECTORY, active, remembered)
                    active = remembered
                    child = _start_child(active)
                _remember_configuration(STATE_DIRECTORY, active)
                remembered = active
            if stopping.wait(3):
                break
            try:
                updated = _configuration(STATE_DIRECTORY)
                if updated != active and updated != rejected:
                    if (updated.host, updated.port) != (active.host, active.port):
                        # The existing listener can occupy the same port when
                        # moving between loopback and a wildcard address.
                        try:
                            _check_bind(updated.host, 0 if updated.port == active.port else updated.port)
                        except OSError:
                            LOGGER.exception("Rejected an unavailable HTTPS listener; restoring its previous web settings.")
                            _reject_configuration(STATE_DIRECTORY, updated, active)
                            rejected = updated
                            continue
                    LOGGER.info("Applying saved HTTPS settings.")
                    _stop_child(child)
                    child = None
                    try:
                        child = _start_child(updated)
                    except (OSError, RuntimeError):
                        LOGGER.exception("The new HTTPS listener failed; restoring the previous listener and certificate.")
                        _reject_configuration(STATE_DIRECTORY, updated, active)
                        rejected = updated
                        child = _start_child(active)
                    else:
                        active = updated
                        _remember_configuration(STATE_DIRECTORY, active)
                        remembered = active
                        rejected = None
            except (ValueError, OSError, sqlite3.Error):
                LOGGER.exception("Cannot apply saved HTTPS settings; keeping the current listener.")
    finally:
        if child is not None:
            _stop_child(child)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if sys.argv[1:] == ["--serve"]:
        serve(runtime_config=json.load(sys.stdin))
    elif sys.argv[1:]:
        raise SystemExit("PKIMaster is configured in the web console, not through command-line options.")
    else:
        supervise()
