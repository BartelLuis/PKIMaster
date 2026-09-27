"""Browser-managed installation, identity, policy, and audit storage."""
from __future__ import annotations

import ipaddress
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import ssl
import tempfile
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


DEFAULT_SETTINGS = {
    "organization": "PKIMaster",
    "public_base_url": "",
    "max_leaf_days": "397",
    "crl_days": "7",
    "allow_key_export": "false",
    "session_minutes": "30",
    "listen_address": "127.0.0.1",
    "https_port": "8443",
}
ROLES = {"admin", "operator", "auditor"}
enterprise = Blueprint("enterprise", __name__)


def _db():
    from app import get_db
    return get_db()


def _read_secrets(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or any(
            not isinstance(payload.get(key), str) or not payload[key].strip()
            for key in ("SECRET_KEY", "KEY_ENCRYPTION_SECRET")
        ):
            raise ValueError("Incomplete secret file")
        return {key: payload[key] for key in ("SECRET_KEY", "KEY_ENCRYPTION_SECRET")}
    except (ValueError, OSError) as exc:
        raise RuntimeError("Runtime secrets cannot be read. Restore runtime-secrets.json from the installation backup.") from exc


def configure_runtime(app) -> None:
    """Persist independent secrets before opening the PKI database; never silently rotate keys."""
    directory = Path(app.config["INSTANCE_PATH"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_path = directory / "runtime-secrets.json"
    supplied = {key: app.config.get(key) for key in ("SECRET_KEY", "KEY_ENCRYPTION_SECRET")}
    if secret_path.exists():
        payload = _read_secrets(secret_path)
        for key, value in supplied.items():
            if value and value != payload[key]:
                raise RuntimeError(f"{key} conflicts with the persisted installation secret. Restore the original configuration.")
        database = Path(app.config["DATABASE"])
        if database.exists() and database.stat().st_size > 0:
            _verify_existing_keys(database, payload["KEY_ENCRYPTION_SECRET"])
    else:
        # Import legacy deployment secrets once; all future starts use the persisted file.
        for key, filename in (("SECRET_KEY", ".dev-secret-key"), ("KEY_ENCRYPTION_SECRET", ".dev-key-encryption-secret")):
            legacy_path = directory / filename
            if not supplied[key]:
                supplied[key] = os.environ.get("PKIMASTER_" + key) or (legacy_path.read_text(encoding="utf-8").strip() if legacy_path.is_file() else None)
        database = Path(app.config["DATABASE"])
        existing_database = database.exists() and database.stat().st_size > 0
        encryption_secret = supplied["KEY_ENCRYPTION_SECRET"]
        if existing_database and not encryption_secret:
            # The original application used SECRET_KEY for encryption when no independent key was set.
            encryption_secret = supplied["SECRET_KEY"]
        if existing_database and not encryption_secret:
            raise RuntimeError("The database exists but its encryption secret is missing. Restore runtime-secrets.json or supply the original encryption secret to migrate.")
        payload = {
            "SECRET_KEY": supplied["SECRET_KEY"] or secrets.token_urlsafe(48),
            "KEY_ENCRYPTION_SECRET": encryption_secret or secrets.token_urlsafe(48),
        }
        if existing_database:
            _verify_existing_keys(database, payload["KEY_ENCRYPTION_SECRET"])
        # Publish a fully written file without replacing a concurrent installer's secrets.
        descriptor, temporary_name = tempfile.mkstemp(prefix=".runtime-secrets-", dir=directory)
        temporary = Path(temporary_name)
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(payload, output)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, secret_path)
            except FileExistsError:
                payload = _read_secrets(secret_path)
                for key, value in supplied.items():
                    if value and value != payload[key]:
                        raise RuntimeError("Concurrent installation created different runtime secrets.")
        finally:
            temporary.unlink(missing_ok=True)
    if os.name != "nt":
        secret_path.chmod(0o600)
    app.config.update(payload)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_REFRESH_EACH_REQUEST=True)
    # Flask defines this key as False by default; the application chooses a secure default before this call.
    if not app.config.get("MAX_CONTENT_LENGTH"):
        app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


def _verify_existing_keys(database: Path, secret: str) -> None:
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(str(secret).encode("utf-8")).digest()))
    try:
        with closing(sqlite3.connect(database)) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            for table in ("authorities", "certificates"):
                if table in tables:
                    for row in connection.execute(f"SELECT private_key_pem FROM {table} WHERE private_key_pem IS NOT NULL AND private_key_pem != ''"):
                        cipher.decrypt(row[0].encode("utf-8"))
            if "users" in tables:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
                for column in ("mfa_secret", "mfa_pending_secret"):
                    if column in columns:
                        for row in connection.execute(f"SELECT {column} FROM users WHERE {column} IS NOT NULL"):
                            cipher.decrypt(row[0].encode("utf-8"))
            if "settings" in tables:
                for row in connection.execute("SELECT value FROM settings WHERE key IN ('key_storage_config', 'publication_config')"):
                    cipher.decrypt(row[0].encode("utf-8"))
            if "identity_settings" in tables:
                for row in connection.execute("SELECT payload FROM identity_settings"):
                    payload = json.loads(row[0])
                    for field in ("oidc_client_secret", "ldap_bind_password"):
                        if payload.get(field):
                            cipher.decrypt(payload[field].encode("utf-8"))
            if "oidc_flows" in tables:
                for row in connection.execute("SELECT payload FROM oidc_flows"):
                    cipher.decrypt(row[0].encode("utf-8"))
    except (sqlite3.Error, InvalidToken, ValueError, AttributeError) as exc:
        raise RuntimeError("The supplied encryption secret cannot decrypt the existing PKI. Restore the original secret before migrating.") from exc


def get_setting(key: str, default=None):
    row = _db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    value = row["value"] if row else DEFAULT_SETTINGS.get(key, default)
    if key == "allow_key_export":
        return str(value).lower() == "true"
    return value


def audit_event(action: str, object_type: str = "", object_id: str = "", detail: str = "") -> None:
    """Append to the caller's transaction. Never include passwords or key material."""
    user = getattr(g, "user", None)
    from audit_integrity import append_event
    append_event(_db(), current_app.config["KEY_ENCRYPTION_SECRET"],
                 actor_id=user["id"] if user else None, actor_name=user["username"] if user else "anonymous",
                 action=action, object_type=object_type, object_id=str(object_id), detail=detail,
                 remote_addr=request.remote_addr or "")


def can_manage(*roles: str) -> bool:
    user = getattr(g, "user", None)
    return bool(user and user["mfa_secret"] and session.get("mfa_verified") is True and user["role"] in (roles or ("admin",)))


def require_roles(*roles: str):
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if not can_manage(*roles):
                abort(403)
            return function(*args, **kwargs)
        return wrapped
    return decorator


def _is_loopback(address: str | None) -> bool:
    try:
        parsed = ipaddress.ip_address(address or "")
        return parsed.is_loopback or bool(getattr(parsed, "ipv4_mapped", None) and parsed.ipv4_mapped.is_loopback)
    except ValueError:
        return False


def _local_setup_request() -> bool:
    try:
        hostname = urlsplit("//" + request.host).hostname
        return _is_loopback(request.remote_addr) and (hostname == "localhost" or _is_loopback(hostname))
    except ValueError:
        return False


def _validate_password(password: str) -> None:
    if len(password) < 14 or len(password) > 256:
        raise ValueError("Use a password or passphrase between 14 and 256 characters.")


def _validate_username(username: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{2,63}", username):
        raise ValueError("Usernames must contain 3–64 letters, numbers, dots, hyphens, underscores, or @.")


def _validate_public_url(raw: str) -> str:
    value = raw.strip().rstrip("/")
    if not value:
        return ""
    if not value.isascii():
        raise ValueError("The public URL must use ASCII characters; use the IDNA hostname and percent-encode any non-ASCII path characters.")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The public URL has an invalid port.") from exc
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(character.isspace() for character in value)
            or "\\" in value or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("Enter an absolute HTTPS URL without credentials, query parameters, or a fragment.")
    if parsed.scheme != "https" and parsed.hostname != "localhost" and not _is_loopback(parsed.hostname):
        raise ValueError("The public URL must use HTTPS; HTTP is allowed only on localhost.")
    return value


def _settings_from_form() -> dict[str, str]:
    organization = request.form.get("organization", "").strip()
    if not organization or len(organization) > 200:
        raise ValueError("Provide an organization name with at most 200 characters.")
    values = {"organization": organization, "public_base_url": _validate_public_url(request.form.get("public_base_url", ""))}
    for key, minimum, maximum in (("max_leaf_days", 1, 825), ("crl_days", 1, 30), ("session_minutes", 5, 480), ("https_port", 1024, 65535)):
        try:
            value = int(request.form.get(key, DEFAULT_SETTINGS[key]))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key.replace('_', ' ').capitalize()} must be a whole number.") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{key.replace('_', ' ').capitalize()} must be between {minimum} and {maximum}.")
        values[key] = str(value)
    values["allow_key_export"] = "true" if request.form.get("allow_key_export") == "on" else "false"
    try:
        values["listen_address"] = str(ipaddress.ip_address(request.form.get("listen_address", DEFAULT_SETTINGS["listen_address"]).strip()))
    except ValueError as exc:
        raise ValueError("Listen address must be an IPv4 or IPv6 address, such as 127.0.0.1 or 0.0.0.0.") from exc
    return values


def _tls_upload() -> bytes | None:
    certificate_upload = request.files.get("tls_certificate")
    private_key_upload = request.files.get("tls_private_key")
    if not certificate_upload and not private_key_upload:
        return None
    if not certificate_upload or not private_key_upload:
        raise ValueError("Upload both the HTTPS certificate chain and its private key.")
    certificate_bytes = certificate_upload.read(65537)
    private_key_bytes = private_key_upload.read(65537)
    if max(len(certificate_bytes), len(private_key_bytes)) > 65536:
        raise ValueError("Each HTTPS certificate or key file must be 64 KiB or smaller.")
    try:
        certificates = x509.load_pem_x509_certificates(certificate_bytes)
        certificate = certificates[0]
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        if isinstance(private_key, rsa.RSAPrivateKey):
            strong_key = private_key.key_size >= 2048
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            strong_key = private_key.key_size >= 256
        else:
            strong_key = False
        if not strong_key:
            raise ValueError("Use an RSA key of at least 2048 bits or an EC key of at least 256 bits.")
        public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if private_key.public_key().public_bytes(*public_format) != certificate.public_key().public_bytes(*public_format):
            raise ValueError("The HTTPS certificate does not match the uploaded private key.")
        now = datetime.now(UTC)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("The HTTPS certificate is not currently valid.")
        try:
            if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("Use a server certificate, not a CA certificate, for HTTPS.")
        except x509.ExtensionNotFound:
            pass
        alternatives = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if not (alternatives.get_values_for_type(x509.DNSName) or alternatives.get_values_for_type(x509.IPAddress)):
            raise ValueError("The HTTPS certificate must contain at least one DNS name or IP address in its Subject Alternative Name.")
        try:
            purposes = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.SERVER_AUTH not in purposes:
                raise ValueError("The HTTPS certificate must permit TLS server authentication.")
        except x509.ExtensionNotFound:
            pass
        return (private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                + b"".join(entry.public_bytes(serialization.Encoding.PEM) for entry in certificates))
    except (TypeError, IndexError, x509.ExtensionNotFound, UnsupportedAlgorithm) as exc:
        raise ValueError("Upload an unencrypted PEM private key and a PEM server certificate containing a Subject Alternative Name.") from exc


def _install_tls(pem: bytes) -> None:
    directory = Path(current_app.config["INSTANCE_PATH"]) / "server-tls"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=directory)
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(pem)
            output.flush()
            os.fsync(output.fileno())
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(temporary))
        except ssl.SSLError as exc:
            raise ValueError("The HTTPS certificate chain or private key is not supported by the server's TLS configuration.") from exc
        os.replace(temporary, directory / "uploaded.pem")
    finally:
        temporary.unlink(missing_ok=True)


def _write_settings(values: dict) -> None:
    _db().executemany("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", values.items())


def _start_session(user) -> None:
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["session_version"] = user["session_version"]
    session["last_seen"] = int(time.time())
    session["first_factor_at"] = int(time.time())
    session["password_authenticated"] = True
    session["mfa_verified"] = False
    g.user = user


def init_enterprise(app) -> None:
    app.extensions["pkimaster_dummy_password_hash"] = generate_password_hash(secrets.token_urlsafe(32))
    with closing(sqlite3.connect(app.config["DATABASE"])) as connection, connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'auditor')),
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                session_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                actor_id INTEGER,
                actor_name TEXT NOT NULL,
                action TEXT NOT NULL,
                object_type TEXT NOT NULL DEFAULT '',
                object_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                remote_addr TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS login_throttles (
                bucket TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                window_started INTEGER NOT NULL,
                blocked_until INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at);
        """)
        connection.execute("BEGIN IMMEDIATE")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        for name, definition in (("mfa_secret", "TEXT"), ("mfa_pending_secret", "TEXT"),
                                 ("mfa_pending_created", "INTEGER"), ("mfa_last_counter", "INTEGER NOT NULL DEFAULT -1")):
            if name not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        connection.executemany("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", DEFAULT_SETTINGS.items())
        from identity import init_identity
        init_identity(connection)
    app.register_blueprint(enterprise)
    from mfa import mfa
    app.register_blueprint(mfa)
    from identity import identity, public_config, user_allowed
    app.register_blueprint(identity)

    @app.before_request
    def enforce_access():
        from app import validate_csrf
        g.user = None
        endpoint = request.endpoint
        if endpoint is None:
            return None
        if endpoint in {"healthz", "static", "download_crl", "publication.aia"} and request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        installed = _db().execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
        if not installed:
            if not _local_setup_request():
                return Response("Initial setup is available only from localhost. Connect through a local browser or an SSH tunnel.", status=403)
            if endpoint != "enterprise.setup":
                return redirect(url_for("enterprise.setup"))
        elif endpoint == "enterprise.setup":
            return Response("Initial setup has already been completed.", status=404)
        user_id = session.get("user_id")
        if user_id:
            user = _db().execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone()
            timeout = int(get_setting("session_minutes")) * 60
            if (user and user_allowed(user) and session.get("password_authenticated") is True and user["session_version"] == session.get("session_version")
                    and time.time() - session.get("last_seen", 0) < timeout):
                verified = session.get("mfa_verified") is True and bool(user["mfa_secret"])
                if not verified and time.time() - session.get("first_factor_at", 0) >= 600:
                    session.clear()
                    return redirect(url_for("enterprise.login"))
                g.user = user
                session["last_seen"] = int(time.time())
                session.permanent = True
                app.permanent_session_lifetime = timedelta(seconds=timeout)
            else:
                session.clear()
        anonymous_endpoints = {"enterprise.login", "identity.oidc_start", "identity.oidc_callback"}
        if installed and not g.user and endpoint not in anonymous_endpoints:
            return redirect(url_for("enterprise.login"))
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("Origin")
            if origin and origin.rstrip("/").lower() != request.host_url.rstrip("/").lower():
                return Response("Cross-origin form submission is not allowed.", status=403)
            if not validate_csrf():
                return Response("The form expired or its security token is invalid. Reload the page and try again.", status=403)
        factor_endpoints = {"mfa.enroll", "mfa.challenge", "enterprise.logout"}
        if g.user and not (session.get("mfa_verified") is True and g.user["mfa_secret"]) and endpoint not in factor_endpoints:
            return redirect(url_for("mfa.challenge" if g.user["mfa_secret"] else "mfa.enroll"))
        admin_endpoints = {"create_authority", "revoke_authority", "unlock_private_keys", "enterprise.settings", "enterprise.users",
                           "activate_authority", "update_parent_crls", "sign_subordinate", "revoke_subordinate", "approve_subordinate", "reject_subordinate",
                           "identity.settings", "key_storage.settings", "security.policy", "publication.settings", "publication.publish_now"}
        operator_endpoints = {"create_certificate", "revoke_certificate"}
        if endpoint in admin_endpoints and not can_manage("admin"):
            abort(403)
        if endpoint in operator_endpoints and not can_manage("admin", "operator"):
            abort(403)
        if endpoint in {"download_authority", "download_certificate"} and (request.view_args or {}).get("artifact") == "key":
            if not can_manage("admin") or not get_setting("allow_key_export"):
                abort(403)
        known_mutations = admin_endpoints | operator_endpoints | factor_endpoints | {"enterprise.setup", "enterprise.login", "enterprise.password", "identity.oidc_start"}
        if request.method not in {"GET", "HEAD", "OPTIONS"} and endpoint not in known_mutations:
            abort(403)

    @app.after_request
    def secure_responses(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        form_action = "'self'"
        if request.endpoint in {"enterprise.login", "identity.oidc_start"}:
            from identity import form_action_origin
            origin = form_action_origin()
            if origin:
                form_action += " " + origin
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action " + form_action + "; frame-ancestors 'none'; base-uri 'self'")
        if request.endpoint not in {"static", "download_crl", "publication.aia"}:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def identity_context():
        from app import get_csrf_token
        return {"current_user": getattr(g, "user", None), "can_manage": can_manage,
                "settings": {key: get_setting(key) for key in DEFAULT_SETTINGS}, "csrf_token": get_csrf_token,
                "authentication": public_config()}


@enterprise.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            _validate_username(username)
            _validate_password(password)
            if password != request.form.get("password_confirm", ""):
                raise ValueError("The passwords do not match.")
            values = _settings_from_form()
            password_hash = generate_password_hash(password)
            db = _db()
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                db.rollback()
                abort(404)
            cursor = db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", (username, password_hash))
            _write_settings(values)
            g.user = db.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
            audit_event("installation.completed", "user", str(cursor.lastrowid))
            db.commit()
            _start_session(g.user)
            flash("Installation complete. Enroll your authenticator to finish securing the administrator account.", "success")
            return redirect(url_for("mfa.enroll"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("setup.html", title="Set up PKIMaster"), 400
    return render_template("setup.html", title="Set up PKIMaster")


@enterprise.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")
        from identity import password_login
        return password_login(username, password)
    return render_template("login.html", title="Sign in")


@enterprise.post("/logout")
def logout():
    if session.get("mfa_verified") is True and g.user["mfa_secret"]:
        audit_event("session.logout", "user", str(g.user["id"]))
        # Verified sign-out invalidates copied cookies. An incomplete login must
        # not let a password-only actor revoke other fully authenticated sessions.
        _db().execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (g.user["id"],))
        _db().commit()
    session.clear()
    return redirect(url_for("enterprise.login"))


@enterprise.route("/settings", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    if request.method == "POST":
        try:
            values = _settings_from_form()
            tls_pem = _tls_upload()
            previous_crl_days = get_setting("crl_days")
            _write_settings(values)
            if previous_crl_days != values["crl_days"]:
                _db().execute("UPDATE crls SET next_update = NULL")
                from publication import queue_publication
                queue_publication(_db())
            audit_event("settings.updated", "settings", "", json.dumps(values, sort_keys=True))
            if tls_pem:
                _install_tls(tls_pem)
                audit_event("settings.https_certificate_updated", "settings")
            _db().commit()
            flash("Settings saved. The packaged HTTPS service restarts automatically when its listener or certificate changes; reconnect at the configured address and port.", "success")
            return redirect(url_for("enterprise.settings"))
        except ValueError as exc:
            _db().rollback()
            flash(str(exc), "error")
            return render_template("settings.html", title="Settings"), 400
    return render_template("settings.html", title="Settings")


@enterprise.route("/users", methods=["GET", "POST"])
@require_roles("admin")
def users():
    from identity import user_allowed, validate_binding
    db = _db()
    if request.method == "POST":
        try:
            action = request.form.get("action", "create")
            if action == "create":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                role = request.form.get("role", "")
                source = request.form.get("auth_source", "local")
                issuer, subject = validate_binding(source, request.form.get("external_issuer", "").strip(), request.form.get("external_subject", "").strip())
                _validate_username(username)
                if source == "local":
                    _validate_password(password)
                else:
                    password = secrets.token_urlsafe(64)
                if role not in ROLES:
                    raise ValueError("Select a valid role.")
                cursor = db.execute("INSERT INTO users (username, password_hash, role, auth_source, external_issuer, external_subject) VALUES (?, ?, ?, ?, ?, ?)",
                                    (username, generate_password_hash(password), role, source, issuer, subject))
                audit_event("user.created", "user", str(cursor.lastrowid), f"username={username}; role={role}")
            elif action in {"deactivate", "activate", "reset_password"}:
                try:
                    user_id = int(request.form.get("user_id", ""))
                    if not 1 <= user_id <= 9223372036854775807:
                        raise ValueError("User ID is outside the valid range.")
                except ValueError as exc:
                    raise ValueError("Select a valid user.") from exc
                db.execute("BEGIN IMMEDIATE")
                user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                if not user:
                    raise ValueError("The user does not exist.")
                if action == "deactivate":
                    admins = sum(user_allowed(admin) for admin in db.execute("SELECT * FROM users WHERE role = 'admin' AND active = 1"))
                    if user["active"] and user["role"] == "admin" and user_allowed(user) and admins <= 1:
                        raise ValueError("The last active administrator cannot be deactivated.")
                    db.execute("UPDATE users SET active = 0, session_version = session_version + 1 WHERE id = ?", (user_id,))
                elif action == "activate":
                    db.execute("UPDATE users SET active = 1, session_version = session_version + 1 WHERE id = ?", (user_id,))
                else:
                    if user["auth_source"] != "local":
                        raise ValueError("External passwords must be changed at the identity provider.")
                    password = request.form.get("password", "")
                    _validate_password(password)
                    db.execute("UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?", (generate_password_hash(password), user_id))
                audit_event("user." + action, "user", str(user_id))
            else:
                raise ValueError("Unknown user action.")
            db.commit()
            flash("User account updated.", "success")
            return redirect(url_for("enterprise.users"))
        except (ValueError, sqlite3.IntegrityError) as exc:
            db.rollback()
            flash("That username or external identity is already in use." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "error")
            return render_template("users.html", title="Users", users=db.execute("SELECT id, username, role, active, auth_source, external_issuer, external_subject FROM users ORDER BY username").fetchall()), 400
    return render_template("users.html", title="Users", users=db.execute("SELECT id, username, role, active, auth_source, external_issuer, external_subject FROM users ORDER BY username").fetchall())


@enterprise.route("/password", methods=["GET", "POST"])
def password():
    if g.user["auth_source"] != "local":
        return Response("Change your password at the configured identity provider.", 403)
    if request.method == "POST":
        try:
            old_password = request.form.get("current_password", "")
            new_password = request.form.get("password", "")
            if len(old_password) > 256 or not check_password_hash(g.user["password_hash"], old_password):
                raise ValueError("The current password is incorrect.")
            _validate_password(new_password)
            if new_password != request.form.get("password_confirm", ""):
                raise ValueError("The new passwords do not match.")
            _db().execute("UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?", (generate_password_hash(new_password), g.user["id"]))
            audit_event("user.password_changed", "user", str(g.user["id"]))
            _db().commit()
            session.clear()
            flash("Password changed. Sign in again; all previous sessions have been revoked.", "success")
            return redirect(url_for("enterprise.login"))
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("login.html", title="Change password", change_password=True), 400
    return render_template("login.html", title="Change password", change_password=True)


@enterprise.get("/audit")
def audit():
    try:
        before = min(9223372036854775807, max(0, int(request.args.get("before", "0"))))
    except ValueError:
        before = 0
    events = _db().execute("SELECT * FROM audit_events WHERE (? = 0 OR id < ?) ORDER BY id DESC LIMIT 100", (before, before)).fetchall()
    return render_template("audit.html", title="Audit log", events=events, next_before=events[-1]["id"] if len(events) == 100 else None)
