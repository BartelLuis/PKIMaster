"""Optional WebAuthn passkeys as a phishing-resistant second factor."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import UTC, datetime
from urllib.parse import urlsplit

from flask import Blueprint, Response, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

from enterprise import audit_event, get_setting, require_roles


passkeys = Blueprint("passkeys", __name__)
CEREMONY_SECONDS = 180
MAX_CREDENTIALS_PER_USER = 20


def init_passkeys(app) -> None:
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS passkey_credentials (
            credential_id BLOB PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            credential_data BLOB NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS passkey_credentials_user ON passkey_credentials(user_id, created_at)")
    app.register_blueprint(passkeys)


def _origin_and_rp() -> tuple[str, str]:
    base_url = get_setting("public_base_url", "")
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError("Configure the canonical HTTPS public base URL before using passkeys.")
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = parsed.port
    if port not in {None, 443}:
        hostname += f":{port}"
    return f"https://{hostname}", parsed.hostname.lower()


def _server() -> Fido2Server:
    origin, rp_id = _origin_and_rp()
    return Fido2Server(
        PublicKeyCredentialRpEntity(id=rp_id, name=str(get_setting("organization", "PKIMaster"))[:64]),
        verify_origin=lambda candidate: secrets.compare_digest(candidate, origin),
    )


def _user_handle(user_id: int) -> bytes:
    secret = current_app.config["KEY_ENCRYPTION_SECRET"].encode("utf-8")
    return hmac.new(secret, f"pkimaster-webauthn-user-v1:{user_id}".encode("ascii"), hashlib.sha256).digest()


def _credentials(db, user_id: int) -> list[AttestedCredentialData]:
    values = db.execute("SELECT credential_data FROM passkey_credentials WHERE user_id=? ORDER BY created_at",
                        (user_id,)).fetchall()
    try:
        return [AttestedCredentialData(bytes(row["credential_data"])) for row in values]
    except (ValueError, TypeError) as error:
        current_app.logger.error("Stored passkey data could not be decoded for user id %s", user_id)
        raise RuntimeError("A stored passkey is invalid. Contact your installation administrator.") from error


def _valid_state(name: str, user_id: int) -> dict:
    state = session.pop(name, None)
    if (not isinstance(state, dict) or state.get("user_id") != user_id
            or type(state.get("created")) is not int
            or not 0 <= int(time.time()) - state["created"] <= CEREMONY_SECONDS
            or not isinstance(state.get("state"), dict)):
        raise ValueError("The passkey request expired. Start again.")
    return state["state"]


def _options_response(options) -> Response:
    return jsonify(dict(options)["publicKey"])


@passkeys.get("/account/security/passkeys")
@require_roles("admin", "operator", "auditor")
def manage():
    db = _db()
    rows = db.execute("""SELECT hex(credential_id) AS id,label,created_at
        FROM passkey_credentials WHERE user_id=? ORDER BY created_at""", (g.user["id"],)).fetchall()
    return render_template("passkeys.html", title="Passkeys", credentials=rows)


@passkeys.post("/account/security/passkeys/register/begin")
@require_roles("admin", "operator", "auditor")
def register_begin():
    from fido2.webauthn import ResidentKeyRequirement
    db = _db()
    try:
        if not request.is_secure:
            raise ValueError("Passkey ceremonies require HTTPS.")
        origin, _ = _origin_and_rp()
        existing = _credentials(db, g.user["id"])
        if len(existing) >= MAX_CREDENTIALS_PER_USER:
            raise ValueError("This account already has the maximum number of passkeys.")
        options, state = _server().register_begin(
            PublicKeyCredentialUserEntity(
                id=_user_handle(g.user["id"]), name=g.user["username"],
                display_name=g.user["username"][:64],
            ),
            credentials=existing,
            resident_key_requirement=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session["passkey_register_state"] = {"user_id": g.user["id"], "created": int(time.time()), "state": state}
        session["passkey_register_origin"] = origin
        return _options_response(options)
    except (ValueError, RuntimeError) as error:
        return jsonify(error=str(error)), 400


@passkeys.post("/account/security/passkeys/register/complete")
@require_roles("admin", "operator", "auditor")
def register_complete():
    from app import get_db
    from mfa import MfaReauthenticationError, verify_reauthentication
    db = get_db()
    try:
        if not request.is_secure:
            raise ValueError("Passkey ceremonies require HTTPS.")
        raw = request.form.get("credential_json", "")
        label = request.form.get("label", "").strip()
        if not raw or len(raw) > 65536 or not label or len(label) > 80:
            raise ValueError("Enter a passkey label and complete the passkey request.")
        response = json.loads(raw)
        db.execute("BEGIN IMMEDIATE")
        verify_reauthentication(db, request.form.get("totp_code", "").strip())
        state = _valid_state("passkey_register_state", g.user["id"])
        session.pop("passkey_register_origin", None)
        registered = _server().register_complete(state, response)
        credential_data = registered.credential_data
        if credential_data is None:
            raise ValueError("The authenticator returned no passkey credential.")
        count = db.execute("SELECT COUNT(*) FROM passkey_credentials WHERE user_id=?",
                           (g.user["id"],)).fetchone()[0]
        if count >= MAX_CREDENTIALS_PER_USER:
            raise ValueError("This account already has the maximum number of passkeys.")
        db.execute("""INSERT INTO passkey_credentials
            (credential_id,user_id,credential_data,sign_count,label,created_at)
            VALUES (?,?,?,?,?,?)""",
            (credential_data.credential_id, g.user["id"], bytes(credential_data),
             registered.counter, label, datetime.now(UTC).isoformat()))
        audit_event("user.passkey_added", "user", str(g.user["id"]), "label=" + label)
        db.commit()
        return jsonify(message="Passkey added.")
    except MfaReauthenticationError as error:
        db.rollback()
        return jsonify(error=str(error)), error.status_code
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(error="This passkey is already registered."), 400
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, RuntimeError, sqlite3.Error) as error:
        db.rollback()
        return jsonify(error=str(error) if isinstance(error, ValueError) else "The passkey could not be registered."), 400


@passkeys.post("/account/security/passkeys/remove")
@require_roles("admin", "operator", "auditor")
def remove():
    from app import get_db
    from mfa import MfaReauthenticationError, verify_reauthentication
    db = get_db()
    try:
        identifier = request.form.get("credential_id", "")
        if len(identifier) != 64 or any(character not in "0123456789abcdefABCDEF" for character in identifier):
            raise ValueError("Select a valid passkey.")
        db.execute("BEGIN IMMEDIATE")
        verify_reauthentication(db, request.form.get("totp_code", "").strip())
        cursor = db.execute("DELETE FROM passkey_credentials WHERE credential_id=? AND user_id=?",
                            (bytes.fromhex(identifier), g.user["id"]))
        if not cursor.rowcount:
            raise ValueError("That passkey no longer exists.")
        audit_event("user.passkey_removed", "user", str(g.user["id"]))
        db.commit()
        flash("Passkey removed.", "success")
        return redirect(url_for("passkeys.manage"))
    except MfaReauthenticationError as error:
        db.rollback()
        flash(str(error), "error")
        return redirect(url_for("passkeys.manage")), error.status_code
    except (ValueError, sqlite3.Error) as error:
        db.rollback()
        flash(str(error) if isinstance(error, ValueError) else "The passkey could not be removed.", "error")
        return redirect(url_for("passkeys.manage")), 400


@passkeys.post("/mfa/passkeys/authenticate/begin")
def authenticate_begin():
    from app import get_db
    from mfa import _throttle
    db = get_db()
    try:
        if not request.is_secure:
            raise ValueError("Passkey ceremonies require HTTPS.")
        origin, _ = _origin_and_rp()
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT * FROM users WHERE id=? AND active=1", (g.user["id"],)).fetchone()
        if not user or session.get("password_authenticated") is not True or session.get("mfa_verified") is True:
            db.rollback()
            return jsonify(error="Sign in with your password before using a passkey."), 403
        _, _, blocked = _throttle(db, user["id"], int(time.time()))
        if blocked:
            db.commit()
            return jsonify(error="Too many authentication attempts. Try again later."), 429
        credentials = _credentials(db, user["id"])
        if not credentials:
            db.rollback()
            return jsonify(error="No passkey is registered for this account."), 404
        options, state = _server().authenticate_begin(
            credentials=credentials, user_verification=UserVerificationRequirement.REQUIRED)
        session["passkey_auth_state"] = {"user_id": user["id"], "created": int(time.time()), "state": state}
        session["passkey_auth_origin"] = origin
        db.commit()
        return _options_response(options)
    except (ValueError, RuntimeError) as error:
        db.rollback()
        return jsonify(error=str(error)), 400


@passkeys.post("/mfa/passkeys/authenticate/complete")
def authenticate_complete():
    from app import get_db
    from mfa import _failure, _throttle, _verified_session
    db = get_db()
    try:
        if not request.is_secure:
            raise ValueError("Passkey ceremonies require HTTPS.")
        raw = request.form.get("credential_json", "")
        if not raw or len(raw) > 65536:
            raise ValueError("The passkey response is invalid.")
        response = json.loads(raw)
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT * FROM users WHERE id=? AND active=1", (g.user["id"],)).fetchone()
        if not user or session.get("password_authenticated") is not True or session.get("mfa_verified") is True:
            db.rollback()
            return jsonify(error="Sign in with your password before using a passkey."), 403
        buckets, entries, blocked = _throttle(db, user["id"], int(time.time()))
        if blocked:
            db.commit()
            return jsonify(error="Too many authentication attempts. Try again later."), 429
        state = _valid_state("passkey_auth_state", user["id"])
        session.pop("passkey_auth_origin", None)
        credentials = _credentials(db, user["id"])
        server = _server()
        credential = server.authenticate_complete(state, credentials, response)
        assertion = AuthenticationResponse.from_dict(response)
        count = assertion.response.authenticator_data.counter
        saved = db.execute("SELECT sign_count FROM passkey_credentials WHERE credential_id=? AND user_id=?",
                           (credential.credential_id, user["id"])).fetchone()
        if not saved or (count != 0 and count <= saved["sign_count"]):
            raise ValueError("The authenticator counter is invalid or replayed.")
        db.execute("UPDATE passkey_credentials SET sign_count=? WHERE credential_id=? AND user_id=?",
                   (max(count, saved["sign_count"]), credential.credential_id, user["id"]))
        db.execute("DELETE FROM login_throttles WHERE bucket=?", (buckets[0],))
        audit_event("session.login", "user", str(user["id"]), "Password and WebAuthn passkey verified")
        refreshed = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        db.commit()
        _verified_session(refreshed, int(time.time()))
        return jsonify(redirect=url_for("index"))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, RuntimeError, sqlite3.Error) as error:
        if db.in_transaction:
            user = db.execute("SELECT * FROM users WHERE id=? AND active=1", (g.user["id"],)).fetchone()
            if user and not isinstance(error, sqlite3.Error):
                buckets, entries, blocked = _throttle(db, user["id"], int(time.time()))
                if not blocked:
                    _failure(db, audit_event, user, buckets, entries, int(time.time()))
                else:
                    db.commit()
            else:
                db.rollback()
        current_app.logger.info("WebAuthn passkey authentication failed for user id %s", g.user["id"])
        return jsonify(error="Passkey verification failed. Try again or use your authenticator code."), 401


def _db():
    from app import get_db
    return get_db()
