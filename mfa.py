"""RFC 6238 TOTP verification and mandatory browser enrollment.

Production credentials use HMAC-SHA256, six digits and 30-second time steps.
This control does not establish BSI certification or phishing resistance.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import closing
from urllib.parse import quote, urlencode

from cryptography.fernet import InvalidToken
from flask import Blueprint, Response, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup
import segno


mfa = Blueprint("mfa", __name__)
PERIOD = 30
ENROLLMENT_SECONDS = 600
THROTTLE_SECONDS = 900
RECOVERY_CODE_COUNT = 10


def init_mfa(app) -> None:
    """Migrate account recovery independently of authentication providers."""
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.execute("BEGIN IMMEDIATE")
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "mfa_pending_token_hash" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN mfa_pending_token_hash TEXT")
        db.execute("""CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            digest TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            used_at INTEGER,
            PRIMARY KEY(user_id, digest)
        )""")
    app.register_blueprint(mfa)


def provisioning_uri(secret: str, username: str, organization: str) -> str:
    """Carry every TOTP parameter so authenticators do not default to SHA-1."""
    # A colon separates issuer and account in the key URI format; neither
    # component may contain another colon, including an encoded one.
    # Bound the label's encoded length so long Unicode names still produce a
    # scannable QR on small screens. The full organization stays in the UI.
    organization_label = organization.replace(":", " ").strip().encode("utf-8")[:40].decode("utf-8", errors="ignore")
    issuer = "PKIMaster (" + organization_label + ")"
    label = quote(issuer, safe="") + ":" + quote(username.replace(":", " "), safe="")
    parameters = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA256", "digits": 6, "period": PERIOD})
    return "otpauth://totp/" + label + "?" + parameters


def _enrollment_page(secret: str | None, *, replacement: bool = False):
    from enterprise import get_setting
    uri = provisioning_uri(secret, g.user["username"], get_setting("organization")) if secret else None
    # Encode locally. Only the encoder's geometric SVG output is marked safe;
    # labels and the copyable URI remain escaped by the template engine.
    qr_svg = Markup(segno.make_qr(uri, error="m").svg_inline(scale=4, border=4, light="white", omitsize=True)) if uri else None
    return render_template("mfa_enroll.html", title="Replace authenticator" if replacement else "Set up authenticator",
                           secret=secret, provisioning_uri=uri, qr_svg=qr_svg, replacement=replacement)


def time_counter(at_time: float | None = None) -> int:
    return int(time.time() if at_time is None else at_time) // PERIOD


def code_at_counter(secret: str, counter: int, *, digits: int = 6, algorithm: str = "sha256") -> str:
    """HOTP construction used by TOTP; see RFC 4226 section 5.3."""
    if digits not in {6, 8} or algorithm not in {"sha1", "sha256", "sha512"} or not 0 <= counter < 2**64:
        raise ValueError("Invalid TOTP parameters.")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    if len(key) < 20:
        raise ValueError("TOTP secrets must contain at least 160 bits.")
    digest = hmac.new(key, counter.to_bytes(8, "big"), getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def totp(secret: str, at_time: float | None = None, *, digits: int = 6, algorithm: str = "sha256") -> str:
    return code_at_counter(secret, time_counter(at_time), digits=digits, algorithm=algorithm)


def verify_totp(secret: str, code: str, last_counter: int, *, window: int = 1) -> int | None:
    """Return the accepted time step; the caller must consume it atomically."""
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = time_counter()
    accepted = None
    for counter in range(max(0, current - window), current + window + 1):
        matches = hmac.compare_digest(code_at_counter(secret, counter), code)
        if matches and counter > last_counter:
            accepted = counter
    return accepted


def encrypt_secret(secret: str) -> str:
    from app import private_key_cipher
    return private_key_cipher().encrypt(("pkimaster-mfa-v1:" + secret).encode("ascii")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    from app import private_key_cipher
    plaintext = private_key_cipher().decrypt(ciphertext.encode("ascii")).decode("ascii")
    if not plaintext.startswith("pkimaster-mfa-v1:"):
        raise ValueError("Invalid MFA credential encoding.")
    return plaintext.removeprefix("pkimaster-mfa-v1:")


def new_enrollment_secret() -> tuple[str, str]:
    """Return a plaintext setup key and its encrypted database representation."""
    secret = base64.b32encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return secret, encrypt_secret(secret)


def _services():
    from enterprise import _db, audit_event
    return _db(), audit_event


def _current_user(db):
    user = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (g.user["id"],)).fetchone()
    if not user or user["session_version"] != session.get("session_version"):
        db.rollback()
        session.clear()
        return None
    return user


def _throttle(db, user_id: int, now: int):
    buckets = (f"mfa:user:{user_id}", "mfa:ip:" + (request.remote_addr or "unknown"))
    entries = [db.execute("SELECT * FROM login_throttles WHERE bucket = ?", (bucket,)).fetchone() for bucket in buckets]
    blocked = any(entry and entry["blocked_until"] > now for entry in entries)
    return buckets, entries, blocked


def _failure(db, audit, user, buckets, entries, now: int) -> None:
    for bucket, entry in zip(buckets, entries):
        within_window = entry and now - entry["window_started"] < THROTTLE_SECONDS
        attempts = entry["attempts"] + 1 if within_window else 1
        started = entry["window_started"] if within_window else now
        limit = 5 if bucket.startswith("mfa:user:") else 20
        blocked_until = now + THROTTLE_SECONDS if attempts >= limit else 0
        db.execute("""INSERT INTO login_throttles (bucket, attempts, window_started, blocked_until)
            VALUES (?, ?, ?, ?) ON CONFLICT(bucket) DO UPDATE SET attempts = excluded.attempts,
            window_started = excluded.window_started, blocked_until = excluded.blocked_until""",
            (bucket, attempts, started, blocked_until))
    audit("session.mfa_failed", "user", str(user["id"]), "Invalid, expired, or replayed code")
    db.commit()


class MfaReauthenticationError(ValueError):
    """A public reauthentication failure; invalid attempts are already committed."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


def verify_reauthentication(db, code: str):
    """Consume a fresh TOTP within the caller's BEGIN IMMEDIATE transaction.

    Success remains uncommitted for the caller's operation. Invalid attempts
    commit their shared throttle and audit event before raising. All callers
    must authenticate before writing anything else in this transaction.
    """
    if not db.in_transaction:
        raise RuntimeError("MFA reauthentication requires a write transaction.")
    from enterprise import audit_event
    user = _current_user(db)
    if user is None or session.get("mfa_verified") is not True or not user["mfa_secret"]:
        raise MfaReauthenticationError("Complete sign-in before changing account security.")
    now = int(time.time())
    buckets, entries, blocked = _throttle(db, user["id"], now)
    if blocked:
        raise MfaReauthenticationError("Too many authentication-code attempts. Try again in 15 minutes.", 429)
    try:
        counter = verify_totp(decrypt_secret(user["mfa_secret"]), code.strip(), user["mfa_last_counter"])
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise MfaReauthenticationError("The stored authenticator credential cannot be read. Contact your installation administrator.", 503) from exc
    if counter is None:
        _failure(db, audit_event, user, buckets, entries, now)
        raise MfaReauthenticationError("Invalid or already used code. Wait for a new code and try again.")
    db.execute("UPDATE users SET mfa_last_counter = ? WHERE id = ?", (counter, user["id"]))
    db.execute("DELETE FROM login_throttles WHERE bucket = ?", (buckets[0],))
    return db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()


def _recovery_digest(user_id: int, value: str) -> str:
    normalized = re.sub(r"[-\s]", "", value).upper()
    # Each code contains 128 random bits. A hash does not permit practical
    # offline guessing and the per-user domain prevents cross-account reuse.
    return hashlib.sha256(f"pkimaster-recovery-v1:{user_id}:{normalized}".encode()).hexdigest()


def _new_recovery_codes(db, user_id: int) -> list[str]:
    codes = []
    db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(16).upper()
        code = "-".join(raw[offset:offset + 8] for offset in range(0, len(raw), 8))
        db.execute("INSERT INTO mfa_recovery_codes (user_id, digest, created_at) VALUES (?, ?, ?)",
                   (user_id, _recovery_digest(user_id, code), int(time.time())))
        codes.append(code)
    return codes


def _verified_session(user, now: int) -> None:
    session.clear()
    session.permanent = True
    session.update(user_id=user["id"], session_version=user["session_version"],
                   password_authenticated=True, mfa_verified=True, last_seen=now)
    g.user = user


def _replacement_started(db, user, *, recovery: bool) -> str:
    secret = base64.b32encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    token = secrets.token_urlsafe(32)
    db.execute("""UPDATE users SET mfa_pending_secret = ?, mfa_pending_created = ?,
        mfa_pending_token_hash = ? WHERE id = ?""",
        (encrypt_secret(secret), int(time.time()), hashlib.sha256(token.encode()).hexdigest(), user["id"]))
    session["mfa_change_token"] = token
    session["mfa_recovery"] = recovery
    return secret


def _replacement_authorized(user, now: int) -> bool:
    token = session.get("mfa_change_token", "")
    digest = hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) else ""
    return bool(user["mfa_secret"] and user["mfa_pending_secret"] and user["mfa_pending_created"]
                and 0 <= now - user["mfa_pending_created"] < ENROLLMENT_SECONDS
                and user["mfa_pending_token_hash"]
                and hmac.compare_digest(user["mfa_pending_token_hash"], digest))


def _verify(enrollment: bool):
    db, audit = _services()
    db.execute("BEGIN IMMEDIATE")
    user = _current_user(db)
    if user is None:
        return redirect(url_for("enterprise.login"))
    now = int(time.time())
    buckets, entries, blocked = _throttle(db, user["id"], now)
    if blocked:
        db.commit()
        response = Response("Too many authentication-code attempts. Try again in 15 minutes.", status=429)
        response.headers["Retry-After"] = str(THROTTLE_SECONDS)
        return response
    if enrollment and user["mfa_secret"]:
        db.rollback()
        return redirect(url_for("mfa.challenge"))
    if not enrollment and not user["mfa_secret"]:
        db.rollback()
        return redirect(url_for("mfa.enroll"))
    ciphertext = user["mfa_pending_secret"] if enrollment else user["mfa_secret"]
    expired = enrollment and (not user["mfa_pending_created"] or now - user["mfa_pending_created"] >= ENROLLMENT_SECONDS)
    if enrollment and expired:
        if session.get("mfa_enrollment_displayed") or session.get("mfa_enrollment_authorized", False):
            _, encrypted_enrollment_secret = new_enrollment_secret()
            db.execute("""UPDATE users SET mfa_pending_secret = ?, mfa_pending_created = ?,
                mfa_pending_token_hash = NULL WHERE id = ?""",
                (encrypted_enrollment_secret, now, user["id"]))
            db.commit()
            session["mfa_enrollment_authorized"] = True
            session.pop("mfa_enrollment_displayed", None)
            flash("Your setup key expired. Scan the refreshed QR code and try again.", "warning")
            return redirect(url_for("mfa.enroll"))
        db.rollback()
        return Response("Authenticator enrollment is unavailable. Ask an administrator for a new setup key.", status=403)
    if not ciphertext:
        db.rollback()
        return Response("Authenticator enrollment is unavailable. Ask an administrator for a new setup key.", status=403)
    try:
        secret = decrypt_secret(ciphertext)
        counter = verify_totp(secret, request.form.get("code", "").strip(), user["mfa_last_counter"])
    except (InvalidToken, ValueError, UnicodeError):
        db.rollback()
        return Response("The stored authenticator credential cannot be read. Contact your installation administrator.", status=503)
    if counter is None:
        _failure(db, audit, user, buckets, entries, now)
        if enrollment:
            flash("Invalid or already used code. Wait for a new code and try again.", "error")
            return _enrollment_page(secret if session.get("mfa_enrollment_displayed") else None), 401
        flash("Invalid or already used code. Wait for a new code and try again.", "error")
        return render_template("mfa_challenge.html", title="Verify authenticator"), 401
    # The write lock covers validation and consumption, across all WSGI workers.
    if enrollment:
        db.execute("""UPDATE users SET mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL,
            mfa_pending_created = NULL, mfa_pending_token_hash = NULL, mfa_last_counter = ?,
            session_version = session_version + 1 WHERE id = ?""",
            (counter, user["id"]))
        audit("user.mfa_enrolled", "user", str(user["id"]))
    else:
        db.execute("UPDATE users SET mfa_last_counter = ? WHERE id = ?", (counter, user["id"]))
    db.execute("DELETE FROM login_throttles WHERE bucket = ?", (buckets[0],))
    audit("session.login", "user", str(user["id"]), "Password and TOTP verified")
    refreshed = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    db.commit()
    # Rotate the signed session and CSRF token after completing authentication.
    _verified_session(refreshed, now)
    flash("Authenticator verified.", "success")
    if enrollment:
        flash("Create your one-use recovery codes under Account security and keep them in a safe place.", "info")
    return redirect(url_for("index"))


@mfa.route("/mfa/enroll", methods=["GET", "POST"])
def enroll():
    if g.user["mfa_secret"]:
        return redirect(url_for("index") if session.get("mfa_verified") is True else url_for("mfa.challenge"))
    if request.method == "POST":
        return _verify(enrollment=True)
    db, _ = _services()
    db.execute("BEGIN IMMEDIATE")
    user = _current_user(db)
    if user is None:
        return redirect(url_for("enterprise.login"))
    # Recheck under the lock; another session may just have completed enrollment.
    if user["mfa_secret"]:
        db.rollback()
        return redirect(url_for("mfa.challenge"))
    now = int(time.time())
    if user["mfa_pending_secret"] and user["mfa_pending_created"] and now - user["mfa_pending_created"] < ENROLLMENT_SECONDS:
        try:
            secret = decrypt_secret(user["mfa_pending_secret"])
        except (InvalidToken, ValueError, UnicodeError):
            db.rollback()
            return Response("The stored authenticator credential cannot be read. Contact your installation administrator.", status=503)
    else:
        db.rollback()
        return Response("Authenticator enrollment is unavailable. Ask an administrator for a new setup key.", status=403)
    db.commit()
    # Only the trusted setup ceremony may display its own key. Keys provisioned
    # by an administrator must be delivered to the user over a separate channel.
    display_secret = None
    if session.pop("mfa_enrollment_authorized", False) or session.get("mfa_enrollment_displayed"):
        display_secret = secret
        session["mfa_enrollment_displayed"] = True
    return _enrollment_page(display_secret)


@mfa.route("/mfa/challenge", methods=["GET", "POST"])
def challenge():
    if session.get("mfa_verified") is True and g.user["mfa_secret"]:
        return redirect(url_for("index"))
    if not g.user["mfa_secret"]:
        return redirect(url_for("mfa.enroll"))
    if session.get("mfa_change_token"):
        return redirect(url_for("mfa.replace"))
    if request.method == "POST":
        return _verify(enrollment=False)
    passkey_available = _services()[0].execute(
        "SELECT 1 FROM passkey_credentials WHERE user_id=? LIMIT 1", (g.user["id"],)
    ).fetchone() is not None
    return render_template("mfa_challenge.html", title="Verify authenticator",
                           passkey_available=passkey_available)


@mfa.route("/account/security", methods=["GET", "POST"])
def account():
    if session.get("mfa_verified") is not True or not g.user["mfa_secret"]:
        return redirect(url_for("mfa.challenge" if g.user["mfa_secret"] else "mfa.enroll"))
    db, audit = _services()
    status = 200
    if request.method == "POST":
        action = request.form.get("action", "")
        if action not in {"generate_recovery", "replace"}:
            return Response("Unknown account-security action.", status=400)
        db.execute("BEGIN IMMEDIATE")
        try:
            user = verify_reauthentication(db, request.form.get("code", ""))
        except MfaReauthenticationError as exc:
            db.rollback()
            if not session.get("user_id"):
                return redirect(url_for("enterprise.login"))
            flash(str(exc), "error")
            status = exc.status_code
        else:
            if action == "replace":
                _replacement_started(db, user, recovery=False)
                audit("user.mfa_change_started", "user", str(user["id"]), "Current authenticator verified")
                db.commit()
                return redirect(url_for("mfa.replace"))
            codes = _new_recovery_codes(db, user["id"])
            # Replacing the recovery set revokes copied sessions and any
            # outstanding replacement flow, including a lost-browser ticket.
            db.execute("""UPDATE users SET session_version = session_version + 1,
                mfa_pending_secret = NULL, mfa_pending_created = NULL,
                mfa_pending_token_hash = NULL WHERE id = ?""", (user["id"],))
            audit("user.mfa_recovery_codes_generated", "user", str(user["id"]), f"{RECOVERY_CODE_COUNT} one-use codes; previous set invalidated")
            refreshed = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            db.commit()
            _verified_session(refreshed, int(time.time()))
            return render_template("mfa_recovery_codes.html", title="Save recovery codes", codes=codes)
    remaining = db.execute("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL", (g.user["id"],)).fetchone()[0]
    response = Response(render_template("mfa_account.html", title="Account security", remaining=remaining), status=status)
    if status == 429:
        response.headers["Retry-After"] = str(THROTTLE_SECONDS)
    return response


@mfa.route("/mfa/recover", methods=["GET", "POST"])
def recover():
    if session.get("mfa_verified") is True:
        return redirect(url_for("mfa.account"))
    if not g.user["mfa_secret"]:
        return redirect(url_for("mfa.enroll"))
    if request.method == "GET":
        return render_template("mfa_recover.html", title="Recover your authenticator")
    db, audit = _services()
    db.execute("BEGIN IMMEDIATE")
    user = _current_user(db)
    if user is None:
        return redirect(url_for("enterprise.login"))
    now = int(time.time())
    buckets, entries, blocked = _throttle(db, user["id"], now)
    if blocked:
        db.rollback()
        return Response("Too many authentication-code attempts. Try again in 15 minutes.", status=429,
                        headers={"Retry-After": str(THROTTLE_SECONDS)})
    code = request.form.get("recovery_code", "")
    # Keep oversized input out of normalization/hashing and use the same
    # throttle as TOTP so alternating methods cannot increase guess limits.
    consumed = 0
    if len(code) <= 100:
        consumed = db.execute("""UPDATE mfa_recovery_codes SET used_at = ?
            WHERE user_id = ? AND digest = ? AND used_at IS NULL""",
            (now, user["id"], _recovery_digest(user["id"], code))).rowcount
    if consumed != 1:
        _failure(db, audit, user, buckets, entries, now)
        flash("Invalid or already used recovery code.", "error")
        return render_template("mfa_recover.html", title="Recover your authenticator"), 401
    # Recovery grants only a bounded, browser-bound replacement flow. It does
    # not unlock PKI operations before a new authenticator is confirmed.
    db.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user["id"],))
    refreshed = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    first_factor_at = session.get("first_factor_at", now)
    session.clear()
    session.permanent = True
    session.update(user_id=refreshed["id"], session_version=refreshed["session_version"],
                   password_authenticated=True, mfa_verified=False, first_factor_at=first_factor_at, last_seen=now)
    _replacement_started(db, refreshed, recovery=True)
    db.execute("DELETE FROM login_throttles WHERE bucket = ?", (buckets[0],))
    audit("user.mfa_recovery_started", "user", str(user["id"]), "One-use recovery code consumed; existing sessions invalidated")
    db.commit()
    g.user = refreshed
    return redirect(url_for("mfa.replace"))


@mfa.route("/mfa/replace", methods=["GET", "POST"])
def replace():
    db, audit = _services()
    db.execute("BEGIN IMMEDIATE")
    user = _current_user(db)
    if user is None:
        return redirect(url_for("enterprise.login"))
    now = int(time.time())
    if not _replacement_authorized(user, now):
        db.rollback()
        session.pop("mfa_change_token", None)
        session.pop("mfa_recovery", None)
        flash("Authenticator replacement has expired or belongs to another sign-in. Verify your current authenticator or use another recovery code.", "warning")
        return redirect(url_for("mfa.account" if session.get("mfa_verified") is True else "mfa.recover"))
    if request.method == "POST" and request.form.get("action") == "cancel":
        db.execute("UPDATE users SET mfa_pending_secret = NULL, mfa_pending_created = NULL, mfa_pending_token_hash = NULL WHERE id = ?", (user["id"],))
        audit("user.mfa_change_cancelled", "user", str(user["id"]))
        db.commit()
        if session.get("mfa_verified") is not True:
            session.clear()
            flash("Authenticator replacement cancelled. The recovery code remains used; your original authenticator is unchanged.", "info")
            return redirect(url_for("enterprise.login"))
        session.pop("mfa_change_token", None)
        session.pop("mfa_recovery", None)
        flash("Authenticator replacement cancelled. Your original authenticator is unchanged.", "info")
        return redirect(url_for("mfa.account"))
    try:
        secret = decrypt_secret(user["mfa_pending_secret"])
    except (InvalidToken, ValueError, UnicodeError):
        db.rollback()
        return Response("The stored authenticator credential cannot be read. Contact your installation administrator.", status=503)
    if request.method == "GET":
        db.rollback()
        return _enrollment_page(secret, replacement=True)
    buckets, entries, blocked = _throttle(db, user["id"], now)
    if blocked:
        db.rollback()
        return Response("Too many authentication-code attempts. Try again in 15 minutes.", status=429,
                        headers={"Retry-After": str(THROTTLE_SECONDS)})
    counter = verify_totp(secret, request.form.get("code", "").strip(), -1)
    if counter is None:
        _failure(db, audit, user, buckets, entries, now)
        flash("Invalid code for the new authenticator. Scan this QR code with SHA-256 support and try a fresh code.", "error")
        return _enrollment_page(secret, replacement=True), 401
    db.execute("""UPDATE users SET mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL,
        mfa_pending_created = NULL, mfa_pending_token_hash = NULL, mfa_last_counter = ?,
        session_version = session_version + 1 WHERE id = ?""", (counter, user["id"]))
    codes = _new_recovery_codes(db, user["id"])
    db.execute("DELETE FROM login_throttles WHERE bucket = ?", (buckets[0],))
    audit("user.mfa_changed", "user", str(user["id"]),
          "Recovery code" if session.get("mfa_recovery") else "Current authenticator verified")
    audit("user.mfa_recovery_codes_generated", "user", str(user["id"]), f"{RECOVERY_CODE_COUNT} one-use codes; previous set invalidated")
    audit("session.login", "user", str(user["id"]), "New authenticator verified; previous sessions invalidated")
    refreshed = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    db.commit()
    _verified_session(refreshed, now)
    flash("Authenticator replaced. Previous sessions and recovery codes have been invalidated.", "success")
    return render_template("mfa_recovery_codes.html", title="Save recovery codes", codes=codes)
