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
import time

from cryptography.fernet import InvalidToken
from flask import Blueprint, Response, flash, g, redirect, render_template, request, session, url_for


mfa = Blueprint("mfa", __name__)
PERIOD = 30
ENROLLMENT_SECONDS = 600
THROTTLE_SECONDS = 900


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
    if not ciphertext or expired:
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
        flash("Invalid or already used code. Wait for a new code and try again.")
        return render_template("mfa_enroll.html" if enrollment else "mfa_challenge.html",
                               title="Set up authenticator" if enrollment else "Verify authenticator", secret=None), 401
    # The write lock covers validation and consumption, across all WSGI workers.
    if enrollment:
        db.execute("""UPDATE users SET mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL,
            mfa_pending_created = NULL, mfa_last_counter = ?, session_version = session_version + 1 WHERE id = ?""",
            (counter, user["id"]))
        audit("user.mfa_enrolled", "user", str(user["id"]))
    else:
        db.execute("UPDATE users SET mfa_last_counter = ? WHERE id = ?", (counter, user["id"]))
    db.execute("DELETE FROM login_throttles WHERE bucket = ?", (buckets[0],))
    audit("session.login", "user", str(user["id"]), "Password and TOTP verified")
    refreshed = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    db.commit()
    # Rotate the signed session and CSRF token after completing authentication.
    session.clear()
    session.permanent = True
    session.update(user_id=refreshed["id"], session_version=refreshed["session_version"],
                   password_authenticated=True, mfa_verified=True, last_seen=now)
    g.user = refreshed
    flash("Authenticator verified.")
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
    display_secret = secret if session.pop("mfa_enrollment_authorized", False) else None
    return render_template("mfa_enroll.html", title="Set up authenticator", secret=display_secret)


@mfa.route("/mfa/challenge", methods=["GET", "POST"])
def challenge():
    if session.get("mfa_verified") is True and g.user["mfa_secret"]:
        return redirect(url_for("index"))
    if not g.user["mfa_secret"]:
        return redirect(url_for("mfa.enroll"))
    if request.method == "POST":
        return _verify(enrollment=False)
    return render_template("mfa_challenge.html", title="Verify authenticator")
