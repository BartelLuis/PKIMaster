"""Web-managed public CA artifacts and a durable, serialized SFTP publisher."""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, Response, current_app, flash, has_request_context, redirect, render_template, request, url_for

from enterprise import audit_event, get_setting, require_roles
from pki import build_crl, validate_publication_url
from publication_transports import PublicationError, SECRET_FIELDS, publish, validate_transport

publication = Blueprint("publication", __name__)
DEFAULTS = {"enabled": False, "transport": "sftp", "crl_url": "", "aia_url": "", "auth_method": "key", "port": 22}


def configuration():
    from app import get_db, private_key_cipher
    row = get_db().execute("SELECT value FROM settings WHERE key='publication_config'").fetchone()
    return {**DEFAULTS, **json.loads(private_key_cipher().decrypt(row[0].encode()))} if row else dict(DEFAULTS)


def _save(values):
    from app import get_db, private_key_cipher
    encrypted = private_key_cipher().encrypt(json.dumps(values).encode()).decode()
    get_db().execute("INSERT INTO settings(key,value) VALUES ('publication_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encrypted,))


def init_publication(app):
    from app import get_db
    with app.app_context():
        db = get_db()
        db.executescript("""CREATE TABLE IF NOT EXISTS publication_state (
            id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL DEFAULT 0,
            published_generation INTEGER NOT NULL DEFAULT 0, last_attempt TEXT, last_success TEXT,
            last_error TEXT NOT NULL DEFAULT '', failures INTEGER NOT NULL DEFAULT 0,
            next_attempt_at REAL NOT NULL DEFAULT 0, last_published_crl_number INTEGER);
            INSERT OR IGNORE INTO publication_state(id) VALUES (1);""")
    app.register_blueprint(publication)


def queue_publication(db):
    """Called in the content mutation's transaction; never performs network I/O."""
    db.execute("UPDATE publication_state SET generation=generation+1, next_attempt_at=0 WHERE id=1")


def reset_for_new_authority(db, authority_id):
    """Retire the old destination in the caller's locked creation transaction."""
    if not db.in_transaction:
        raise RuntimeError("Publication reset requires a transaction.")
    previous = db.execute("SELECT id FROM authorities WHERE id<>? ORDER BY id DESC LIMIT 1", (authority_id,)).fetchone()
    if previous is None:
        return
    config = configuration()
    retired = list(config.get("retired_targets", []))
    retired.append({"authority_id": previous["id"],
                    "crl_url": public_url("crl", previous["id"]) or "",
                    "aia_url": public_url("aia", previous["id"]) or "",
                    **{field: config.get(field, "") for field in ("host", "port", "directory")}})
    _save({**config, "authority_id": authority_id, "retired_targets": retired,
           "enabled": False, "crl_url": "", "aia_url": "", "directory": ""})
    db.execute("""UPDATE publication_state SET published_generation=0, last_attempt=NULL,
        last_success=NULL, last_error='', failures=0, next_attempt_at=0,
        last_published_crl_number=NULL WHERE id=1""")
    _audit("publication.retired", previous["id"], f"replacement_authority={authority_id}; automatic publication disabled")


def public_url(kind, authority_id):
    config = configuration()
    if config.get("authority_id", authority_id) != authority_id:
        config = next((target for target in reversed(config.get("retired_targets", []))
                       if target["authority_id"] == authority_id), {})
    if config.get(kind + "_url"):
        return config[kind + "_url"]
    base = get_setting("public_base_url", "").rstrip("/")
    suffix = f"crl/{authority_id}.crl" if kind == "crl" else f"aia/{authority_id}.cer"
    return base + "/" + suffix if base else None


def _audit(action, authority_id="", detail=""):
    if has_request_context():
        audit_event(action, "publication", str(authority_id), detail)
    else:
        from app import get_db
        from audit_integrity import append_event
        append_event(get_db(), current_app.config["KEY_ENCRYPTION_SECRET"], actor_name="system",
                     action=action, object_type="publication", object_id=str(authority_id), detail=detail)


@contextmanager
def publication_lock():
    """An OS lock outlives no process and cannot expire during an upload."""
    path = Path(current_app.config["INSTANCE_PATH"]) / "publication.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                pass
        else:
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                pass
        yield acquired
    finally:
        if acquired:
            if os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def ensure_crl(db, authority, *, renew=False):
    """Return fresh DER; caller holds BEGIN IMMEDIATE and owns commit/rollback."""
    from key_storage import authority_signing_key
    if not db.in_transaction:
        raise RuntimeError("CRL generation requires a transaction.")
    if authority["state"] != "active":
        raise ValueError("The local CA is awaiting activation.")
    now = datetime.now(UTC)
    cached = db.execute("SELECT * FROM crls WHERE authority_id=?", (authority["id"],)).fetchone()
    if cached and cached["next_update"]:
        crl = x509.load_der_x509_crl(cached["der"])
        threshold = min(timedelta(days=1), (crl.next_update_utc - crl.last_update_utc) / 2) if renew else timedelta(0)
        # At the end of the CA lifetime, do not regenerate an identical expiry every minute.
        capped = crl.next_update_utc == x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).not_valid_after_utc
        if crl.next_update_utc > now and (capped or crl.next_update_utc - now > threshold):
            return cached["der"]
    revoked = db.execute("""SELECT serial_number, revoked_at, revocation_reason FROM certificates
        WHERE authority_id=? AND revoked_at IS NOT NULL UNION ALL
        SELECT serial_number, revoked_at, revocation_reason FROM issued_authorities
        WHERE authority_id=? AND revoked_at IS NOT NULL""", (authority["id"], authority["id"])).fetchall()
    number = (cached["number"] if cached else 0) + 1
    der = build_crl(authority["certificate_pem"], authority_signing_key(authority),
                    [dict(row) for row in revoked], number, int(get_setting("crl_days", 7)))
    next_update = x509.load_der_x509_crl(der).next_update_utc.isoformat()
    db.execute("""INSERT INTO crls(authority_id,number,der,next_update) VALUES (?,?,?,?)
        ON CONFLICT(authority_id) DO UPDATE SET number=excluded.number,der=excluded.der,next_update=excluded.next_update""",
        (authority["id"], number, der, next_update))
    queue_publication(db)
    _audit("crl.published", authority["id"], f"number={number}; entries={len(revoked)}")
    return der


def _record_failure(db, authority_id, message):
    db.rollback()
    db.execute("BEGIN IMMEDIATE")
    failures = db.execute("SELECT failures FROM publication_state WHERE id=1").fetchone()[0] + 1
    delay = min(3600, 60 * 2 ** min(failures - 1, 6))
    db.execute("UPDATE publication_state SET failures=?,last_error=?,last_attempt=?,next_attempt_at=? WHERE id=1",
               (failures, message, datetime.now(UTC).isoformat(), time.time() + delay))
    _audit("publication.failed", authority_id, message)
    db.commit()
    return {"status": "failed"}


def run_publication_cycle():
    """One timer/manual attempt; content changes during upload remain pending."""
    from app import get_db, build_ca_chain, current_authority
    from audit_integrity import verify_chain
    db = get_db()
    with publication_lock() as acquired:
        if not acquired:
            return {"status": "busy"}
        config = configuration()
        if not config["enabled"]:
            return {"status": "disabled"}
        verify_chain(db, current_app.config["KEY_ENCRYPTION_SECRET"])
        db.execute("BEGIN IMMEDIATE")
        state = db.execute("SELECT * FROM publication_state WHERE id=1").fetchone()
        if state["next_attempt_at"] > time.time():
            db.rollback()
            return {"status": "waiting"}
        authority = current_authority(db)
        if authority is None:
            # Continue serving a retired CA until its replacement is initialized.
            authority = db.execute("SELECT * FROM authorities ORDER BY id DESC LIMIT 1").fetchone()
        if not authority or authority["state"] != "active":
            db.rollback()
            return {"status": "waiting"}
        try:
            der = ensure_crl(db, authority, renew=True)
            state = db.execute("SELECT * FROM publication_state WHERE id=1").fetchone()
            if state["generation"] <= state["published_generation"]:
                db.commit()
                return {"status": "idle"}
            generation = state["generation"]
            number = db.execute("SELECT number FROM crls WHERE authority_id=?", (authority["id"],)).fetchone()[0]
            artifacts = [
                {"name": "ca.cer", "content": x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER), "content_type": "application/pkix-cert"},
                {"name": "chain.pem", "content": build_ca_chain(authority["id"]).encode(), "content_type": "application/x-pem-file"},
                {"name": "ca.crl", "content": der, "content_type": "application/pkix-crl"},
            ]
            db.execute("UPDATE publication_state SET last_attempt=? WHERE id=1", (datetime.now(UTC).isoformat(),))
            _audit("publication.attempted", authority["id"], f"generation={generation}; crl={number}")
            db.commit()
        except Exception:
            return _record_failure(db, authority["id"], "Public artifacts could not be prepared. Check CA validity and signing-provider availability.")
        try:
            publish(config, artifacts)
        except PublicationError as exc:
            return _record_failure(db, authority["id"], str(exc))
        except Exception:
            return _record_failure(db, authority["id"], "SFTP publication failed. Check the destination and credentials.")
        db.execute("BEGIN IMMEDIATE")
        db.execute("""UPDATE publication_state SET published_generation=?,last_success=?,last_error='',failures=0,
            next_attempt_at=0,last_published_crl_number=? WHERE id=1""", (generation, datetime.now(UTC).isoformat(), number))
        _audit("publication.succeeded", authority["id"], f"generation={generation}; crl={number}")
        db.commit()
        return {"status": "published", "generation": generation, "crl_number": number}


def _url_location(value):
    parsed = urlsplit(value)
    return (parsed.scheme.lower(), parsed.hostname.lower(),
            parsed.port or (443 if parsed.scheme.lower() == "https" else 80), unquote(parsed.path or "/"))


def _validate_retired_targets(values, *, destination=False):
    for retired in values.get("retired_targets", []):
        old_urls = {_url_location(retired[field]) for field in ("crl_url", "aia_url") if retired.get(field)}
        if any(values.get(field) and _url_location(values[field]) in old_urls for field in ("crl_url", "aia_url")):
            raise ValueError("Use new CRL and AIA URLs for the replacement CA. Retired CA URLs must remain available for its certificates.")
        if (destination and retired.get("host") and retired.get("directory")
                and all(str(values.get(field, "")) == str(retired.get(field, "")) for field in ("host", "port", "directory"))):
            raise ValueError("Use a different SFTP directory or server for the replacement CA to preserve the retired CA's public files.")


def _form_configuration(saved):
    values = dict(saved)
    values["enabled"] = request.form.get("enabled") == "on"
    for field in ("crl_url", "aia_url"):
        values[field] = request.form.get(field, "").strip()
        if values[field]:
            validate_publication_url(values[field], label="CRL" if field == "crl_url" else "AIA")
            if "?" in values[field]:
                raise ValueError("Public artifact URLs must not contain query parameters.")
    _validate_retired_targets(values)
    # Disabling must remain possible even if credentials are no longer usable.
    if not values["enabled"]:
        return values
    if not values["crl_url"] or not values["aia_url"] or values["crl_url"] == values["aia_url"]:
        raise ValueError("Provide distinct public HTTP(S) URLs for ca.crl and ca.cer before enabling SFTP.")
    for field in ("host", "port", "directory", "username", "host_key_sha256"):
        values[field] = request.form.get(field, "").strip()
    method = request.form.get("auth_method", "key")
    if method not in {"password", "key"}:
        raise ValueError("Select password or SSH key authentication.")
    # Never carry credentials to a different server/account without an explicit replacement.
    changed_target = any(str(values.get(field, "")) != str(saved.get(field, "")) for field in ("host", "port", "username", "host_key_sha256"))
    for field in SECRET_FIELDS:
        values[field] = request.form.get(field) or (saved.get(field, "") if not changed_target else "")
    if request.form.get("private_key_pem"):
        # A newly supplied unencrypted key must not inherit an old key's passphrase.
        values["private_key_passphrase"] = request.form.get("private_key_passphrase", "")
    values["auth_method"] = method
    if method == "password":
        values["private_key_pem"] = values["private_key_passphrase"] = ""
    else:
        values["password"] = ""
    values = {**values, **validate_transport(values)}
    _validate_retired_targets(values, destination=True)
    return values


@publication.route("/settings/publication", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    from app import get_db, current_authority
    db = get_db()
    status = 200
    if request.method == "POST":
        with publication_lock() as acquired:
            if not acquired:
                flash("A publication is running. Wait for it to finish before changing its target.", "warning")
                return redirect(url_for("publication.settings"))
            try:
                db.execute("BEGIN IMMEDIATE")
                values = _form_configuration(configuration())
                _save(values)
                queue_publication(db)
                public = {key: value for key, value in values.items() if key not in SECRET_FIELDS}
                public["credentials_replaced"] = any(request.form.get(field) for field in SECRET_FIELDS)
                _audit("publication.configured", detail=json.dumps(public, sort_keys=True))
                db.commit()
                flash("Publication settings saved. The APT service checks pending work every minute. URL changes apply to newly issued certificates.", "success")
                return redirect(url_for("publication.settings"))
            except ValueError as exc:
                db.rollback()
                flash(str(exc), "error")
                status = 400
    config = configuration()
    state = dict(db.execute("SELECT * FROM publication_state WHERE id=1").fetchone())
    state["next_attempt"] = datetime.fromtimestamp(state["next_attempt_at"], UTC).isoformat() if state["next_attempt_at"] else None
    authority = current_authority(db)
    if authority is None:
        authority = db.execute("SELECT * FROM authorities ORDER BY id DESC LIMIT 1").fetchone()
    cached = db.execute("SELECT number,next_update FROM crls WHERE authority_id=?", (authority["id"],)).fetchone() if authority else None
    return render_template("publication.html", title="CRL & AIA publication", provider={key: value for key, value in config.items() if key not in SECRET_FIELDS},
                           has_password=bool(config.get("password")), has_key=bool(config.get("private_key_pem")),
                           state=state, authority=authority, cached=cached), status


@publication.post("/publication/publish")
@require_roles("admin")
def publish_now():
    from app import get_db
    db = get_db()
    queue_publication(db)
    _audit("publication.requested")
    db.commit()
    result = run_publication_cycle()
    messages = {"published": "Public CA artifacts published successfully.", "failed": "Publication failed. The pending job will be retried; see the status below.",
                "busy": "Another publication is running. Your request remains queued.", "disabled": "Enable SFTP publication first.",
                "waiting": "Publication is waiting for an active CA or the next retry.", "idle": "The current artifacts are already published."}
    categories = {"published": "success", "failed": "error", "busy": "info", "disabled": "warning", "waiting": "info", "idle": "info"}
    flash(messages[result["status"]], categories[result["status"]])
    return redirect(url_for("publication.settings"))


@publication.get("/aia/<int:authority_id>.cer")
def aia(authority_id):
    from app import get_authority
    authority = get_authority(authority_id)
    if authority is None or authority["state"] != "active":
        return Response("Not found", status=404)
    der = x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)
    response = Response(der, mimetype="application/pkix-cert")
    response.headers["Cache-Control"] = "public, max-age=3600"
    response.headers["Content-Disposition"] = 'inline; filename="ca.cer"'
    return response
