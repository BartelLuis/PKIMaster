"""Optional four-eyes approval for high-impact browser actions."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3

from flask import Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, url_for

from enterprise import audit_event, get_setting, require_roles


approvals = Blueprint("approvals", __name__)
APPROVABLE_ENDPOINTS = {
    "create_authority": "Initialize a CA",
    "activate_authority": "Activate a CA",
    "create_certificate": "Issue a certificate",
    "revoke_certificate": "Revoke a certificate",
    "revoke_authority": "Revoke a local CA",
    "revoke_subordinate": "Revoke a subordinate CA",
    "delete_authority": "Delete an archived CA",
    "update_parent_crls": "Import parent CRLs",
    "enterprise.settings": "Change service and certificate settings",
    "enterprise.users": "Change user access or credentials",
    "identity.settings": "Change external authentication settings",
    "key_storage.settings": "Change CA key-provider settings",
    "certificate_profiles.manage": "Change certificate template policy",
    "publication.settings": "Change public certificate distribution",
    "publication.publish_now": "Publish CA artifacts",
    "automation.settings": "Change automation and recovery destinations",
    "automation.run_now": "Run configured automation jobs",
    "acme_admin.settings": "Change ACME enrollment settings",
    "scep_est_admin.settings": "Change SCEP / EST enrollment settings",
    "backup.export": "Export a complete CA backup",
}
SENSITIVE_FIELDS = {
    "password", "password_confirm", "current_password", "passphrase", "passphrase_confirm",
    "client_secret", "ldap_bind_password", "user_pin", "token", "secret", "totp_code",
}
TRANSIENT_AUTH_FIELDS = {"totp_code"}
FILE_LIMIT = 65536


def _db():
    from app import get_db
    return get_db()


def init_approvals(app) -> None:
    from contextlib import closing

    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT NOT NULL,
            view_args TEXT NOT NULL,
            form_data TEXT NOT NULL,
            file_hashes TEXT NOT NULL,
            secret_fields TEXT NOT NULL DEFAULT '[]',
            secret_hashes TEXT NOT NULL DEFAULT '{}',
            payload_sha256 TEXT NOT NULL DEFAULT '',
            requested_by INTEGER NOT NULL REFERENCES users(id),
            requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
            reviewed_by INTEGER REFERENCES users(id),
            reviewed_at TEXT,
            CHECK(status = 'pending' OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL))
        )""")
        columns = {row[1] for row in db.execute("PRAGMA table_info(approval_requests)")}
        if "secret_fields" not in columns:
            db.execute("ALTER TABLE approval_requests ADD COLUMN secret_fields TEXT NOT NULL DEFAULT '[]'")
        if "secret_hashes" not in columns:
            db.execute("ALTER TABLE approval_requests ADD COLUMN secret_hashes TEXT NOT NULL DEFAULT '{}'")
        if "payload_sha256" not in columns:
            db.execute("ALTER TABLE approval_requests ADD COLUMN payload_sha256 TEXT NOT NULL DEFAULT ''")
        db.execute("""CREATE TRIGGER IF NOT EXISTS immutable_approval_request
            BEFORE UPDATE OF endpoint, view_args, form_data, file_hashes, secret_fields, secret_hashes,
                payload_sha256, requested_by, requested_at ON approval_requests
            BEGIN SELECT RAISE(ABORT, 'Approval request details are immutable'); END""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS final_approval_decision
            BEFORE UPDATE OF status ON approval_requests
            WHEN OLD.status != 'pending' OR NEW.status NOT IN ('approved','rejected')
            BEGIN SELECT RAISE(ABORT, 'Approval decisions are final'); END""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS immutable_approval_reviewer
            BEFORE UPDATE OF reviewed_by, reviewed_at ON approval_requests
            WHEN OLD.status != 'pending' OR NEW.status NOT IN ('approved','rejected')
                OR NEW.reviewed_by IS NULL OR NEW.reviewed_at IS NULL
                OR NEW.reviewed_by = OLD.requested_by
            BEGIN SELECT RAISE(ABORT, 'Approval review details are final'); END""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS retain_approval_history
            BEFORE DELETE ON approval_requests
            BEGIN SELECT RAISE(ABORT, 'Approval requests are retained'); END""")
        db.execute("CREATE INDEX IF NOT EXISTS approval_requests_pending ON approval_requests(status, id)")
    app.register_blueprint(approvals)


def enabled() -> bool:
    return bool(get_setting("require_dual_approval", False))


def _payload() -> tuple[dict[str, list[str]], dict[str, str], list[str], dict[str, list[str]]]:
    if request.files and any(item.filename for values in request.files.values() for item in values):
        file_hashes = {}
        for name, values in request.files.lists():
            fingerprints = []
            for item in values:
                content = item.stream.read(FILE_LIMIT + 1)
                item.stream.seek(0)
                if len(content) > FILE_LIMIT:
                    raise ValueError("Files used in an approval request must be no larger than 64 KiB.")
                fingerprints.append(hashlib.sha256(content).hexdigest())
            file_hashes[name] = ",".join(fingerprints)
    else:
        file_hashes = {}
    secret_fields = sorted(
        key for key, values in request.form.lists()
        if key not in {"csrf_token", "approval_id"}
        and (key in TRANSIENT_AUTH_FIELDS or any(values))
        and (key.lower() in SENSITIVE_FIELDS or any(word in key.lower() for word in ("password", "secret", "private_key", "pin")))
    )
    secret_key = current_app.config["KEY_ENCRYPTION_SECRET"]
    if isinstance(secret_key, str):
        secret_key = secret_key.encode("utf-8")
    secret_hashes = {
        key: [hmac.new(secret_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
              for value in values]
        for key, values in request.form.lists()
        if key in secret_fields and key not in TRANSIENT_AUTH_FIELDS
    }
    fields = {
        key: values for key, values in request.form.lists()
        if key not in {"csrf_token", "approval_id"} and key not in secret_fields
    }
    if any(len(key) > 100 or any(len(value) > 65536 for value in values)
           for key, values in fields.items()):
        raise ValueError("The approval request contains a field that is too large.")
    if any(not values or any(not value for value in values) or any(len(value) > 65536 for value in values)
           for key, values in request.form.lists()
           if key in secret_fields and key not in TRANSIENT_AUTH_FIELDS):
        raise ValueError("The reviewing administrator must enter each credential again.")
    return fields, file_hashes, secret_fields, secret_hashes


def _payload_sha256(endpoint: str, view_args: dict, fields: dict, file_hashes: dict,
                    secret_fields: list, secret_hashes: dict) -> str:
    payload = {
        "endpoint": endpoint, "view_args": view_args, "form_data": fields,
        "file_hashes": file_hashes, "secret_fields": secret_fields,
    }
    if secret_hashes:
        payload["secret_hashes"] = secret_hashes
    envelope = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()


def approval_gate() -> Response | None:
    """Queue an action or authorize its exact replay by a different administrator."""
    if request.method != "POST" or request.endpoint not in APPROVABLE_ENDPOINTS:
        return None
    approval_id = request.form.get("approval_id", "")
    enabling_approvals = request.endpoint == "enterprise.settings" and request.form.get("require_dual_approval") == "on"
    if not (enabled() or enabling_approvals or approval_id):
        return None
    if not g.user or (g.user["role"] not in {"admin", "operator"}):
        abort(403)
    db = _db()
    try:
        fields, file_hashes, secret_fields, secret_hashes = _payload()
        view_args = request.view_args or {}
        if not approval_id:
            if request.endpoint not in {"create_certificate", "revoke_certificate"} and g.user["role"] != "admin":
                abort(403)
            db.execute("BEGIN IMMEDIATE")
            eligible = db.execute("""SELECT COUNT(*) FROM users
                WHERE active=1 AND role='admin' AND mfa_secret IS NOT NULL AND mfa_secret != ''""").fetchone()[0]
            if eligible < 2:
                raise ValueError("Four-eyes approval requires at least two active administrators with MFA enrolled.")
            payload_sha256 = _payload_sha256(
                request.endpoint, view_args, fields, file_hashes, secret_fields, secret_hashes)
            cursor = db.execute("""INSERT INTO approval_requests
                (endpoint, view_args, form_data, file_hashes, secret_fields, secret_hashes,
                 payload_sha256, requested_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (
                    request.endpoint, json.dumps(view_args, sort_keys=True),
                    json.dumps(fields, sort_keys=True), json.dumps(file_hashes, sort_keys=True),
                    json.dumps(secret_fields), json.dumps(secret_hashes, sort_keys=True),
                    payload_sha256, g.user["id"],
                ))
            audit_event("approval.requested", "approval_request", str(cursor.lastrowid),
                        "action=" + request.endpoint + "; sha256=" + payload_sha256)
            db.commit()
            flash("Action submitted for independent approval. The requested change has not been applied.", "info")
            return redirect(url_for("approvals.pending"))

        if not approval_id.isascii() or not approval_id.isdigit() or len(approval_id) > 18:
            return Response("Not found", status=404)
        if g.user["role"] != "admin":
            abort(403)
        db.execute("BEGIN IMMEDIATE")
        pending = db.execute("SELECT * FROM approval_requests WHERE id=?", (int(approval_id),)).fetchone()
        stored_view_args = json.loads(pending["view_args"]) if pending else {}
        stored_fields = json.loads(pending["form_data"]) if pending else {}
        stored_file_hashes = json.loads(pending["file_hashes"]) if pending else {}
        stored_secrets = json.loads(pending["secret_fields"]) if pending else []
        stored_secret_hashes = json.loads(pending["secret_hashes"]) if pending else {}
        stored_hash = (_payload_sha256(pending["endpoint"], stored_view_args, stored_fields,
                                      stored_file_hashes, stored_secrets, stored_secret_hashes) if pending else "")
        expected = (
            pending is not None
            and pending["status"] == "pending"
            and pending["payload_sha256"] == stored_hash
            and pending["endpoint"] == request.endpoint
            and stored_view_args == view_args
            and stored_fields == fields
            and stored_file_hashes == file_hashes
            and stored_secrets == secret_fields
            and stored_secret_hashes == secret_hashes
            and pending["requested_by"] != g.user["id"]
        )
        if not expected:
            db.rollback()
            raise ValueError("This approval is unavailable, changed, already reviewed, or was requested by your account.")
        db.execute("UPDATE approval_requests SET status='approved', reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",
                   (g.user["id"], pending["id"]))
        audit_event("approval.granted", "approval_request", str(pending["id"]),
                    "action=" + pending["endpoint"] + "; requester=" + str(pending["requested_by"])
                    + "; sha256=" + stored_hash)
        db.commit()
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
        return redirect(url_for("approvals.pending"))
    except (sqlite3.Error, json.JSONDecodeError):
        db.rollback()
        raise
    return None


@approvals.get("/approvals")
@require_roles("admin")
def pending():
    db = _db()
    requests = db.execute("""SELECT r.*, requester.username AS requester, reviewer.username AS reviewer
        FROM approval_requests r JOIN users requester ON requester.id=r.requested_by
        LEFT JOIN users reviewer ON reviewer.id=r.reviewed_by
        WHERE r.status='pending' OR r.id IN (
            SELECT id FROM approval_requests WHERE status!='pending' ORDER BY id DESC LIMIT 100
        )
        ORDER BY r.id DESC""").fetchall()
    entries = []
    for item in requests:
        entry = dict(item)
        entry["action_label"] = APPROVABLE_ENDPOINTS.get(item["endpoint"], "Unknown action")
        entry["view_args"] = json.loads(item["view_args"])
        entry["form_data"] = json.loads(item["form_data"])
        entry["file_hashes"] = json.loads(item["file_hashes"])
        entry["secret_fields"] = json.loads(item["secret_fields"])
        entries.append(entry)
    return render_template("approvals.html", title="Four-eyes approvals", requests=entries)


@approvals.post("/approvals/<int:approval_id>/reject")
@require_roles("admin")
def reject(approval_id: int):
    if not 0 < approval_id <= 9223372036854775807:
        return Response("Not found", status=404)
    db = _db()
    db.execute("BEGIN IMMEDIATE")
    pending_request = db.execute("SELECT * FROM approval_requests WHERE id=?", (approval_id,)).fetchone()
    if not pending_request or pending_request["status"] != "pending":
        db.rollback()
        flash("This approval is no longer pending.", "error")
        return redirect(url_for("approvals.pending"))
    if pending_request["requested_by"] == g.user["id"]:
        db.rollback()
        flash("The requester cannot reject or approve their own request.", "error")
        return redirect(url_for("approvals.pending"))
    db.execute("UPDATE approval_requests SET status='rejected', reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",
               (g.user["id"], approval_id))
    audit_event("approval.rejected", "approval_request", str(approval_id),
                "action=" + pending_request["endpoint"] + "; requester=" + str(pending_request["requested_by"])
                + "; sha256=" + pending_request["payload_sha256"])
    db.commit()
    flash("Approval request rejected. The requested change was not applied.", "success")
    return redirect(url_for("approvals.pending"))
