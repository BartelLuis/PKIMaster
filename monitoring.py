"""Persistent PKI operational findings, expiry escalation and recovery notices."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import time
import uuid

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from flask import Blueprint, current_app, flash, has_request_context, redirect, render_template, request, url_for

from enterprise import audit_event, require_roles
from monitoring_transports import MonitoringError, deliver, http_request, validate_email, validate_url
from pki import crl_signature_is_valid

monitoring = Blueprint("monitoring", __name__)
DEFAULTS = {"channel": "none", "warning_days": [30, 14, 7], "crl_warning_hours": 24,
            "public_checks": True, "webhook_url": "", "webhook_token": "", "smtp_host": "",
            "smtp_port": 587, "smtp_security": "starttls", "smtp_username": "", "smtp_password": "",
            "smtp_sender": "", "smtp_recipients": []}
SECRET_FIELDS = {"webhook_token", "smtp_password"}


def configuration():
    from app import get_db, private_key_cipher
    row = get_db().execute("SELECT value FROM settings WHERE key='monitoring_config'").fetchone()
    return {**DEFAULTS, **json.loads(private_key_cipher().decrypt(row[0].encode()))} if row else dict(DEFAULTS)


def init_monitoring(app):
    from app import get_db
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS monitoring_findings (
                finding_key TEXT PRIMARY KEY, title TEXT NOT NULL, detail TEXT NOT NULL,
                severity TEXT NOT NULL, signature TEXT NOT NULL, active INTEGER NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, changed_at TEXT NOT NULL,
                event_id TEXT NOT NULL, notified_signature TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS monitoring_state (
                id INTEGER PRIMARY KEY CHECK(id=1), last_check TEXT,
                last_delivery TEXT, notification_error TEXT NOT NULL DEFAULT '',
                failures INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
                public_checked INTEGER NOT NULL DEFAULT 0, public_cursor INTEGER NOT NULL DEFAULT 0);
            INSERT OR IGNORE INTO monitoring_state(id) VALUES (1);
        """)
        if "public_cursor" not in {row[1] for row in db.execute("PRAGMA table_info(monitoring_state)")}:
            db.execute("ALTER TABLE monitoring_state ADD COLUMN public_cursor INTEGER NOT NULL DEFAULT 0")
            db.commit()
    app.register_blueprint(monitoring)


def delete_authority_monitoring(db, authority_id):
    """Called before certificate deletion in the CA deletion transaction."""
    if not db.in_transaction:
        raise RuntimeError("Monitoring cleanup requires a transaction.")
    db.execute("DELETE FROM monitoring_findings WHERE finding_key GLOB ?", (f"authority:{authority_id}:*",))
    for table, kind in (("certificates", "certificate"), ("issued_authorities", "subordinate")):
        ids = [row[0] for row in db.execute(f"SELECT id FROM {table} WHERE authority_id=?", (authority_id,))]
        db.executemany("DELETE FROM monitoring_findings WHERE finding_key=?", ((f"{kind}:{identity}:expiry",) for identity in ids))


@contextmanager
def monitoring_lock(instance_path=None):
    path = Path(instance_path or current_app.config["INSTANCE_PATH"]) / "monitoring.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            if not os.fstat(descriptor).st_size:
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


def _audit(action, key="", detail=""):
    if has_request_context():
        audit_event(action, "monitoring", key, detail)
    else:
        from app import get_db
        from audit_integrity import append_event
        append_event(get_db(), current_app.config["KEY_ENCRYPTION_SECRET"], actor_name="system",
                     action=action, object_type="monitoring", object_id=key, detail=detail)


def _finding(key, title, detail, signature, severity="warning"):
    return {"key": key, "title": title, "detail": detail, "signature": signature, "severity": severity}


def _expiry(key, title, expires, now, thresholds, *, hours=False):
    expiry = datetime.fromisoformat(expires) if isinstance(expires, str) else expires
    if expiry is None or expiry.tzinfo is None:
        return _finding(key, title, "The expiry timestamp is missing or invalid.", "invalid", "error")
    remaining = (expiry - now).total_seconds()
    if remaining <= 0:
        return _finding(key, title, f"Expired at {expiry.isoformat()}.", "expired", "error")
    unit = 3600 if hours else 86400
    reached = [limit for limit in thresholds if remaining <= limit * unit]
    if reached:
        limit = min(reached)
        return _finding(key, title, f"Expires at {expiry.isoformat()} (within {limit} {'hours' if hours else 'days'}).",
                        f"expires:{limit}")
    return None


def _snapshot(db):
    from publication import configuration as publication_configuration, public_url
    db.execute("BEGIN")
    try:
        authorities = [dict(row) for row in db.execute("SELECT * FROM authorities")]
        leaves = [dict(row) for row in db.execute("SELECT id,common_name,not_after FROM certificates WHERE revoked_at IS NULL")]
        issued = [dict(row) for row in db.execute("SELECT id,common_name,not_after FROM issued_authorities WHERE revoked_at IS NULL")]
        crls = {row["authority_id"]: dict(row) for row in db.execute("SELECT * FROM crls")}
        revoked = {}
        for row in db.execute("""SELECT authority_id,serial_number FROM certificates WHERE revoked_at IS NOT NULL
                               UNION ALL SELECT authority_id,serial_number FROM issued_authorities WHERE revoked_at IS NOT NULL"""):
            revoked.setdefault(row["authority_id"], set()).add(int(row["serial_number"], 16))
        for authority in authorities:
            authority["public_crl_url"] = public_url("crl", authority["id"])
        publication_state = dict(db.execute("SELECT * FROM publication_state WHERE id=1").fetchone())
        publishing = publication_configuration()["enabled"]
        db.commit()
        return authorities, leaves, issued, crls, revoked, publication_state, publishing
    except BaseException:
        db.rollback()
        raise


def _parent_findings(authority, config, now):
    from app import split_pem_crl_blocks, validate_parent_crls
    findings = []
    prefix = f"authority:{authority['id']}:parent"
    try:
        parents = x509.load_pem_x509_certificates(authority["parent_chain_pem"].encode())
        for index, parent in enumerate(parents):
            finding = _expiry(f"{prefix}:{index}:expiry", f"Parent CA of {authority['name']}",
                              parent.not_valid_after_utc, now, config["warning_days"])
            if finding:
                findings.append(finding)
        blocks = split_pem_crl_blocks(authority["parent_crls_pem"])
        for index, block in enumerate(blocks):
            crl = x509.load_pem_x509_crl(block.encode())
            finding = _expiry(f"{prefix}:{index}:crl", f"Parent CRL of {authority['name']}", crl.next_update_utc,
                              now, [config["crl_warning_hours"]], hours=True)
            if finding:
                findings.append(finding)
        validate_parent_crls(authority, authority["parent_crls_pem"])
    except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension):
        findings.append(_finding(prefix + ":validation", f"Parent status of {authority['name']}",
                                 "The parent chain or CRL bundle is missing, expired, revoked or invalid. Review the CA console.",
                                 "invalid", "error"))
    return findings


def validate_public_crl(content, authority, cached, revoked, now):
    """Check the data clients actually receive against this CA and local state."""
    try:
        crl = x509.load_pem_x509_crl(content) if content.lstrip().startswith(b"-----BEGIN") else x509.load_der_x509_crl(content)
        certificate = x509.load_pem_x509_certificate(authority["certificate_pem"].encode())
        if crl.issuer != certificate.subject or not crl_signature_is_valid(crl, certificate.public_key()):
            raise MonitoringError("The public CRL has the wrong issuer or an invalid signature.")
        if crl.next_update_utc is None or not crl.last_update_utc <= now < crl.next_update_utc:
            raise MonitoringError("The public CRL is expired or not yet valid.")
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        for extension in crl.extensions:
            if isinstance(extension.value, (x509.DeltaCRLIndicator, x509.IssuingDistributionPoint)) or (
                    extension.critical and not isinstance(extension.value, (x509.AuthorityKeyIdentifier, x509.CRLNumber))):
                raise MonitoringError("The public endpoint must provide a full, direct CRL.")
        if cached:
            local = x509.load_der_x509_crl(cached["der"])
            if (number < cached["number"] or crl.last_update_utc < local.last_update_utc
                    or (number == cached["number"] and crl.fingerprint(hashes.SHA256()) != local.fingerprint(hashes.SHA256()))):
                raise MonitoringError("The public CRL is older than or differs from the latest locally generated CRL.")
        if not revoked.issubset({entry.serial_number for entry in crl}):
            raise MonitoringError("The public CRL omits locally recorded revocations.")
        return crl
    except MonitoringError:
        raise
    except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension, UnsupportedAlgorithm) as exc:
        raise MonitoringError("The public endpoint did not return a supported signed CRL.") from exc


def collect_findings(snapshot, config, now, *, start_index=0):
    authorities, leaves, issued, crls, revoked, state, publishing = snapshot
    findings = []
    for kind, rows, title in (("certificate", leaves, "Certificate"), ("subordinate", issued, "Issued CA")):
        for row in rows:
            finding = _expiry(f"{kind}:{row['id']}:expiry", f"{title}: {row['common_name']}", row["not_after"], now, config["warning_days"])
            if finding:
                findings.append(finding)
    if publishing and state["last_error"]:
        findings.append(_finding("publication:failure", "CA publication failed",
                                 "The latest SFTP upload failed. Review CRL & AIA publication for details.", "failed", "error"))
    public_checked = 0
    deferred = 0
    preserved = set()
    deadline = time.monotonic() + 45
    if authorities:
        offset = start_index % len(authorities)
        authorities = authorities[offset:] + authorities[:offset]
    for authority in authorities:
        if authority["state"] != "active":
            continue
        key = f"authority:{authority['id']}"
        if not authority["revoked_at"]:
            finding = _expiry(key + ":expiry", "CA: " + authority["name"], authority["not_after"], now, config["warning_days"])
            if finding:
                findings.append(finding)
            if authority["role"] != "root":
                findings.extend(_parent_findings(authority, config, now))
        cached = crls.get(authority["id"])
        if cached and datetime.fromisoformat(authority["not_after"]) > now:
            local_crl = x509.load_der_x509_crl(cached["der"])
            finding = _expiry(key + ":local-crl", "Local CRL: " + authority["name"], local_crl.next_update_utc,
                              now, [config["crl_warning_hours"]], hours=True)
            if finding:
                findings.append(finding)
        # Retired CA distribution remains relevant until its validity ends.
        if datetime.fromisoformat(authority["not_after"]) <= now:
            continue
        if not config["public_checks"]:
            preserved.add(key + ":public")
            preserved.add("monitoring:coverage")
            continue
        title = "Public CRL: " + authority["name"]
        if not authority["public_crl_url"]:
            findings.append(_finding(key + ":public", title, "No public CRL URL is configured. Set a public base URL or a CRL distribution URL.", "unconfigured"))
            continue
        if time.monotonic() >= deadline:
            preserved.add(key + ":public")
            deferred += 1
            continue
        public_checked += 1
        try:
            crl = validate_public_crl(http_request(authority["public_crl_url"]), authority, crls.get(authority["id"]),
                                      revoked.get(authority["id"], set()), now)
            finding = _expiry(key + ":public", title, crl.next_update_utc, now, [config["crl_warning_hours"]], hours=True)
            if finding:
                findings.append(finding)
        except MonitoringError as exc:
            findings.append(_finding(key + ":public", title, str(exc), "unhealthy:" + str(exc), "error"))
    if deferred:
        findings.append(_finding("monitoring:coverage", "Public CRL checks deferred",
                                 f"{deferred} endpoint check(s) exceeded this cycle's network time budget. The next cycle rotates its starting point. Previous findings retain their last observed state.",
                                 "incomplete"))
    return findings, public_checked, preserved


def _record_findings(db, findings, now, public_checked, preserved=()):
    timestamp = now.isoformat()
    previous = {row["finding_key"]: dict(row) for row in db.execute("SELECT * FROM monitoring_findings")}
    seen = set()
    for finding in findings:
        key = finding["key"]
        kind, _, identifier = key.partition(":")
        table = {"authority": "authorities", "certificate": "certificates", "subordinate": "issued_authorities"}.get(kind)
        if table and not db.execute(f"SELECT 1 FROM {table} WHERE id=?", (int(identifier.split(":", 1)[0]),)).fetchone():
            # A CA can be deleted while a public retrieval is in flight. Never
            # recreate its removed findings from the older read snapshot.
            continue
        seen.add(key)
        old = previous.get(key)
        changed = not old or not old["active"] or old["signature"] != finding["signature"]
        db.execute("""INSERT INTO monitoring_findings(finding_key,title,detail,severity,signature,active,
            first_seen,last_seen,changed_at,event_id) VALUES (?,?,?,?,?,1,?,?,?,?)
            ON CONFLICT(finding_key) DO UPDATE SET title=excluded.title,detail=excluded.detail,severity=excluded.severity,
            signature=excluded.signature,active=1,last_seen=excluded.last_seen,changed_at=excluded.changed_at,event_id=excluded.event_id""",
                   (key, finding["title"], finding["detail"], finding["severity"], finding["signature"],
                    timestamp, timestamp, timestamp if changed else old["changed_at"], str(uuid.uuid4()) if changed else old["event_id"]))
        if changed:
            _audit("monitoring.alert", key, f"severity={finding['severity']}; status={finding['signature']}")
    for key, old in previous.items():
        if key not in seen and key not in preserved and old["active"]:
            db.execute("""UPDATE monitoring_findings SET active=0,severity='success',signature='resolved',
                detail='The condition is no longer present.',last_seen=?,changed_at=?,event_id=? WHERE finding_key=?""",
                       (timestamp, timestamp, str(uuid.uuid4()), key))
            _audit("monitoring.resolved", key)
    # Conditions which began and ended while notifications were off need no recovery message.
    db.execute("UPDATE monitoring_findings SET notified_signature=signature WHERE active=0 AND notified_signature=''")
    db.execute("UPDATE monitoring_state SET last_check=?,public_checked=?,public_cursor=public_cursor+? WHERE id=1",
               (timestamp, public_checked, max(1, public_checked)))
    db.execute("DELETE FROM monitoring_findings WHERE active=0 AND notified_signature=signature AND changed_at<?",
               ((now - timedelta(days=90)).isoformat(),))


def run_monitoring_cycle():
    from app import get_db
    from audit_integrity import verify_chain
    from backup import restore_pending
    with monitoring_lock() as acquired:
        if not acquired:
            return {"status": "busy"}
        if restore_pending(Path(current_app.config["INSTANCE_PATH"])):
            return {"status": "restore_pending"}
        db = get_db()
        verify_chain(db, current_app.config["KEY_ENCRYPTION_SECRET"])
        config = configuration()
        now = datetime.now(UTC)
        cursor = db.execute("SELECT public_cursor FROM monitoring_state WHERE id=1").fetchone()[0]
        findings, public_checked, preserved = collect_findings(_snapshot(db), config, now, start_index=cursor)
        db.execute("BEGIN IMMEDIATE")
        _record_findings(db, findings, now, public_checked, preserved)
        active_count = db.execute("SELECT COUNT(*) FROM monitoring_findings WHERE active=1").fetchone()[0]
        state = dict(db.execute("SELECT * FROM monitoring_state WHERE id=1").fetchone())
        pending = [dict(row) for row in db.execute("""SELECT * FROM monitoring_findings
            WHERE signature<>notified_signature ORDER BY changed_at,finding_key LIMIT 100""")]
        db.commit()
        delivered = 0
        if config["channel"] != "none" and pending and state["next_attempt_at"] <= time.time():
            events = [{"id": row["event_id"], "key": row["finding_key"], "status": "active" if row["active"] else "resolved",
                       "severity": row["severity"], "title": row["title"], "detail": row["detail"], "changed_at": row["changed_at"]} for row in pending]
            try:
                deliver(config, events)
            except MonitoringError as exc:
                db.execute("BEGIN IMMEDIATE")
                failures = state["failures"] + 1
                db.execute("UPDATE monitoring_state SET failures=?,notification_error=?,next_attempt_at=? WHERE id=1",
                           (failures, str(exc), time.time() + min(3600, 300 * 2 ** min(failures - 1, 4))))
                _audit("monitoring.delivery_failed", detail=str(exc))
                db.commit()
                return {"status": "failed", "active": active_count, "delivered": 0}
            db.execute("BEGIN IMMEDIATE")
            for row in pending:
                db.execute("UPDATE monitoring_findings SET notified_signature=? WHERE finding_key=? AND signature=?",
                           (row["signature"], row["finding_key"], row["signature"]))
            delivered = len(events)
            db.execute("UPDATE monitoring_state SET last_delivery=?,notification_error='',failures=0,next_attempt_at=0 WHERE id=1",
                       (datetime.now(UTC).isoformat(),))
            _audit("monitoring.delivered", detail=f"channel={config['channel']}; events={delivered}")
            db.commit()
        return {"status": "checked", "active": active_count, "delivered": delivered}


def _form_configuration(saved):
    values = {**saved, "channel": request.form.get("channel", "none"), "public_checks": "public_checks" in request.form}
    try:
        days = sorted(set(int(value.strip()) for value in request.form.get("warning_days", "30,14,7").split(",")), reverse=True)
        hours = int(request.form.get("crl_warning_hours", "24"))
        if not 1 <= len(days) <= 8 or not all(1 <= day <= 365 for day in days) or not 1 <= hours <= 168:
            raise ValueError
    except ValueError as exc:
        raise MonitoringError("Use 1–8 warning thresholds between 1 and 365 days, and a CRL warning between 1 and 168 hours.") from exc
    values.update(warning_days=days, crl_warning_hours=hours)
    if values["channel"] not in {"none", "email", "webhook"}:
        raise MonitoringError("Select no notifications, email or webhook.")
    if values["channel"] == "webhook":
        url = request.form.get("webhook_url", "").strip()
        validate_url(url, webhook=True)
        token = request.form.get("webhook_token", "")
        if not token and url != saved["webhook_url"] and saved["webhook_token"] and "clear_webhook_token" not in request.form:
            raise MonitoringError("Re-enter the webhook token when changing its destination, or clear it explicitly.")
        if "clear_webhook_token" in request.form:
            token = ""
        elif not token:
            token = saved["webhook_token"]
        if len(token) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise MonitoringError("Use a token of at most 4096 printable ASCII characters without whitespace.")
        values.update(webhook_url=url, webhook_token=token)
    if values["channel"] == "email":
        for field in ("smtp_host", "smtp_username", "smtp_sender", "smtp_security"):
            values[field] = request.form.get(field, "").strip()
        host = values["smtp_host"]
        if (not host or len(host) > 253 or not host.isascii() or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:" for char in host)
                or len(values["smtp_username"]) > 254 or "\n" in values["smtp_username"] or "\r" in values["smtp_username"]):
            raise MonitoringError("Provide a valid SMTP hostname and username.")
        try:
            values["smtp_port"] = int(request.form.get("smtp_port", "587"))
            if not 1 <= values["smtp_port"] <= 65535:
                raise ValueError
        except ValueError as exc:
            raise MonitoringError("Use an SMTP port between 1 and 65535.") from exc
        if values["smtp_security"] not in {"starttls", "tls"}:
            raise MonitoringError("SMTP requires STARTTLS or implicit TLS.")
        values["smtp_sender"] = validate_email(values["smtp_sender"])
        recipients = [value.strip() for value in request.form.get("smtp_recipients", "").split(",") if value.strip()]
        if not 1 <= len(recipients) <= 10:
            raise MonitoringError("Provide 1–10 comma-separated notification recipients.")
        values["smtp_recipients"] = [validate_email(value) for value in recipients]
        changed_target = any(values[field] != saved[field] for field in ("smtp_host", "smtp_port", "smtp_security", "smtp_username"))
        password = request.form.get("smtp_password", "")
        if changed_target and saved["smtp_password"] and not password and values["smtp_username"]:
            raise MonitoringError("Re-enter the SMTP password when changing the server, TLS mode or account.")
        values["smtp_password"] = (password or (saved["smtp_password"] if not changed_target else "")) if values["smtp_username"] else ""
        if len(values["smtp_password"]) > 4096 or (values["smtp_username"] and not values["smtp_password"]):
            raise MonitoringError("Provide an SMTP password of at most 4096 characters for the configured account.")
    return values


@monitoring.get("/monitoring")
@require_roles("admin", "operator", "auditor")
def dashboard():
    from app import get_db
    db = get_db()
    config = configuration()
    return render_template("monitoring.html", title="Monitoring", channel=config["channel"], public_checks=config["public_checks"],
                           state=db.execute("SELECT * FROM monitoring_state WHERE id=1").fetchone(),
                           findings=db.execute("SELECT * FROM monitoring_findings WHERE active=1 ORDER BY severity,title").fetchall(),
                           recovered=db.execute("SELECT * FROM monitoring_findings WHERE active=0 ORDER BY changed_at DESC LIMIT 20").fetchall())


@monitoring.route("/monitoring/settings", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    from app import get_db, private_key_cipher
    db = get_db()
    status = 200
    if request.method == "POST":
        with monitoring_lock() as acquired:
            if not acquired:
                flash("A monitoring check is running. Try saving again when it finishes.", "warning")
                return redirect(url_for("monitoring.settings"))
            try:
                db.execute("BEGIN IMMEDIATE")
                saved = configuration()
                values = _form_configuration(saved)
                encrypted = private_key_cipher().encrypt(json.dumps(values).encode()).decode()
                db.execute("INSERT INTO settings(key,value) VALUES ('monitoring_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encrypted,))
                destination_fields = ("channel", "webhook_url", "smtp_host", "smtp_port", "smtp_sender", "smtp_recipients")
                if values["channel"] != "none" and any(values[field] != saved[field] for field in destination_fields):
                    db.execute("UPDATE monitoring_findings SET notified_signature='' WHERE active=1")
                db.execute("UPDATE monitoring_state SET next_attempt_at=0,notification_error='',failures=0 WHERE id=1")
                _audit("monitoring.configured", detail=f"channel={values['channel']}; public_checks={values['public_checks']}")
                db.commit()
                flash("Monitoring settings saved. The next timer run or manual check applies them.", "success")
                return redirect(url_for("monitoring.settings"))
            except ValueError as exc:
                db.rollback()
                flash(str(exc), "error")
                status = 400
    config = configuration()
    return render_template("monitoring_settings.html", title="Monitoring settings",
                           provider={key: value for key, value in config.items() if key not in SECRET_FIELDS},
                           has_webhook_token=bool(config["webhook_token"]), has_smtp_password=bool(config["smtp_password"])), status


@monitoring.post("/monitoring/check")
@require_roles("admin")
def check_now():
    result = run_monitoring_cycle()
    if result["status"] == "busy":
        flash("A monitoring check is already running.", "info")
    elif result["status"] == "restore_pending":
        flash("Monitoring is paused while a restore is pending.", "warning")
    elif result["status"] == "failed":
        flash("Checks completed, but notification delivery failed. See the monitoring status.", "error")
    else:
        flash(f"Checks completed: {result['active']} active finding(s), {result['delivered']} notification update(s) delivered.",
              "warning" if result["active"] else "success")
    return redirect(url_for("monitoring.dashboard"))
