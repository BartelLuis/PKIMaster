"""Browser-managed parent status, encrypted backups and external audit archives."""
from __future__ import annotations

from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import socket
import stat
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, current_app, flash, has_request_context, redirect, render_template, request, url_for
import paramiko

from enterprise import audit_event, require_roles
from monitoring_transports import MonitoringError, http_request, resolve_address, validate_url
from publication_transports import (PublicationError, SECRET_FIELDS, _PinnedHostKey,
                                   _StrictHostSignatureTransport, _private_key, validate_transport)


automation = Blueprint("automation", __name__)
DEFAULTS = {"parent_enabled": False, "parent_authority_id": None, "parent_urls": [],
            "parent_interval_minutes": 60, "backup_enabled": False, "backup_interval_hours": 24,
            "backup_retention": 14, "backup_public_key": "", "audit_enabled": False,
            "audit_interval_minutes": 15, "transport": "sftp", "host": "", "port": 22,
            "username": "", "directory": "", "host_key_sha256": "", "password": "",
            "private_key_pem": "", "private_key_passphrase": "", "auth_method": "key"}
JOBS = ("parent", "backup", "audit")
NETWORK_SECONDS = 120
MAX_REMOTE_FILES = 10000
MAX_AUDIT_BYTES = 128 * 1024 * 1024


class AutomationError(ValueError):
    """Safe operational diagnostic without remote responses or credentials."""


def configuration():
    from app import get_db, private_key_cipher
    row = get_db().execute("SELECT value FROM settings WHERE key='automation_config'").fetchone()
    return {**DEFAULTS, **json.loads(private_key_cipher().decrypt(row[0].encode()))} if row else dict(DEFAULTS)


def _save(values):
    from app import get_db, private_key_cipher
    encrypted = private_key_cipher().encrypt(json.dumps(values).encode()).decode()
    get_db().execute("INSERT INTO settings(key,value) VALUES ('automation_config',?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encrypted,))


def init_automation(app):
    from app import get_db
    with app.app_context():
        db = get_db()
        db.executescript("""CREATE TABLE IF NOT EXISTS automation_jobs (
            name TEXT PRIMARY KEY CHECK(name IN ('parent','backup','audit')),
            last_attempt TEXT, last_success TEXT, last_error TEXT NOT NULL DEFAULT '',
            failures INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
            last_cursor INTEGER NOT NULL DEFAULT 0, last_object TEXT NOT NULL DEFAULT '');
            INSERT OR IGNORE INTO automation_jobs(name) VALUES ('parent'),('backup'),('audit');""")
    app.register_blueprint(automation)


def _audit(action, job, detail=""):
    if has_request_context():
        audit_event(action, "automation", job, detail)
    else:
        from app import get_db
        from audit_integrity import append_event
        append_event(get_db(), current_app.config["KEY_ENCRYPTION_SECRET"], actor_name="system",
                     action=action, object_type="automation", object_id=job, detail=detail)


def _interval(config, job):
    return (config["backup_interval_hours"] * 3600 if job == "backup"
            else config[job + "_interval_minutes"] * 60)


def _deadline(deadline):
    if time.monotonic() >= deadline:
        raise AutomationError("The external archive transfer exceeded its time limit.")


@contextmanager
def _sftp(config):
    """Use publication's strict host verification with a bounded pinned socket."""
    value = validate_transport(config)
    key = _private_key(value)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_PinnedHostKey(value["host_key_sha256"]))
    deadline = time.monotonic() + NETWORK_SECONDS
    connection = None
    channel = None
    timer = threading.Timer(NETWORK_SECONDS, client.close)
    timer.daemon = True
    timer.start()
    try:
        connection = socket.create_connection((resolve_address(value["host"], value["port"]), value["port"]), timeout=5)
        client.connect(value["host"], port=value["port"], username=value["username"], sock=connection,
                       password=None if key else value["password"], pkey=key,
                       allow_agent=False, look_for_keys=False, timeout=5, banner_timeout=10,
                       auth_timeout=10, channel_timeout=10, transport_factory=_StrictHostSignatureTransport,
                       disabled_algorithms={"keys": ["ssh-rsa", "ssh-dss"], "pubkeys": ["ssh-rsa", "ssh-dss"],
                                            "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]})
        _deadline(deadline)
        channel = client.open_sftp()
        channel.get_channel().settimeout(10)
        info = channel.lstat(value["directory"])
        if info.st_mode is None or not stat.S_ISDIR(info.st_mode):
            raise AutomationError("The external archive directory must exist and must not be a symbolic link.")
        yield channel, value["directory"], deadline
    except (AutomationError, PublicationError, MonitoringError):
        raise
    except (paramiko.SSHException, OSError, EOFError):
        raise AutomationError("SFTP archive delivery failed. Check the host fingerprint, account, connection and directory permissions.") from None
    finally:
        timer.cancel()
        if channel is not None:
            with suppress(paramiko.SSHException, OSError, EOFError):
                channel.close()
        with suppress(paramiko.SSHException, OSError, EOFError):
            client.close()
        if connection is not None:
            with suppress(OSError):
                connection.close()


def _remote_digest(sftp, path, expected_size, deadline):
    info = sftp.lstat(path)
    if info.st_mode is None or not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
        raise AutomationError("An external archive object has an unexpected type or size; it was not overwritten.")
    digest = hashlib.sha256()
    count = 0
    with sftp.open(path, "rb", bufsize=0) as stream:
        while True:
            _deadline(deadline)
            block = stream.read(min(65536, expected_size + 1 - count))
            if not block:
                break
            count += len(block)
            if count > expected_size:
                raise AutomationError("An external archive object changed during verification.")
            digest.update(block)
    if count != expected_size:
        raise AutomationError("The external archive transfer is incomplete.")
    return digest.hexdigest()


def _remote_entries(sftp, directory, deadline):
    entries = []
    for entry in sftp.listdir_iter(directory, read_aheads=1):
        _deadline(deadline)
        entries.append(entry)
        if len(entries) > MAX_REMOTE_FILES:
            raise AutomationError("The external archive directory exceeds 10,000 entries; select a dedicated directory.")
    return entries


def _upload_immutable(sftp, directory, filename, content, deadline):
    """Verify the staged bytes before a standard non-overwriting SFTP rename."""
    if not re.fullmatch(r"pkimaster-[a-z0-9.-]+", filename):
        raise AutomationError("Invalid managed archive filename.")
    destination = posixpath.join(directory, filename)
    expected = hashlib.sha256(content).hexdigest()
    try:
        sftp.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        if _remote_digest(sftp, destination, len(content), deadline) != expected:
            raise AutomationError("An existing external archive has different bytes; overwrite was refused.")
        return
    temporary = posixpath.join(directory, ".pkimaster-archive-" + secrets.token_hex(16) + ".tmp")
    created = False
    try:
        with sftp.open(temporary, "wx", bufsize=0) as output:
            created = True
            sftp.chmod(temporary, 0o600)
            for offset in range(0, len(content), 65536):
                _deadline(deadline)
                output.write(content[offset:offset + 65536])
            output.flush()
        if _remote_digest(sftp, temporary, len(content), deadline) != expected:
            raise AutomationError("The external archive failed read-back SHA-256 verification.")
        _deadline(deadline)
        # Standard SFTP rename refuses an existing destination. POSIX rename,
        # intentionally used by public CRL publishing, must not be used here.
        sftp.rename(temporary, destination)
        created = False
        if _remote_digest(sftp, destination, len(content), deadline) != expected:
            raise AutomationError("The delivered archive failed SHA-256 verification.")
    finally:
        if created:
            with suppress(AutomationError, paramiko.SSHException, OSError, EOFError):
                _deadline(deadline)
                sftp.remove(temporary)


def _retention(sftp, directory, installation, keep, deadline):
    pattern = re.compile(r"pkimaster-backup-" + re.escape(installation)
                         + r"-[0-9]{8}t[0-9]{12}z-[a-f0-9]{64}\.pkibackup\Z")
    managed = [entry.filename for entry in _remote_entries(sftp, directory, deadline)
               if pattern.fullmatch(entry.filename) and entry.st_mode is not None and stat.S_ISREG(entry.st_mode)]
    for name in sorted(managed, reverse=True)[keep:]:
        _deadline(deadline)
        path = posixpath.join(directory, name)
        info = sftp.lstat(path)
        if info.st_mode is None or not stat.S_ISREG(info.st_mode):
            raise AutomationError("A managed backup changed type during retention; deletion stopped.")
        sftp.remove(path)


def apply_parent_crls(db, authority, pem):
    """Use the existing validation policy and keep authenticated revocation final."""
    from app import split_pem_crl_blocks, validate_parent_crls
    if not db.in_transaction:
        raise RuntimeError("Parent CRL updates require a write transaction.")
    revoked = False
    try:
        canonical = validate_parent_crls(authority, pem)
    except ValueError as exc:
        if str(exc) != "The CA or an ancestor is revoked in its issuer's CRL.":
            raise
        canonical, revoked = pem, True
    old_blocks = split_pem_crl_blocks(authority["parent_crls_pem"])
    new_blocks = split_pem_crl_blocks(canonical)
    if old_blocks:
        if len(old_blocks) != len(new_blocks):
            raise AutomationError("Parent CRL bundle is inconsistent with stored CRLs.")
        for old_pem, new_pem in zip(old_blocks, new_blocks):
            old, new = (x509.load_pem_x509_crl(value.encode()) for value in (old_pem, new_pem))
            old_number = old.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            new_number = new.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            if (new.last_update_utc < old.last_update_utc or new_number < old_number
                    or (new_number == old_number and new.public_bytes(serialization.Encoding.DER) != old.public_bytes(serialization.Encoding.DER))):
                raise AutomationError("Parent CRL timestamp or number rollback is not allowed.")
    db.execute("UPDATE authorities SET parent_crls_pem=? WHERE id=?", (canonical, authority["id"]))
    if revoked:
        db.execute("UPDATE authorities SET revoked_at=COALESCE(revoked_at,?), "
                   "revocation_reason=COALESCE(revocation_reason,'unspecified') WHERE id=?",
                   (datetime.now(UTC).isoformat(), authority["id"]))
    if revoked or canonical != authority["parent_crls_pem"]:
        _audit("automation.parent_crls_updated", "parent", f"authority={authority['id']}; revoked={int(revoked)}")
    return revoked


def _sync_parent(db, config):
    from app import get_authority
    authority = get_authority(config["parent_authority_id"])
    if (not authority or authority["revoked_at"] or authority["state"] != "active"
            or authority["role"] == "root"):
        raise AutomationError("The configured parent-CRL owner is no longer the active subordinate CA. Review automation settings.")
    parents = x509.load_pem_x509_certificates(authority["parent_chain_pem"].encode())
    if not 1 <= len(config["parent_urls"]) == len(parents) <= 8:
        raise AutomationError("Configure one parent CRL URL per ancestor, ordered immediate issuer to root.")
    parts = []
    for url in config["parent_urls"]:
        content = http_request(url, limit=4 * 1024 * 1024)
        try:
            crl = x509.load_pem_x509_crl(content) if content.lstrip().startswith(b"-----BEGIN") else x509.load_der_x509_crl(content)
            parts.append(crl.public_bytes(serialization.Encoding.PEM).decode())
        except ValueError as exc:
            raise AutomationError("A configured parent endpoint did not return a supported CRL.") from exc
    db.execute("BEGIN IMMEDIATE")
    current = get_authority(authority["id"])
    if (not current or current["revoked_at"] or current["certificate_pem"] != authority["certificate_pem"]
            or current["parent_chain_pem"] != authority["parent_chain_pem"]):
        raise AutomationError("The CA changed while retrieving parent CRLs; retry with its current configuration.")
    apply_parent_crls(db, current, "".join(parts))
    db.commit()
    return "", 0


def _external_backup(db, config):
    from backup import create_snapshot, encrypt_recipient_archive, sign_archive
    plaintext = create_snapshot(db)
    encrypted = encrypt_recipient_archive(plaintext, config["backup_public_key"])
    encrypted, _ = sign_archive(encrypted)
    del plaintext
    name = (f"pkimaster-backup-{config['installation_id']}-"
            + datetime.now(UTC).strftime("%Y%m%dt%H%M%S%fz") + "-"
            + hashlib.sha256(encrypted).hexdigest() + ".pkibackup")
    with _sftp(config) as (sftp, directory, deadline):
        _upload_immutable(sftp, directory, name, encrypted, deadline)
        _retention(sftp, directory, config["installation_id"], config["backup_retention"], deadline)
    return name, 0


def audit_archive(db, installation):
    """Snapshot and authenticate the complete chain under one SQLite read view."""
    from audit_integrity import verify_chain
    db.execute("BEGIN")
    try:
        checkpoint = verify_chain(db, current_app.config["KEY_ENCRYPTION_SECRET"])
        prefix = json.dumps({"format": 1, "installation_id": installation, "checkpoint": checkpoint},
                            sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()[:-1] + b',"events":['
        content = bytearray(prefix)
        hashes = {}
        for row in db.execute("SELECT * FROM audit_events ORDER BY id"):
            event = dict(row)
            item = json.dumps(event, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
            if len(content) + len(item) + 3 > MAX_AUDIT_BYTES:
                raise AutomationError("The verified audit archive exceeds 128 MiB; archive delivery requires administrator attention.")
            if hashes:
                content.extend(b",")
            content.extend(item)
            hashes[event["id"]] = event["event_hash"]
        content.extend(b"]}")
        db.commit()
        return bytes(content), checkpoint, hashes
    except BaseException:
        db.rollback()
        raise


def _external_audit(db, config):
    content, checkpoint, hashes = audit_archive(db, config["installation_id"])
    name = f"pkimaster-audit-{config['installation_id']}-{checkpoint['last_id']:020d}-{checkpoint['head_hash']}.json"
    pattern = re.compile(r"pkimaster-audit-" + re.escape(config["installation_id"]) + r"-([0-9]{20})-([a-f0-9]{64})\.json\Z")
    from audit_integrity import ZERO
    with _sftp(config) as (sftp, directory, deadline):
        for entry in _remote_entries(sftp, directory, deadline):
            match = pattern.fullmatch(entry.filename)
            if not match:
                continue
            cursor, expected = int(match[1]), match[2]
            actual = ZERO if cursor == 0 else hashes.get(cursor)
            if actual != expected:
                raise AutomationError("An external audit checkpoint conflicts with local history. Possible rollback or fork; archive delivery stopped.")
        _upload_immutable(sftp, directory, name, content, deadline)
    return name, checkpoint["last_id"]


def run_automation_cycle(force=False):
    from app import get_db
    from audit_integrity import verify_chain
    from backup import restore_pending
    from publication import publication_lock
    with publication_lock() as acquired:
        if not acquired:
            return {"status": "busy"}
        if restore_pending(Path(current_app.config["INSTANCE_PATH"])):
            return {"status": "restore_pending"}
        db = get_db()
        config = configuration()
        if not any(config[job + "_enabled"] for job in JOBS):
            return {"status": "disabled"}
        verify_chain(db, current_app.config["KEY_ENCRYPTION_SECRET"])
        checked, failures = 0, 0
        for job in JOBS:
            state = db.execute("SELECT * FROM automation_jobs WHERE name=?", (job,)).fetchone()
            if not config[job + "_enabled"] or (not force and state["next_attempt_at"] > time.time()):
                continue
            checked += 1
            attempt = datetime.now(UTC).isoformat()
            try:
                name, cursor = {"parent": _sync_parent, "backup": _external_backup, "audit": _external_audit}[job](db, config)
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE automation_jobs SET last_attempt=?,last_success=?,last_error='',failures=0,"
                           "next_attempt_at=?,last_object=?,last_cursor=? WHERE name=?",
                           (attempt, datetime.now(UTC).isoformat(), time.time() + _interval(config, job), name, cursor, job))
                if job == "backup":
                    _audit("automation.backup_delivered", job, name)
                db.commit()
            except Exception as exc:
                db.rollback()
                # Only our transport/validation diagnostics are safe; provider
                # errors, exception tracebacks and private material never reach UI.
                message = str(exc) if isinstance(exc, (AutomationError, MonitoringError, PublicationError)) else "The automation job failed validation or could not complete. Review its configuration and local state."
                failures += 1
                count = state["failures"] + 1
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE automation_jobs SET last_attempt=?,last_error=?,failures=?,next_attempt_at=? WHERE name=?",
                           (attempt, message, count, time.time() + min(3600, 60 * 2 ** min(count - 1, 6)), job))
                if state["last_error"] != message:
                    _audit("automation.failed", job, message)
                db.commit()
        return {"status": "failed" if failures else "checked", "checked": checked, "failed": failures}


def automation_findings(now=None):
    """No network work here: monitoring reuses durable execution results."""
    from app import get_db
    now = now or datetime.now(UTC)
    config = configuration()
    findings = []
    for state in get_db().execute("SELECT * FROM automation_jobs"):
        job = state["name"]
        if not config[job + "_enabled"]:
            continue
        title = {"parent": "Parent CRL synchronization", "backup": "External encrypted backup", "audit": "External audit archive"}[job]
        if state["last_error"]:
            findings.append({"key": f"automation:{job}:failure", "title": title,
                             "detail": state["last_error"], "signature": "failed:" + state["last_error"], "severity": "error"})
        last = datetime.fromisoformat(state["last_success"]) if state["last_success"] else None
        overdue = not last or (now - last).total_seconds() > _interval(config, job) + max(300, _interval(config, job) // 4)
        if overdue:
            findings.append({"key": f"automation:{job}:overdue", "title": title,
                             "detail": "No successful run has been recorded." if not last else f"The last successful run was {last.isoformat()}.",
                             "signature": "overdue", "severity": "warning"})
    return findings


def _integer(form, name, default, minimum, maximum):
    try:
        value = int(form.get(name, default))
        if not minimum <= value <= maximum:
            raise ValueError
        return value
    except (TypeError, ValueError) as exc:
        raise AutomationError(f"{name.replace('_', ' ').capitalize()} must be between {minimum} and {maximum}.") from exc


def form_configuration(saved):
    from app import current_authority
    from backup import recipient_public_key
    form = request.form
    values = {**saved, "installation_id": saved.get("installation_id") or secrets.token_hex(16)}
    for job in JOBS:
        values[job + "_enabled"] = form.get(job + "_enabled") == "on"
    for name, default, low, high in (("parent_interval_minutes", 60, 5, 10080),
                                   ("backup_interval_hours", 24, 1, 720),
                                   ("audit_interval_minutes", 15, 5, 10080),
                                   ("backup_retention", 14, 1, 365)):
        values[name] = _integer(form, name, default, low, high)
    values["parent_urls"] = [value.strip() for value in form.get("parent_urls", "").splitlines() if value.strip()]
    if len(values["parent_urls"]) > 8:
        raise AutomationError("At most eight parent CRL URLs are supported.")
    for url in values["parent_urls"]:
        validate_url(url)
    if values["parent_enabled"]:
        authority = current_authority()
        if not authority or authority["state"] != "active" or authority["role"] == "root":
            raise AutomationError("Parent CRL synchronization requires an activated subordinate CA.")
        parents = x509.load_pem_x509_certificates(authority["parent_chain_pem"].encode())
        if not 1 <= len(parents) == len(values["parent_urls"]):
            raise AutomationError("Provide one CRL URL per parent, ordered immediate issuer to root.")
        values["parent_authority_id"] = authority["id"]
    public_pem = form.get("backup_public_key", "").strip()
    values["backup_public_key"] = recipient_public_key(public_pem)[0] if public_pem else ""
    if values["backup_enabled"]:
        if not values["backup_public_key"]:
            raise AutomationError("Configure the public recovery key before enabling scheduled backups.")
        if (values["backup_public_key"] != saved.get("backup_public_key") or not saved.get("backup_enabled")) and form.get("recovery_key_saved") != "on":
            raise AutomationError("Confirm that the matching private recovery key is saved outside this CA host.")
    if values["backup_enabled"] or values["audit_enabled"]:
        for field in ("host", "username", "directory", "host_key_sha256", "auth_method"):
            values[field] = form.get(field, "").strip()
        values["port"] = _integer(form, "port", 22, 1, 65535)
        if values["auth_method"] not in {"key", "password"}:
            raise AutomationError("Select SSH key or password authentication.")
        changed = any(str(values.get(field, "")) != str(saved.get(field, ""))
                      for field in ("host", "port", "username", "host_key_sha256", "auth_method"))
        for field in SECRET_FIELDS:
            entered = form.get(field, "")
            values[field] = entered if entered or changed else saved.get(field, "")
        if values["auth_method"] == "password":
            values["private_key_pem"] = values["private_key_passphrase"] = ""
        else:
            values["password"] = ""
        try:
            values.update(validate_transport(values))
        except ValueError as exc:
            raise AutomationError(str(exc)) from exc
    return values


def _page(status=200):
    from app import current_authority, get_db
    from backup import provenance_fingerprint, recipient_public_key
    config = configuration()
    public = {key: value for key, value in config.items() if key not in SECRET_FIELDS}
    fingerprint = recipient_public_key(config["backup_public_key"])[1] if config["backup_public_key"] else ""
    jobs = {row["name"]: dict(row) for row in get_db().execute("SELECT * FROM automation_jobs")}
    checksum = jobs["backup"]["last_object"].rsplit("-", 1)[-1].removesuffix(".pkibackup")
    checksum = checksum if re.fullmatch(r"[0-9a-f]{64}", checksum) else ""
    return render_template("automation.html", title="Automation", provider=public,
                           credential_stored=bool(config.get("password") or config.get("private_key_pem")),
                           fingerprint=fingerprint, authority=current_authority(),
                           backup_checksum=checksum, provenance_fingerprint=provenance_fingerprint(),
                           jobs=jobs), status


@automation.route("/settings/automation", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    from app import get_db
    from backup import BackupError
    from mfa import MfaReauthenticationError, verify_reauthentication
    from publication import publication_lock
    if request.method == "GET":
        return _page()
    from approvals import approval_gate
    approval_response = approval_gate()
    if approval_response is not None:
        return approval_response
    db = get_db()
    try:
        with publication_lock() as acquired:
            if not acquired:
                raise AutomationError("Publication, backup or automation is running. Try again shortly.")
            db.execute("BEGIN IMMEDIATE")
            verify_reauthentication(db, request.form.get("totp_code", ""))
            values = form_configuration(configuration())
            _save(values)
            db.execute("UPDATE automation_jobs SET last_attempt=NULL,last_success=NULL,last_error='',"
                       "failures=0,next_attempt_at=0,last_cursor=0,last_object=''")
            _audit("automation.configured", "settings", ",".join(job for job in JOBS if values[job + "_enabled"]))
            db.commit()
        flash("Automation settings saved. Enabled jobs will run on the next worker tick.", "success")
        return redirect(url_for("automation.settings"))
    except (AutomationError, MonitoringError, BackupError, MfaReauthenticationError) as exc:
        db.rollback()
        flash(str(exc), "error")
        return _page(getattr(exc, "status_code", 400))


@automation.post("/settings/automation/run")
@require_roles("admin")
def run_now():
    from approvals import approval_gate
    approval_response = approval_gate()
    if approval_response is not None:
        return approval_response
    from app import get_db
    from mfa import MfaReauthenticationError, verify_reauthentication
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        verify_reauthentication(db, request.form.get("totp_code", ""))
        _audit("automation.requested", "all")
        db.commit()
    except MfaReauthenticationError as exc:
        db.rollback()
        flash(str(exc), "error")
        return _page(exc.status_code)
    result = run_automation_cycle(force=True)
    flash({"checked": "Enabled automation jobs completed.", "disabled": "No automation jobs are enabled.",
           "failed": "An automation job failed. Review the job status below.", "busy": "Publication, backup or automation is already running.",
           "restore_pending": "Recovery is pending; automation is paused."}[result["status"]],
          "success" if result["status"] == "checked" else "error" if result["status"] == "failed" else "warning")
    return redirect(url_for("automation.settings"))
