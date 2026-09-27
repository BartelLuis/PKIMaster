"""Authenticated complete-state backups and fresh-install recovery.

Only the HTTPS supervisor installs staged restores, with its workers stopped.
The archive format fixes its KDF cost and never extracts arbitrary ZIP paths.
"""
from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager
from datetime import UTC, datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import sqlite3
import ssl
import stat
import tempfile
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask import Blueprint, Response, abort, current_app, flash, render_template, request, session

from enterprise import _local_setup_request, _read_secrets, _verify_existing_keys, audit_event, require_roles


backup = Blueprint("backup", __name__)
MAGIC = b"PKIMASTER-BACKUP\x00\x01"
MAX_BYTES = 128 * 1024 * 1024
MAX_FILES = 10000
MARKER = ".restore-pending.json"
REQUIRED_FILES = {"pkimaster.sqlite", "runtime-secrets.json", "pkimaster.audit-sealed"}
OPTIONAL_FILES = {"server-tls/bootstrap.pem", "server-tls/uploaded.pem", "softhsm/softhsm2.conf"}


class BackupError(ValueError):
    """An actionable, secret-free backup or restore error."""


class RestoreBusy(BackupError):
    """A background worker is still finishing; retry without installing files."""


def _password(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or not 20 <= len(passphrase) <= 256:
        raise BackupError("Use a backup passphrase between 20 and 256 characters.")
    return passphrase.encode("utf-8")


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    # 128 MiB, fixed for format v1. Untrusted headers cannot select KDF work.
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(_password(passphrase))


def encrypt_archive(plaintext: bytes, passphrase: str) -> bytes:
    if len(plaintext) > MAX_BYTES:
        raise BackupError("The backup exceeds the 128 MiB archive limit.")
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, plaintext, header)


def decrypt_archive(encrypted: bytes, passphrase: str) -> bytes:
    header_size = len(MAGIC) + 28
    if not header_size + 16 <= len(encrypted) <= MAX_BYTES + header_size + 16 or not encrypted.startswith(MAGIC):
        raise BackupError("This is not a supported PKIMaster backup, or it exceeds 128 MiB.")
    header = encrypted[:header_size]
    salt, nonce = header[len(MAGIC):len(MAGIC) + 16], header[-12:]
    try:
        return AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, encrypted[header_size:], header)
    except InvalidTag as exc:
        raise BackupError("The backup passphrase is incorrect or the archive has been damaged.") from exc


def _allowed_name(name: str) -> bool:
    path = PurePosixPath(name)
    if (not name or len(name) > 512 or "\\" in name or ":" in name or path.is_absolute()
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or any(ord(character) < 32 for character in name)):
        return False
    if name in REQUIRED_FILES | OPTIONAL_FILES:
        return True
    return (len(path.parts) >= 3 and path.parts[:2] == ("softhsm", "tokens")
            and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and not part.endswith(".")
                    and part.upper().split(".")[0] not in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
                    for part in path.parts[2:]))


def _regular_file(path: Path, root: Path) -> bytes:
    relative = path.relative_to(root)
    parent = root
    for part in relative.parts:
        parent = parent / part
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400):
            raise BackupError("Backups cannot include symbolic links or junctions.")
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > MAX_BYTES:
        raise BackupError("A backup member is not a regular file or exceeds 128 MiB.")
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise BackupError("A backup member exceeds 128 MiB.")
    return data


def _files_from_state(root: Path) -> dict[str, bytes]:
    files = {}
    for name in sorted((REQUIRED_FILES | OPTIONAL_FILES) - {"pkimaster.sqlite"}):
        path = root / name
        if path.exists() or path.is_symlink():
            files[name] = _regular_file(path, root)
        elif name in REQUIRED_FILES:
            raise BackupError("A required installation state file is missing; repair the installation before backing up.")
    token_root = root / "softhsm" / "tokens"
    if token_root.exists() or token_root.is_symlink():
        for directory in (root / "softhsm", token_root):
            if directory.is_symlink() or bool(getattr(directory.lstat(), "st_file_attributes", 0) & 0x400):
                raise BackupError("Backups cannot include symbolic links or junctions.")
        # Walk without following symlinks, rejecting directory links as well.
        for directory, directories, filenames in os.walk(token_root, followlinks=False):
            for name in directories:
                candidate = Path(directory) / name
                if candidate.is_symlink() or bool(getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400):
                    raise BackupError("Backups cannot include symbolic links or junctions.")
            for filename in filenames:
                path = Path(directory) / filename
                name = path.relative_to(root).as_posix()
                if not _allowed_name(name):
                    raise BackupError("The managed SoftHSM store contains an unsupported filename.")
                files[name] = _regular_file(path, root)
                if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES:
                    raise BackupError("The local state exceeds the backup size or file-count limit.")
    return files


def pack_snapshot(files: dict[str, bytes]) -> bytes:
    if not REQUIRED_FILES <= files.keys() or any(not _allowed_name(name) for name in files):
        raise BackupError("The snapshot has missing or unsupported state files.")
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES:
        raise BackupError("The local state exceeds the backup size or file-count limit.")
    manifest = {"format": 1, "created_at": datetime.now(UTC).isoformat(),
                "files": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in sorted(files.items())}}
    output = io.BytesIO()
    # Uncompressed members avoid decompression bombs and produce a bounded format.
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True).encode())
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    data = output.getvalue()
    if len(data) > MAX_BYTES:
        raise BackupError("The backup exceeds the 128 MiB archive limit.")
    return data


def unpack_snapshot(plaintext: bytes) -> dict[str, bytes]:
    if len(plaintext) > MAX_BYTES:
        raise BackupError("The backup exceeds the 128 MiB archive limit.")
    try:
        with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if (len(names) > MAX_FILES + 1 or len(set(names)) != len(names) or "manifest.json" not in names
                    or not REQUIRED_FILES <= set(names) or any(name != "manifest.json" and not _allowed_name(name) for name in names)):
                raise BackupError("The backup contains missing, duplicate, or unsupported state files.")
            if (sum(item.file_size for item in members) > MAX_BYTES
                    or any(item.compress_type != zipfile.ZIP_STORED or item.flag_bits & 1
                           or stat.S_ISLNK(item.external_attr >> 16) or item.is_dir()
                           or item.file_size != item.compress_size for item in members)):
                raise BackupError("The backup contains unsupported archive entries.")
            manifest_info = archive.getinfo("manifest.json")
            if manifest_info.file_size > 2 * 1024 * 1024:
                raise BackupError("The backup manifest is too large.")
            manifest = json.loads(archive.read(manifest_info))
            if not isinstance(manifest, dict) or manifest.get("format") != 1 or not isinstance(manifest.get("files"), dict):
                raise BackupError("The backup manifest is invalid.")
            if set(manifest["files"]) != set(names) - {"manifest.json"}:
                raise BackupError("The backup manifest does not match its state files.")
            files = {}
            for name in names:
                if name == "manifest.json":
                    continue
                data = archive.read(name)
                expected = manifest["files"][name]
                if expected != {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
                    raise BackupError("A backup member failed integrity verification.")
                files[name] = data
            return files
    except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError, KeyError, TypeError, RuntimeError, NotImplementedError) as exc:
        raise BackupError("The backup archive is invalid.") from exc


def _sync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _private_directory(path: Path) -> None:
    if path.exists():
        return
    _private_directory(path.parent)
    path.mkdir(mode=0o700)
    _sync_directory(path.parent)


def _write_private(path: Path, data: bytes) -> None:
    _private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    _sync_directory(path.parent)


def _atomic_private(path: Path, data: bytes) -> None:
    _private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".restore-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate_snapshot(directory: Path) -> dict:
    """Read-only checks before admitting an archive or modifying a destination."""
    from audit_integrity import AuditIntegrityError, verify_chain
    database = directory / "pkimaster.sqlite"
    try:
        payload = _read_secrets(directory / "runtime-secrets.json")
        if (directory / "pkimaster.audit-sealed").read_text(encoding="ascii") != "PKIMaster audit schema 1\n":
            raise BackupError("The backup is missing its sealed audit marker.")
        with closing(sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)) as db:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
                raise BackupError("The backup database failed integrity checks.")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"users", "settings", "authorities", "certificates", "audit_events", "audit_state"} <= tables:
                raise BackupError("The backup does not contain a complete PKIMaster installation.")
            if not db.execute("SELECT 1 FROM users WHERE active=1 AND role='admin' AND mfa_secret IS NOT NULL").fetchone():
                raise BackupError("The backup has no active administrator with an enrolled authenticator.")
            if db.execute("SELECT COUNT(*) FROM authorities WHERE revoked_at IS NULL").fetchone()[0] > 1:
                raise BackupError("The backup has more than one current CA.")
            verify_chain(db, payload["KEY_ENCRYPTION_SECRET"])
            authorities = db.execute("SELECT name, key_backend FROM authorities ORDER BY id").fetchall()
        _verify_existing_keys(database, payload["KEY_ENCRYPTION_SECRET"])
        for name in ("bootstrap.pem", "uploaded.pem"):
            path = directory / "server-tls" / name
            if path.exists():
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(path))
        return {"authorities": [row[0] for row in authorities],
                "external_keys": any(row[1] != "software" for row in authorities)}
    except BackupError:
        raise
    except (sqlite3.Error, RuntimeError, OSError, ValueError, AuditIntegrityError) as exc:
        raise BackupError("The backup database, audit chain, encrypted credentials, or HTTPS identity could not be verified.") from exc


def create_snapshot(db) -> bytes:
    """Hold the app writer lock across SQLite backup and local key/TLS capture."""
    root = Path(current_app.config["INSTANCE_PATH"]).resolve()
    database = Path(current_app.config["DATABASE"]).resolve()
    if database != root / "pkimaster.sqlite":
        raise BackupError("Browser backups require pkimaster.sqlite inside the installation state directory.")
    if db.in_transaction:
        raise RuntimeError("Snapshot requires a connection without an active transaction.")
    db.execute("BEGIN IMMEDIATE")
    try:
        with tempfile.TemporaryDirectory(prefix=".backup-", dir=root) as temporary:
            staging = Path(temporary)
            snapshot = staging / "pkimaster.sqlite"
            # A separate read connection can copy the last committed state while
            # this connection prevents app writers from changing files or SQLite.
            with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as source, closing(sqlite3.connect(snapshot)) as target:
                source.backup(target)
            if os.name != "nt":
                snapshot.chmod(0o600)
            files = _files_from_state(root)
            files["pkimaster.sqlite"] = _regular_file(snapshot, staging)
            for name, data in files.items():
                if name != "pkimaster.sqlite":
                    _write_private(staging / name, data)
            validate_snapshot(staging)
            return pack_snapshot(files)
    finally:
        db.rollback()


def restore_pending(directory: Path) -> bool:
    return (Path(directory) / MARKER).exists()


def stage_restore(db, files: dict[str, bytes]) -> dict:
    root = Path(current_app.config["INSTANCE_PATH"]).resolve()
    if Path(current_app.config["DATABASE"]).resolve() != root / "pkimaster.sqlite":
        raise BackupError("Browser recovery requires pkimaster.sqlite inside the installation state directory.")
    staging = root / (".restore-" + secrets.token_hex(16))
    _private_directory(staging)
    staged = False
    try:
        for name, data in files.items():
            if not _allowed_name(name):
                raise BackupError("The backup contains an unsupported state filename.")
            _write_private(staging / name, data)
        details = validate_snapshot(staging)
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone() or db.execute("SELECT 1 FROM authorities LIMIT 1").fetchone():
            raise BackupError("Restore is available only on a fresh installation before creating an administrator.")
        if restore_pending(root):
            raise BackupError("A restore has already been staged. Wait for the HTTPS service to restart.")
        listener = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('listen_address','https_port')"))
        # Revoke cookies and transient authentication flows from the source host.
        # The encryption secret and all CA key identities remain unchanged.
        with closing(sqlite3.connect(staging / "pkimaster.sqlite")) as restored, restored:
            restored.execute("UPDATE users SET session_version=session_version+1")
            restored.execute("UPDATE users SET mfa_pending_secret=NULL, mfa_pending_created=NULL")
            if "mfa_pending_token_hash" in {row[1] for row in restored.execute("PRAGMA table_info(users)")}:
                restored.execute("UPDATE users SET mfa_pending_token_hash=NULL")
            for table in ("oidc_flows",):
                if restored.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    restored.execute(f"DELETE FROM {table}")
            restored.executemany("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                 [("listen_address", listener.get("listen_address", "127.0.0.1")), ("https_port", listener.get("https_port", "8443"))])
            from audit_integrity import append_event
            payload = _read_secrets(staging / "runtime-secrets.json")
            append_event(restored, payload["KEY_ENCRYPTION_SECRET"], actor_name="system", action="backup.restored",
                         object_type="installation", detail="Fresh-host recovery; source sessions invalidated; destination HTTPS listener retained")
        # The signing secret is regenerated to invalidate even cookies from very
        # old snapshots whose session version might otherwise collide.
        payload["SECRET_KEY"] = secrets.token_urlsafe(48)
        _atomic_private(staging / "runtime-secrets.json", json.dumps(payload).encode())
        token_path = staging / "softhsm" / "softhsm2.conf"
        if token_path.exists():
            _atomic_private(token_path, (f"directories.tokendir = {(root / 'softhsm' / 'tokens').as_posix()}\n"
                                        "objectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n").encode())
        _sync_directory(staging)
        marker = {"stage": staging.name, "phase": "prepared"}
        _write_private(root / MARKER, json.dumps(marker).encode())
        staged = True
        db.commit()
        return details
    except BaseException:
        db.rollback()
        raise
    finally:
        if not staged:
            _remove_stage(root, staging)


def _safe_stage(root: Path, marker: dict) -> Path:
    name = marker.get("stage", "")
    if not isinstance(name, str) or not re.fullmatch(r"\.restore-[0-9a-f]{32}", name):
        raise BackupError("The pending restore marker is invalid.")
    stage = root / name
    if stage.is_symlink() or (stage.exists() and bool(getattr(stage.lstat(), "st_file_attributes", 0) & 0x400)):
        raise BackupError("The pending restore directory is unsafe.")
    return stage


def _remove_stage(root: Path, stage: Path) -> None:
    if stage.resolve().parent != root.resolve() or not re.fullmatch(r"\.restore-[0-9a-f]{32}", stage.name) or stage.is_symlink():
        raise BackupError("The recovery staging directory is outside the installation state directory.")
    if stage.exists():
        shutil.rmtree(stage)
        _sync_directory(root)


@contextmanager
def _worker_lock(path: Path):
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
            except OSError as exc:
                raise RestoreBusy("A background worker is finishing; recovery will retry shortly.") from exc
        else:
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError as exc:
                raise RestoreBusy("A background worker is finishing; recovery will retry shortly.") from exc
        yield
    finally:
        if acquired:
            if os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def apply_pending_restore(directory: Path) -> bool:
    """Install a validated restore while ALL web/worker processes are stopped.

    The marker is a restart journal: after a crash the same validated files are
    installed again before any application process is started.
    """
    root = Path(directory).resolve()
    marker_path = root / MARKER
    if not marker_path.exists():
        return False
    with ExitStack() as locks:
        # Share the existing worker locks; startup is gated before migration.
        for name in ("runtime-startup.lock", "publication.lock", "monitoring.lock"):
            locks.enter_context(_worker_lock(root / name))
        return _install_restore(root, marker_path)


def _install_restore(root: Path, marker_path: Path) -> bool:
    try:
        marker = json.loads(_regular_file(marker_path, root))
        if not isinstance(marker, dict) or marker.get("phase") not in {"prepared", "installing", "complete"}:
            raise BackupError("The pending restore marker is invalid.")
        staging = _safe_stage(root, marker)
        if marker["phase"] == "complete":
            _remove_stage(root, staging)
            marker_path.unlink()
            _sync_directory(root)
            return True
        files = _files_from_state(staging)
        files["pkimaster.sqlite"] = _regular_file(staging / "pkimaster.sqlite", staging)
        validate_snapshot(staging)
        if marker["phase"] == "prepared":
            with closing(sqlite3.connect(f"{(root / 'pkimaster.sqlite').as_uri()}?mode=ro", uri=True)) as db:
                if db.execute("SELECT 1 FROM users LIMIT 1").fetchone() or db.execute("SELECT 1 FROM authorities LIMIT 1").fetchone():
                    raise BackupError("The destination is no longer a fresh installation. Recovery stopped.")
            marker["phase"] = "installing"
            _atomic_private(marker_path, json.dumps(marker).encode())
        # No target traversal may leave the service state directory, even if a
        # manually prepared destination contains a link or junction.
        for name in files:
            target = root / name
            for parent in (target, *target.parents):
                if parent == root:
                    break
                if parent.is_symlink() or (parent.exists() and bool(getattr(parent.lstat(), "st_file_attributes", 0) & 0x400)):
                    raise BackupError("The destination contains a symbolic link or junction.")
        for name in ("pkimaster.sqlite-wal", "pkimaster.sqlite-shm", "pkimaster.sqlite-journal", "runtime-https.json", "server-tls/runtime.pem"):
            (root / name).unlink(missing_ok=True)
        for name in OPTIONAL_FILES - files.keys():
            (root / name).unlink(missing_ok=True)
        # The database is replaced last. The pending marker blocks all readers
        # for the entire sequence and is removed only after final validation.
        for name in sorted(files, key=lambda item: item == "pkimaster.sqlite"):
            _atomic_private(root / name, files[name])
        validate_snapshot(root)
        marker["phase"] = "complete"
        _atomic_private(marker_path, json.dumps(marker).encode())
        _remove_stage(root, staging)
        marker_path.unlink()
        _sync_directory(root)
        return True
    except (OSError, json.JSONDecodeError, sqlite3.Error) as exc:
        raise BackupError("The staged restore could not be installed. Preserve the state directory and restart after resolving the storage error.") from exc


def init_backup(app) -> None:
    app.register_blueprint(backup)

    @app.before_request
    def restore_gate():
        if request.endpoint == "backup.restore":
            request.max_content_length = MAX_BYTES + 64 * 1024
        if restore_pending(Path(app.config["INSTANCE_PATH"])) and request.endpoint != "static":
            return Response("Recovery is being installed. The packaged HTTPS service restarts automatically. "
                            "Wait a few seconds, then reload this page. Custom WSGI installations must stop all workers "
                            "and run the documented recovery command before restarting.", status=503,
                            headers={"Retry-After": "5", "Cache-Control": "no-store"})


@backup.get("/settings/backup")
@require_roles("admin")
def settings():
    return render_template("backup.html", title="Backup and recovery")


@backup.post("/settings/backup/export")
@require_roles("admin")
def export():
    from app import get_db
    from mfa import MfaReauthenticationError, verify_reauthentication
    from publication import publication_lock
    db = get_db()
    try:
        passphrase = request.form.get("passphrase", "")
        _password(passphrase)
        if passphrase != request.form.get("passphrase_confirm", ""):
            raise BackupError("The backup passphrases do not match.")
        with publication_lock() as acquired:
            if not acquired:
                raise BackupError("CA publication or another backup is running. Try again shortly.")
            db.execute("BEGIN IMMEDIATE")
            verify_reauthentication(db, request.form.get("totp_code", "").strip())
            audit_event("backup.created", "installation", detail="Encrypted complete-state archive requested")
            db.commit()
            plaintext = create_snapshot(db)
            encrypted = encrypt_archive(plaintext, passphrase)
        filename = "pkimaster-backup-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".pkibackup"
        return Response(encrypted, mimetype="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})
    except MfaReauthenticationError as exc:
        db.rollback()
        flash(str(exc), "error")
        return render_template("backup.html", title="Backup and recovery"), exc.status_code
    except (BackupError, OSError, sqlite3.Error) as exc:
        db.rollback()
        # Never expose database contents, filesystem paths or provider secrets.
        flash(str(exc) if isinstance(exc, BackupError) else "The backup could not be created. Check free disk space and try again.", "error")
        return render_template("backup.html", title="Backup and recovery"), 400


@backup.route("/restore", methods=["GET", "POST"])
def restore():
    from app import get_db
    db = get_db()
    if not _local_setup_request():
        abort(403)
    if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        abort(404)
    if request.method == "POST":
        try:
            if request.form.get("source_stopped") != "on":
                raise BackupError("Confirm that the original installation is stopped before restoring its CA identity.")
            uploaded = request.files.get("archive")
            if not uploaded or not uploaded.filename:
                raise BackupError("Select a PKIMaster .pkibackup archive.")
            encrypted = uploaded.read(MAX_BYTES + len(MAGIC) + 45)
            plaintext = decrypt_archive(encrypted, request.form.get("passphrase", ""))
            files = unpack_snapshot(plaintext)
            details = stage_restore(db, files)
            session.clear()
            return render_template("backup_restored.html", title="Recovery prepared", details=details), 202
        except (BackupError, OSError, sqlite3.Error) as exc:
            db.rollback()
            flash(str(exc) if isinstance(exc, BackupError) else "Recovery could not be staged. Check free disk space and try again.", "error")
            return render_template("backup_restore.html", title="Restore installation"), 400
    return render_template("backup_restore.html", title="Restore installation")
