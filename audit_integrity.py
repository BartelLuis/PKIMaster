"""Append-only, authenticated audit chain; external checkpoints detect rollback."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

FIELDS = ("id", "created_at", "actor_id", "actor_name", "action", "object_type", "object_id", "detail", "remote_addr")
ZERO = "0" * 64


class AuditIntegrityError(RuntimeError):
    pass


def _key(secret):
    return hmac.digest(str(secret).encode(), b"PKIMaster audit chain v1", "sha256")


def digest(record, previous):
    payload = json.dumps({name: record[name] for name in FIELDS}, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256((previous + "\n" + payload).encode()).hexdigest()


def _rows(db, sql, args=()):
    cursor = db.execute(sql, args)
    names = [column[0] for column in cursor.description]
    return (dict(zip(names, row)) for row in cursor)


def verify_chain(db, secret):
    db.execute("SAVEPOINT audit_verification")
    try:
        return _verify_chain(db, secret)
    finally:
        db.execute("RELEASE audit_verification")


def _verify_chain(db, secret):
    previous, count, last_id = ZERO, 0, 0
    for row in _rows(db, "SELECT * FROM audit_events ORDER BY id"):
        expected = digest(row, previous)
        if (row["id"] <= last_id or row["previous_hash"] != previous
                or not hmac.compare_digest(row["event_hash"], expected)
                or not hmac.compare_digest(row["event_mac"], hmac.new(_key(secret), expected.encode(), "sha256").hexdigest())):
            raise AuditIntegrityError("Audit integrity verification failed. Preserve the state and investigate before resuming operation.")
        previous, last_id, count = expected, row["id"], count + 1
    state = db.execute("SELECT event_count, last_id, head_hash FROM audit_state WHERE id=1").fetchone()
    if not state or tuple(state) != (count, last_id, previous):
        raise AuditIntegrityError("Audit checkpoint does not match the stored records.")
    return {"event_count": count, "last_id": last_id, "head_hash": previous}


def append_event(db, secret, *, actor_name, action, actor_id=None, object_type="", object_id="", detail="", remote_addr=""):
    # Serialize readers of the chain head with all other writers. Keep the caller's
    # transaction: an operation and its evidence must commit or roll back together.
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    head = db.execute("SELECT event_count, last_id, head_hash FROM audit_state WHERE id=1").fetchone()
    tail = db.execute("SELECT id, event_hash, event_mac FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    tail_record = next(_rows(db, "SELECT * FROM audit_events ORDER BY id DESC LIMIT 1"), None)
    if not head or (tail and (tail[0] != head[1] or tail[1] != head[2]
            or digest(tail_record, tail_record["previous_hash"]) != tail[1]
            or not hmac.compare_digest(tail[2], hmac.new(_key(secret), tail[1].encode(), "sha256").hexdigest()))) or (not tail and tuple(head) != (0, 0, ZERO)):
        raise AuditIntegrityError("Audit chain head is invalid; operation refused.")
    record = dict(id=head[1] + 1, created_at=datetime.now(UTC).isoformat(), actor_id=actor_id,
                  actor_name=actor_name, action=action, object_type=object_type,
                  object_id=str(object_id), detail=detail, remote_addr=remote_addr)
    event_hash = digest(record, head[2])
    event_mac = hmac.new(_key(secret), event_hash.encode(), "sha256").hexdigest()
    db.execute("INSERT INTO audit_events (" + ",".join(FIELDS) + ",previous_hash,event_hash,event_mac) VALUES (" + ",".join("?" for _ in range(12)) + ")",
               tuple(record[name] for name in FIELDS) + (head[2], event_hash, event_mac))


def init_audit(app):
    secret = app.config["KEY_ENCRYPTION_SECRET"]
    marker = Path(app.config["DATABASE"]).with_suffix(".audit-sealed")
    with closing(sqlite3.connect(app.config["DATABASE"], timeout=30)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        columns = {row[1] for row in db.execute("PRAGMA table_info(audit_events)")}
        if marker.exists() and "event_hash" not in columns:
            raise AuditIntegrityError("The sealed audit schema has been removed or rolled back. Preserve the state for investigation.")
        if "event_hash" not in columns:
            for name in ("previous_hash", "event_hash", "event_mac"):
                db.execute(f"ALTER TABLE audit_events ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
            db.execute("CREATE TABLE audit_state (id INTEGER PRIMARY KEY CHECK(id=1), event_count INTEGER NOT NULL, last_id INTEGER NOT NULL, head_hash TEXT NOT NULL, legacy_count INTEGER NOT NULL)")
            previous, count, last_id = ZERO, 0, 0
            for row in list(_rows(db, "SELECT * FROM audit_events ORDER BY id")):
                event_hash = digest(row, previous)
                mac = hmac.new(_key(secret), event_hash.encode(), "sha256").hexdigest()
                db.execute("UPDATE audit_events SET previous_hash=?,event_hash=?,event_mac=? WHERE id=?", (previous, event_hash, mac, row["id"]))
                previous, last_id, count = event_hash, row["id"], count + 1
            db.execute("INSERT INTO audit_state VALUES (1,?,?,?,?)", (count, last_id, previous, count))
        verify_chain(db, secret)
        # Do not executescript here: its implicit commit would split migration.
        for statement in (
            "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'Audit records are append-only'); END",
            "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'Audit records are append-only'); END",
            "CREATE TRIGGER IF NOT EXISTS audit_check_insert BEFORE INSERT ON audit_events WHEN length(NEW.event_hash)!=64 OR length(NEW.event_mac)!=64 OR NEW.previous_hash!=(SELECT head_hash FROM audit_state WHERE id=1) OR NEW.id!=(SELECT last_id+1 FROM audit_state WHERE id=1) BEGIN SELECT RAISE(ABORT,'Invalid audit chain append'); END",
            "CREATE TRIGGER IF NOT EXISTS audit_advance AFTER INSERT ON audit_events BEGIN UPDATE audit_state SET event_count=event_count+1,last_id=NEW.id,head_hash=NEW.event_hash WHERE id=1; END",
        ):
            db.execute(statement)
    # Kept outside SQLite so a database-only attacker cannot downgrade to the
    # legacy schema and make startup authenticate fabricated historical records.
    # Publish after the migration commits; a crash before this point is safe to
    # recover because an existing chain is verified, never resealed.
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write("PKIMaster audit schema 1\n")
            output.flush()
            os.fsync(output.fileno())
