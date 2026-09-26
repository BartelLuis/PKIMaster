import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from audit_integrity import AuditIntegrityError, append_event, digest, init_audit, verify_chain


class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "audit.sqlite"
        self.secret = "test-only-secret"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.executescript("""CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, actor_id INTEGER, actor_name TEXT NOT NULL,
            action TEXT NOT NULL, object_type TEXT NOT NULL DEFAULT '', object_id TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '', remote_addr TEXT NOT NULL DEFAULT '');""")
        self.app = SimpleNamespace(config={"DATABASE": str(self.path), "KEY_ENCRYPTION_SECRET": self.secret})
        init_audit(self.app)

    def append(self, action="test.event"):
        append_event(self.db, self.secret, actor_name="admin", action=action)
        self.db.commit()

    def test_chain_is_atomic_and_append_only(self):
        self.append()
        first = verify_chain(self.db, self.secret)
        append_event(self.db, self.secret, actor_name="admin", action="rolled.back")
        self.db.rollback()
        self.assertEqual(first, verify_chain(self.db, self.secret))
        self.append("second")
        self.assertEqual(verify_chain(self.db, self.secret)["event_count"], 2)
        for sql in ("UPDATE audit_events SET detail='changed'", "DELETE FROM audit_events", "INSERT INTO audit_events (actor_name,action) VALUES ('fake','fake')"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql)
            self.db.rollback()

    def test_database_only_attacker_cannot_rehash_modified_history(self):
        self.append()
        self.db.row_factory = sqlite3.Row
        self.db.execute("DROP TRIGGER audit_no_update")
        row = dict(self.db.execute("SELECT * FROM audit_events").fetchone())
        row["detail"] = "forged"
        forged = digest(row, row["previous_hash"])
        self.db.execute("UPDATE audit_events SET detail=?,event_hash=?", (row["detail"], forged))
        self.db.execute("UPDATE audit_state SET head_hash=?", (forged,))
        self.db.commit()
        with self.assertRaises(AuditIntegrityError):
            verify_chain(self.db, self.secret)
        with self.assertRaises(AuditIntegrityError):
            init_audit(self.app)

    def test_tail_deletion_and_wrong_secret_are_detected(self):
        self.append()
        with self.assertRaises(AuditIntegrityError):
            verify_chain(self.db, "wrong-secret")
        self.db.execute("DROP TRIGGER audit_no_delete")
        self.db.execute("DELETE FROM audit_events")
        self.db.commit()
        with self.assertRaises(AuditIntegrityError):
            verify_chain(self.db, self.secret)

    def test_export_format_hashes_can_be_verified_without_secret(self):
        self.append()
        self.db.row_factory = sqlite3.Row
        row = dict(self.db.execute("SELECT * FROM audit_events").fetchone())
        row.pop("event_mac")
        portable = json.loads(json.dumps(row))
        self.assertEqual(digest(portable, portable["previous_hash"]), portable["event_hash"])

    def test_database_schema_downgrade_does_not_reseal_fabricated_history(self):
        self.append()
        self.db.execute("DROP TABLE audit_events")
        self.db.execute("DROP TABLE audit_state")
        self.db.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, actor_name TEXT, action TEXT)")
        self.db.execute("INSERT INTO audit_events VALUES (1,'forged','forged')")
        self.db.commit()
        with self.assertRaisesRegex(AuditIntegrityError, "rolled back"):
            init_audit(self.app)

    def test_upgrade_seals_legacy_records_and_records_boundary(self):
        self.db.close()
        other = Path(self.directory.name) / "legacy.sqlite"
        with closing(sqlite3.connect(other)) as db, db:
            db.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY,created_at TEXT,actor_id INTEGER,actor_name TEXT,action TEXT,object_type TEXT,object_id TEXT,detail TEXT,remote_addr TEXT)")
            db.execute("INSERT INTO audit_events VALUES (7,'2020-01-01',NULL,'system','legacy','','','','')")
        self.app.config["DATABASE"] = str(other)
        init_audit(self.app)
        with closing(sqlite3.connect(other)) as db:
            self.assertEqual(verify_chain(db, self.secret)["last_id"], 7)
            self.assertEqual(db.execute("SELECT legacy_count FROM audit_state").fetchone()[0], 1)
        init_audit(self.app)  # restarting verifies; it does not re-seal history
