"""Read-only security posture and portable audit evidence for authenticated staff."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from flask import Blueprint, Response, current_app, render_template
from audit_integrity import AuditIntegrityError, verify_chain, _rows
from enterprise import require_roles

security = Blueprint("security", __name__)


@security.get("/security")
@require_roles("admin", "operator", "auditor")
def overview():
    from app import get_db, authority_block_reason
    db = get_db()
    # Read head and entries in one snapshot while other workers append.
    db.execute("BEGIN")
    error = ""
    try:
        checkpoint = verify_chain(db, current_app.config["KEY_ENCRYPTION_SECRET"])
    except AuditIntegrityError as exc:
        checkpoint, error = {}, str(exc)
    authority = db.execute("SELECT * FROM authorities LIMIT 1").fetchone()
    legacy = db.execute("SELECT legacy_count FROM audit_state WHERE id=1").fetchone()[0]
    admins = db.execute("SELECT COUNT(*) FROM users WHERE active=1 AND role='admin' AND mfa_secret IS NOT NULL").fetchone()[0]
    return render_template("security.html", title="Security posture", checkpoint=checkpoint, integrity_error=error,
                           authority=authority, block_reason=authority_block_reason(authority) if authority else "No CA initialized.",
                           legacy_events=legacy, enrolled_admins=admins)


@security.get("/security/audit-export")
@require_roles("admin", "auditor")
def export():
    from app import get_db
    db = get_db()
    db.execute("BEGIN")
    try:
        checkpoint = verify_chain(db, current_app.config["KEY_ENCRYPTION_SECRET"])
    except AuditIntegrityError:
        return Response("Audit integrity verification failed; export refused.", status=409)
    records = list(_rows(db, "SELECT * FROM audit_events ORDER BY id"))
    for record in records:
        record.pop("event_mac")  # HMACs remain server verification data, not exported credentials.
    data = {"format": "pkimaster-audit-v1", "exported_at": datetime.now(UTC).isoformat(),
            "checkpoint": checkpoint, "legacy_events": db.execute("SELECT legacy_count FROM audit_state WHERE id=1").fetchone()[0], "events": records}
    return Response(json.dumps(data, ensure_ascii=True, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": 'attachment; filename="pkimaster-audit.json"'})
