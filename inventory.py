"""Certificate ownership, search, export and deployment monitoring settings."""
from __future__ import annotations

from contextlib import closing
import csv
from datetime import UTC, datetime, timedelta
import io
import ipaddress
import json
import sqlite3

from flask import Blueprint, Response, abort, flash, redirect, request, url_for

from enterprise import audit_event, can_manage, require_roles
from pki import _dns_name

inventory = Blueprint("inventory", __name__)
METADATA = {"owner": 150, "service_name": 150, "deployment_host": 253,
            "environment": 50, "tags": 500, "notes": 2000}


def init_inventory(app):
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(certificates)")}
        for name, definition in [*((name, "TEXT NOT NULL DEFAULT ''") for name in METADATA),
                                 ("tls_host", "TEXT NOT NULL DEFAULT ''"), ("tls_port", "INTEGER NOT NULL DEFAULT 443"),
                                 ("tls_server_name", "TEXT NOT NULL DEFAULT ''"), ("tls_enabled", "INTEGER NOT NULL DEFAULT 0")]:
            if name not in columns:
                db.execute(f"ALTER TABLE certificates ADD COLUMN {name} {definition}")
        db.execute("""CREATE TABLE IF NOT EXISTS certificate_endpoint_checks (
            certificate_id INTEGER PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,
            checked_at TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL,
            observed_sha256 TEXT NOT NULL DEFAULT '', observed_not_after TEXT NOT NULL DEFAULT '',
            observed_subject TEXT NOT NULL DEFAULT '')""")
    app.register_blueprint(inventory)


def search_filters(arguments):
    return {"q": arguments.get("q", "").strip()[:255],
            "status": arguments.get("status", "") if arguments.get("status", "") in {"active", "expiring", "expired", "revoked"} else "",
            "owner": arguments.get("owner", "").strip()[:150],
            "environment": arguments.get("environment", "").strip()[:50],
            "tag": arguments.get("tag", "").strip().lower()[:60]}


def _literal(value):
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search_query(filters):
    clauses, parameters = [], []
    if filters["q"]:
        fields = ("common_name", "subject_alt_names", "serial_number", "owner", "service_name", "deployment_host", "tags", "notes")
        clauses.append("(" + " OR ".join(f"c.{field} LIKE ? ESCAPE '\\'" for field in fields) + ")")
        parameters.extend([_literal(filters["q"])] * len(fields))
    for field in ("owner", "environment"):
        if filters[field]:
            clauses.append(f"c.{field} = ? COLLATE NOCASE")
            parameters.append(filters[field])
    if filters["tag"]:
        clauses.append("(',' || c.tags || ',') LIKE ? ESCAPE '\\'")
        parameters.append(_literal("," + filters["tag"] + ","))
    now = datetime.now(UTC).isoformat()
    state = filters["status"]
    if state == "revoked":
        clauses.append("c.revoked_at IS NOT NULL")
    elif state in {"expired", "active", "expiring"}:
        clauses.append("c.revoked_at IS NULL")
        if state == "expired":
            clauses.append("c.not_after <= ?")
            parameters.append(now)
        else:
            clauses.append("c.not_after > ?")
            parameters.append(now)
            if state == "expiring":
                clauses.append("c.not_after <= ?")
                parameters.append((datetime.now(UTC) + timedelta(days=30)).isoformat())
    return " AND ".join(clauses) or "1=1", parameters


def inventory_rows(db, filters, *, page=1, limit=50):
    where, parameters = search_query(filters)
    count = db.execute("SELECT COUNT(*) FROM certificates c WHERE " + where, parameters).fetchone()[0]
    rows = db.execute("""SELECT c.*,a.name AS authority_name,t.name AS template_name,
        e.status AS endpoint_status,e.checked_at AS endpoint_checked_at
        FROM certificates c JOIN authorities a ON a.id=c.authority_id
        LEFT JOIN certificate_templates t ON t.id=c.template_id
        LEFT JOIN certificate_endpoint_checks e ON e.certificate_id=c.id
        WHERE """ + where + " ORDER BY c.id DESC LIMIT ? OFFSET ?", [*parameters, limit, (page - 1) * limit]).fetchall()
    return rows, count


def _host(value):
    if not value or len(value) > 253 or "%" in value:
        raise ValueError("Use a hostname or IP address without a URL, path, wildcard or zone identifier.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        name = _dns_name(value)
        if "*" in name:
            raise ValueError("TLS monitoring requires a concrete hostname.")
        return name
    from monitoring_transports import _allowed_address
    if not _allowed_address(str(address)):
        raise ValueError("Loopback, link-local, metadata and reserved monitoring destinations are not permitted.")
    return str(address)


@inventory.post("/certificates/<int:certificate_id>/metadata")
@require_roles("admin", "operator")
def update_metadata(certificate_id):
    from app import get_db
    if not 0 < certificate_id <= 2**63 - 1:
        abort(404)
    db = get_db()
    try:
        values = {}
        for field, maximum in METADATA.items():
            value = request.form.get(field, "").strip()
            if len(value) > maximum or any(ord(char) < 32 and not (field == "notes" and char in "\n\r\t") for char in value):
                raise ValueError(f"Invalid {field.replace('_', ' ')}; maximum {maximum} characters.")
            values[field] = value
        tags = [part.strip().lower() for part in values["tags"].split(",") if part.strip()]
        if len(tags) > 20 or any(len(tag) > 60 for tag in tags):
            raise ValueError("Use at most 20 comma-separated tags of up to 60 characters.")
        values["tags"] = ",".join(dict.fromkeys(tags))
        db.execute("BEGIN IMMEDIATE")
        original = db.execute("SELECT * FROM certificates WHERE id=?", (certificate_id,)).fetchone()
        if original is None:
            abort(404)
        if can_manage("admin"):
            enabled = "tls_enabled" in request.form
            host = request.form.get("tls_host", "").strip()
            sni = request.form.get("tls_server_name", "").strip()
            try:
                port = int(request.form.get("tls_port", "443"))
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                raise ValueError("Use a TLS port between 1 and 65535.") from None
            if host or enabled:
                host = _host(host)
            if sni:
                sni = _host(sni)
            values.update(tls_enabled=int(enabled), tls_host=host, tls_port=port, tls_server_name=sni)
            if any(values[name] != original[name] for name in ("tls_enabled", "tls_host", "tls_port", "tls_server_name")):
                db.execute("DELETE FROM certificate_endpoint_checks WHERE certificate_id=?", (certificate_id,))
        elif any(name in request.form for name in ("tls_enabled", "tls_host", "tls_port", "tls_server_name")):
            abort(403)
        db.execute("UPDATE certificates SET " + ",".join(f"{name}=?" for name in values) + " WHERE id=?", (*values.values(), certificate_id))
        audit_event("certificate.metadata_updated", "certificate", str(certificate_id),
                    "Updated ownership, deployment information and permitted monitoring settings")
        db.commit()
        flash("Certificate information saved.", "success")
    except ValueError as error:
        db.rollback()
        flash(str(error), "error")
    return redirect(url_for("renewal.detail", certificate_id=certificate_id))


def copy_metadata(db, predecessor_id, successor_id):
    row = db.execute("SELECT * FROM certificates WHERE id=?", (predecessor_id,)).fetchone()
    fields = [*METADATA, "tls_host", "tls_port", "tls_server_name", "tls_enabled"]
    db.execute("UPDATE certificates SET " + ",".join(f"{field}=?" for field in fields) + " WHERE id=?",
               (*[row[field] for field in fields], successor_id))
    # A deployment follows the latest successor; the old certificate remains
    # recorded in history but must not produce contradictory endpoint alarms.
    db.execute("UPDATE certificates SET tls_enabled=0 WHERE id=?", (predecessor_id,))


def csv_cell(value):
    value = "" if value is None else str(value)
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        value = "'" + value
    return value


@inventory.get("/certificates/export.csv")
def export_csv():
    from app import get_db
    db = get_db()
    where, parameters = search_query(search_filters(request.args))
    rows = db.execute("""SELECT c.*,a.name AS authority_name FROM certificates c
        JOIN authorities a ON a.id=c.authority_id WHERE """ + where + " ORDER BY c.id DESC", parameters)
    fields = ("id", "common_name", "subject_alt_names", "serial_number", "authority_name", "profile", "not_before", "not_after",
              "revoked_at", "owner", "service_name", "deployment_host", "environment", "tags", "notes")
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(fields)
    for row in rows:
        writer.writerow([csv_cell(row[field]) for field in fields])
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": 'attachment; filename="pkimaster-certificates.csv"'})
