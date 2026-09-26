from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from flask import Flask, Response, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from enterprise import audit_event, can_manage, configure_runtime, get_setting, init_enterprise
from pki import REVOCATION_REASONS, build_crl, create_ca_certificate, issue_end_entity_certificate, valid_parent_child_roles


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_positive_int(raw_value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return default
    return min(max(value, minimum), maximum)


def key_download_enabled() -> bool:
    return can_manage("admin") and bool(get_setting("allow_key_export", False))


def private_key_cipher() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(current_app.config["KEY_ENCRYPTION_SECRET"].encode("utf-8")).digest())
    return Fernet(key)


def encrypt_private_key(private_key_pem: str) -> str:
    return private_key_cipher().encrypt(private_key_pem.encode("utf-8")).decode("utf-8")


def decrypt_private_key(encrypted_private_key: str) -> str:
    return private_key_cipher().decrypt(encrypted_private_key.encode("utf-8")).decode("utf-8")


def get_csrf_token() -> str:
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def validate_csrf() -> bool:
    submitted = request.form.get("csrf_token", "")
    stored = session.get("csrf_token", "")
    return bool(submitted and stored) and compare_digest(submitted.encode(), stored.encode())


def authority_is_active(authority: sqlite3.Row) -> bool:
    """A revoked or expired ancestor disables signing throughout its subtree."""
    seen = set()
    while authority is not None:
        if authority["id"] in seen:
            return False
        seen.add(authority["id"])
        if (authority["revoked_at"] or datetime.fromisoformat(authority["not_after"]) <= utc_now()
                or datetime.fromisoformat(authority["not_before"]) > utc_now()):
            return False
        if authority["parent_id"] is None:
            return True
        authority = get_authority(authority["parent_id"])
    return False


def crl_distribution_url(authority_id: int) -> str | None:
    base = get_setting("public_base_url", "").rstrip("/")
    return f"{base}/crl/{authority_id}.crl" if base else None


def create_app(test_config: dict | None = None) -> Flask:
    templates = Path(__file__).parent / "templates"
    if not templates.is_dir():
        templates = Path(sys.prefix) / "share" / "pkimaster" / "templates"
    app = Flask(__name__, template_folder=str(templates))
    instance_path = Path((test_config or {}).get("INSTANCE_PATH", Path(__file__).parent / "instance"))
    app.config.update(INSTANCE_PATH=str(instance_path), DATABASE=str(instance_path / "pkimaster.sqlite"),
                      MAX_CONTENT_LENGTH=1024 * 1024, SESSION_COOKIE_SECURE=True)
    if test_config:
        app.config.update(test_config)
    configure_runtime(app)
    init_db(app)

    @app.teardown_appcontext
    def close_db(_: object | None) -> None:
        database = g.pop("db", None)
        if database is not None:
            database.close()

    app.jinja_env.globals["csrf_token"] = get_csrf_token
    init_enterprise(app)

    @app.get("/")
    def index() -> str:
        authorities = list_authorities()
        active_authority_ids = {item["id"] for item in authorities if authority_is_active(item)}
        issuing = [item for item in authorities if item["role"] == "issuing" and item["id"] in active_authority_ids]
        query = request.args.get("q", "").strip()[:255]
        page = parse_positive_int(request.args.get("page"), 1, 1, 1000000)
        # Escape LIKE metacharacters so the browser search is a literal substring.
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        db = get_db()
        total = db.execute("SELECT COUNT(*) FROM certificates WHERE common_name LIKE ? ESCAPE '\\'", (pattern,)).fetchone()[0]
        certificates = db.execute(
            """SELECT certificates.*, authorities.name AS authority_name
               FROM certificates JOIN authorities ON authorities.id = certificates.authority_id
               WHERE certificates.common_name LIKE ? ESCAPE '\\'
               ORDER BY certificates.id DESC LIMIT 50 OFFSET ?""", (pattern, (page - 1) * 50)
        ).fetchall()
        counts = db.execute("""SELECT COUNT(*) AS total,
            COALESCE(SUM(revoked_at IS NOT NULL), 0) AS revoked,
            COALESCE(SUM(revoked_at IS NULL AND not_after <= ?), 0) AS expired,
            COALESCE(SUM(revoked_at IS NULL AND not_after > ? AND not_after <= ?), 0) AS expiring
            FROM certificates""", (utc_now().isoformat(), utc_now().isoformat(), (utc_now() + timedelta(days=30)).isoformat())).fetchone()
        return render_template("index.html", title="Certificate inventory", authorities=authorities,
                               certificates=certificates, issuing_authorities=issuing,
                               active_authority_ids=active_authority_ids, key_download_enabled=key_download_enabled(),
                               revocation_reasons=REVOCATION_REASONS, now=utc_now().isoformat(),
                               counts=counts, query=query, page=page, total=total, max_leaf_days=int(get_setting("max_leaf_days", 397)))

    @app.get("/authorities/<int:authority_id>")
    def authority_detail(authority_id: int) -> str | Response:
        authority = get_authority(authority_id)
        if authority is None:
            return Response("Not found", status=404)
        db = get_db()
        children = db.execute("SELECT id, name, role FROM authorities WHERE parent_id = ? ORDER BY id", (authority_id,)).fetchall()
        certificates = db.execute("SELECT id, common_name FROM certificates WHERE authority_id = ? ORDER BY id DESC LIMIT 100", (authority_id,)).fetchall()
        return render_template("authority_detail.html", title=authority["name"], authority=authority,
                               child_authorities=children, issued_certificates=certificates,
                               active=authority_is_active(authority), revocation_reasons=REVOCATION_REASONS,
                               key_download_enabled=key_download_enabled())

    @app.post("/authorities")
    def create_authority() -> Response:
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "").strip().lower()
        common_name = request.form.get("common_name", "").strip()
        parent_id = request.form.get("parent_id", "").strip()
        days = parse_positive_int(request.form.get("validity_days"), 3650, 1, 7300)
        db = get_db()
        try:
            if not name or len(name) > 100 or not common_name or role not in {"root", "intermediate", "issuing"}:
                raise ValueError("Provide a name (up to 100 characters), role, and certificate common name.")
            db.execute("BEGIN IMMEDIATE")
            parent = None
            if role == "root" and parent_id:
                raise ValueError("Root CAs must be self-signed.")
            if role != "root":
                if not parent_id.isascii() or not parent_id.isdigit() or len(parent_id) > 18:
                    raise ValueError("Intermediate and Issuing CAs require a valid parent CA.")
                parent = get_authority(int(parent_id))
                if parent is None:
                    raise ValueError("Selected parent CA does not exist.")
                if not valid_parent_child_roles(parent["role"], role):
                    raise ValueError("Invalid CA hierarchy. Allowed pairs are Root to Intermediate/Issuing and Intermediate to Issuing.")
                if not authority_is_active(parent):
                    raise ValueError("The parent CA or an ancestor is revoked, expired, or not yet valid.")
            pem, key, serial, start, end = create_ca_certificate(
                common_name=common_name, validity_days=days, role=role,
                issuer_role=parent["role"] if parent else None,
                issuer_certificate_pem=parent["certificate_pem"] if parent else None,
                issuer_private_key_pem=decrypt_private_key(parent["private_key_pem"]) if parent else None,
                crl_url=crl_distribution_url(parent["id"]) if parent else None)
            result = db.execute("""INSERT INTO authorities
                (name, role, common_name, parent_id, certificate_pem, private_key_pem, serial_number, not_before, not_after)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, role, common_name, parent["id"] if parent else None, pem, encrypt_private_key(key), serial, start, end))
            audit_event("authority.created", "authority", str(result.lastrowid), f"{role}: {name}")
            db.commit()
            flash(f"Created {role} CA '{name}'.")
        except sqlite3.IntegrityError:
            db.rollback()
            flash("CA names must be unique.")
        except ValueError as error:
            db.rollback()
            flash(str(error))
        return redirect(url_for("index"))

    @app.post("/certificates")
    def create_certificate() -> Response:
        common_name = request.form.get("common_name", "").strip()
        authority_id = request.form.get("authority_id", "").strip()
        maximum = int(get_setting("max_leaf_days", 397))
        days = parse_positive_int(request.form.get("validity_days"), min(397, maximum), 1, maximum)
        profile = request.form.get("profile", "server")
        db = get_db()
        try:
            if not common_name or not authority_id.isascii() or not authority_id.isdigit() or len(authority_id) > 18:
                raise ValueError("Provide a certificate common name and valid issuing authority.")
            db.execute("BEGIN IMMEDIATE")
            authority = get_authority(int(authority_id))
            if authority is None:
                raise ValueError("Selected issuing authority does not exist.")
            if authority["role"] != "issuing":
                raise ValueError("End-entity certificates must be issued by an Issuing CA.")
            if not authority_is_active(authority):
                raise ValueError("The issuing CA or an ancestor is revoked, expired, or not yet valid.")
            pem, key, serial, start, end = issue_end_entity_certificate(
                common_name=common_name, issuer_certificate_pem=authority["certificate_pem"],
                issuer_private_key_pem=decrypt_private_key(authority["private_key_pem"]), validity_days=days,
                subject_alt_names=request.form.get("subject_alt_names", ""), profile=profile,
                csr_pem=request.form.get("csr_pem", "").strip() or None, crl_url=crl_distribution_url(authority["id"]))
            certificate = x509.load_pem_x509_certificate(pem.encode())
            try:
                sans = ", ".join(str(item.value) for item in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
            except x509.ExtensionNotFound:
                sans = ""
            result = db.execute("""INSERT INTO certificates
                (common_name, authority_id, subject_alt_names, certificate_pem, private_key_pem, serial_number, not_before, not_after, profile)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (common_name, authority["id"], sans, pem, encrypt_private_key(key) if key else "", serial, start, end, profile))
            audit_event("certificate.issued", "certificate", str(result.lastrowid), f"{common_name}; profile={profile}; source={'CSR' if not key else 'generated'}")
            db.commit()
            flash(f"Issued certificate '{common_name}'.")
        except ValueError as error:
            db.rollback()
            flash(str(error))
        return redirect(url_for("index"))

    def revoke(table: str, record_id: int) -> Response:
        if not 0 < record_id <= 9223372036854775807:
            return Response("Not found", status=404)
        db = get_db()
        reason = request.form.get("reason", "unspecified")
        try:
            if reason not in REVOCATION_REASONS:
                raise ValueError("Select a valid revocation reason.")
            db.execute("BEGIN IMMEDIATE")
            record = db.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,)).fetchone()
            if record is None:
                db.rollback()
                return Response("Not found", status=404)
            if record["revoked_at"]:
                raise ValueError("This certificate has already been revoked.")
            issuer_id = record["parent_id"] if table == "authorities" else record["authority_id"]
            db.execute(f"UPDATE {table} SET revoked_at = ?, revocation_reason = ? WHERE id = ?", (utc_now().isoformat(), reason, record_id))
            db.execute("UPDATE crls SET next_update = NULL WHERE authority_id = ?", (issuer_id,))
            kind = "authority" if table == "authorities" else "certificate"
            audit_event(f"{kind}.revoked", kind, str(record_id), reason)
            db.commit()
            if table == "authorities" and issuer_id is None:
                flash("Root CA disabled, including issuance from its descendants. Also remove this root from relying-party trust stores; a root cannot revoke its own trust.")
            else:
                flash("Certificate revoked. Its issuer's CRL will include the revocation on the next download.")
        except ValueError as error:
            db.rollback()
            flash(str(error))
        return redirect(url_for("authority_detail", authority_id=record_id) if table == "authorities" else url_for("index"))

    @app.post("/certificates/<int:certificate_id>/revoke")
    def revoke_certificate(certificate_id: int) -> Response:
        return revoke("certificates", certificate_id)

    @app.post("/authorities/<int:authority_id>/revoke")
    def revoke_authority(authority_id: int) -> Response:
        return revoke("authorities", authority_id)

    @app.get("/crl/<int:authority_id>.crl")
    def download_crl(authority_id: int) -> Response:
        db = get_db()
        authority = get_authority(authority_id)
        if authority is None:
            return Response("Not found", status=404)
        db.execute("BEGIN IMMEDIATE")
        try:
            cached = db.execute("SELECT * FROM crls WHERE authority_id = ?", (authority_id,)).fetchone()
            if cached and cached["next_update"] and datetime.fromisoformat(cached["next_update"]) > utc_now():
                der = cached["der"]
            else:
                revoked = db.execute("""SELECT serial_number, revoked_at, revocation_reason FROM certificates
                    WHERE authority_id = ? AND revoked_at IS NOT NULL UNION ALL
                    SELECT serial_number, revoked_at, revocation_reason FROM authorities
                    WHERE parent_id = ? AND revoked_at IS NOT NULL""", (authority_id, authority_id)).fetchall()
                number = (cached["number"] if cached else 0) + 1
                der = build_crl(authority["certificate_pem"], decrypt_private_key(authority["private_key_pem"]),
                                [dict(row) for row in revoked], number, int(get_setting("crl_days", 7)))
                next_update = x509.load_der_x509_crl(der).next_update_utc.isoformat()
                db.execute("""INSERT INTO crls(authority_id, number, der, next_update) VALUES (?, ?, ?, ?)
                    ON CONFLICT(authority_id) DO UPDATE SET number=excluded.number, der=excluded.der, next_update=excluded.next_update""",
                    (authority_id, number, der, next_update))
                audit_event("crl.published", "authority", str(authority_id), f"number={number}; entries={len(revoked)}")
            db.commit()
        except ValueError as error:
            db.rollback()
            return Response(str(error), status=409)
        response = Response(der, mimetype="application/pkix-crl")
        response.headers["Content-Disposition"] = f'attachment; filename="authority-{authority_id}.crl"'
        # Revalidate every request: a newly recorded revocation invalidates the cached CRL immediately.
        response.headers["Cache-Control"] = "no-cache"
        return response

    def download_key(record: sqlite3.Row, kind: str, name: str) -> Response:
        if not key_download_enabled():
            return Response("Forbidden", status=403)
        if not record["private_key_pem"]:
            return Response("The private key belongs to the CSR owner and is not stored here.", status=404)
        key = decrypt_private_key(record["private_key_pem"])
        audit_event("private_key.exported", kind, str(record["id"]))
        get_db().commit()
        return text_download(name, "key.pem", key)

    @app.get("/authorities/<int:authority_id>/<artifact>")
    def download_authority(authority_id: int, artifact: str) -> Response:
        authority = get_authority(authority_id)
        if authority is None:
            return Response("Not found", status=404)
        if artifact == "cert":
            return text_download(authority["name"], "crt.pem", authority["certificate_pem"])
        if artifact == "key":
            return download_key(authority, "authority", authority["name"])
        if artifact == "chain":
            return text_download(authority["name"], "chain.pem", build_ca_chain(authority_id))
        return Response("Not found", status=404)

    @app.get("/certificates/<int:certificate_id>/<artifact>")
    def download_certificate(certificate_id: int, artifact: str) -> Response:
        if not 0 < certificate_id <= 9223372036854775807:
            return Response("Not found", status=404)
        certificate = get_db().execute("SELECT * FROM certificates WHERE id = ?", (certificate_id,)).fetchone()
        if certificate is None:
            return Response("Not found", status=404)
        if artifact == "cert":
            return text_download(certificate["common_name"], "crt.pem", certificate["certificate_pem"])
        if artifact == "key":
            return download_key(certificate, "certificate", certificate["common_name"])
        if artifact == "chain":
            return text_download(certificate["common_name"], "chain.pem", build_certificate_chain(certificate["certificate_pem"], certificate["authority_id"]))
        return Response("Not found", status=404)

    @app.get("/healthz")
    def healthz() -> dict:
        get_db().execute("SELECT 1")
        return {"status": "ok"}

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"], timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def init_db(app: Flask) -> None:
    connection = sqlite3.connect(app.config["DATABASE"], timeout=30)
    try:
        connection.executescript("""
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS authorities (
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
              role TEXT NOT NULL CHECK(role IN ('root', 'intermediate', 'issuing')),
              common_name TEXT NOT NULL, parent_id INTEGER REFERENCES authorities(id),
              certificate_pem TEXT NOT NULL, private_key_pem TEXT NOT NULL,
              serial_number TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS certificates (
              id INTEGER PRIMARY KEY AUTOINCREMENT, common_name TEXT NOT NULL,
              authority_id INTEGER NOT NULL REFERENCES authorities(id), subject_alt_names TEXT NOT NULL DEFAULT '',
              certificate_pem TEXT NOT NULL, private_key_pem TEXT NOT NULL,
              serial_number TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS crls (
              authority_id INTEGER PRIMARY KEY REFERENCES authorities(id), number INTEGER NOT NULL,
              der BLOB NOT NULL, next_update TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_certificates_authority ON certificates(authority_id);
            CREATE INDEX IF NOT EXISTS idx_authorities_parent ON authorities(parent_id);
        """)
        connection.execute("BEGIN IMMEDIATE")
        for table in ("authorities", "certificates"):
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            for name in ("revoked_at", "revocation_reason"):
                if name not in columns:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} TEXT")
            if table == "certificates" and "profile" not in columns:
                connection.execute("ALTER TABLE certificates ADD COLUMN profile TEXT NOT NULL DEFAULT 'dual'")
        connection.commit()
    finally:
        connection.close()


def list_authorities() -> list[sqlite3.Row]:
    return get_db().execute("""SELECT authorities.*, parent.name AS parent_name FROM authorities
        LEFT JOIN authorities parent ON parent.id = authorities.parent_id ORDER BY authorities.id""").fetchall()


def get_authority(authority_id: int) -> sqlite3.Row | None:
    if not 0 < authority_id <= 9223372036854775807:
        return None
    return get_db().execute("""SELECT authorities.*, parent.name AS parent_name FROM authorities
        LEFT JOIN authorities parent ON parent.id = authorities.parent_id WHERE authorities.id = ?""", (authority_id,)).fetchone()


def build_ca_chain(authority_id: int) -> str:
    chain, seen = [], set()
    while authority_id is not None:
        if authority_id in seen:
            raise ValueError("Invalid cyclic CA hierarchy.")
        seen.add(authority_id)
        authority = get_authority(authority_id)
        if authority is None:
            raise ValueError("Incomplete CA hierarchy.")
        chain.append(authority["certificate_pem"])
        authority_id = authority["parent_id"]
    return "".join(chain)


def build_certificate_chain(certificate_pem: str, authority_id: int) -> str:
    return certificate_pem + build_ca_chain(authority_id)


def text_download(stem: str, suffix: str, body: str) -> Response:
    response = Response(body, mimetype="application/x-pem-file")
    response.headers["Content-Disposition"] = f'attachment; filename="{secure_filename(stem) or "pkimaster"}-{suffix}"'
    response.headers["Cache-Control"] = "no-store"
    return response


def main() -> None:
    # Development only; the Debian service supplies HTTPS and fixed state paths.
    create_app({"SESSION_COOKIE_SECURE": False}).run(host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
