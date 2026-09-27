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
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from flask import Flask, Response, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from enterprise import audit_event, can_manage, configure_runtime, get_setting, init_enterprise
from pki import (REVOCATION_REASONS, build_crl, create_ca_certificate, create_ca_request,
                 issue_end_entity_certificate, sign_ca_request, validate_ca_activation, valid_parent_child_roles, crl_signature_is_valid)


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
    return not authority_block_reason(authority)


def authority_block_reason(authority: sqlite3.Row) -> str:
    if authority["state"] != "active":
        return "Awaiting a signed CA certificate and its parent chain."
    if authority["revoked_at"]:
        return "The local CA has been disabled."
    cert = x509.load_pem_x509_certificate(authority["certificate_pem"].encode())
    key = cert.public_key()
    if not ((isinstance(key, rsa.RSAPublicKey) and key.key_size >= 3072) or
            (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)))):
        return "The local CA key does not meet the current signing policy. Plan a controlled migration."
    if not datetime.fromisoformat(authority["not_before"]) <= utc_now() < datetime.fromisoformat(authority["not_after"]):
        return "The local CA is expired or not yet valid."
    if authority["role"] != "root":
        try:
            validate_parent_crls(authority, authority["parent_crls_pem"])
        except ValueError as error:
            return str(error)
    return ""


def split_pem_crl_blocks(pem: str, *, strict: bool = True) -> list[str]:
    """Return PEM CRL blocks, optionally rejecting non-whitespace content between them."""
    begin_marker = "-----BEGIN X509 CRL-----"
    end_marker = "-----END X509 CRL-----"
    blocks: list[str] = []
    lines = pem.splitlines(keepends=True)
    cursor = 0
    while cursor < len(lines):
        if strict:
            while cursor < len(lines) and not lines[cursor].strip():
                cursor += 1
        else:
            while cursor < len(lines) and lines[cursor].strip() != begin_marker:
                cursor += 1
        if cursor >= len(lines):
            break
        if lines[cursor].strip() != begin_marker:
            raise ValueError("Upload only PEM-encoded parent CRLs.")
        block = [lines[cursor]]
        cursor += 1
        while cursor < len(lines):
            block.append(lines[cursor])
            if lines[cursor].strip() == end_marker:
                cursor += 1
                blocks.append("".join(block))
                break
            cursor += 1
        else:
            raise ValueError("Upload only PEM-encoded parent CRLs.")
    return blocks


def validate_parent_crls(authority: sqlite3.Row, pem: str) -> str:
    """Validate each ancestor's status using an explicitly imported, fresh full CRL."""
    if not pem.strip():
        raise ValueError("Import current signed parent CRLs before using this CA.")
    try:
        chain = x509.load_pem_x509_certificates((authority["certificate_pem"] + authority["parent_chain_pem"]).encode())
        blocks = split_pem_crl_blocks(pem)
        if not blocks:
            raise ValueError("Upload only PEM-encoded parent CRLs.")
        try:
            crls = [x509.load_pem_x509_crl(block.encode()) for block in blocks]
        except ValueError as error:
            raise ValueError("Upload only PEM-encoded parent CRLs.") from error
        if len(chain) < 2 or len(crls) != len(chain) - 1:
            raise ValueError("Provide one full CRL per parent, ordered immediate issuer to root.")
        revoked = False
        for child, parent, crl in zip(chain, chain[1:], crls):
            if not parent.not_valid_before_utc <= utc_now() < parent.not_valid_after_utc:
                raise ValueError("A parent CA is expired or not yet valid.")
            if crl.issuer != parent.subject or not crl_signature_is_valid(crl, parent.public_key()):
                raise ValueError("Parent CRL signature or issuer is invalid.")
            if not crl.next_update_utc or not crl.last_update_utc <= utc_now() < crl.next_update_utc:
                raise ValueError("A parent CRL is stale or not yet valid. Import a fresh CRL.")
            crl.extensions.get_extension_for_class(x509.CRLNumber)
            # Delta and scoped/indirect CRLs need additional processing and cannot be treated as full status.
            for extension in crl.extensions:
                if isinstance(extension.value, (x509.DeltaCRLIndicator, x509.IssuingDistributionPoint)) or (
                        extension.critical and not isinstance(extension.value, (x509.AuthorityKeyIdentifier, x509.CRLNumber))):
                    raise ValueError("Only full, direct parent CRLs are supported.")
            if crl.get_revoked_certificate_by_serial_number(child.serial_number) is not None:
                revoked = True
        if revoked:
            raise ValueError("The CA or an ancestor is revoked in its issuer's CRL.")
        return "".join(crl.public_bytes(serialization.Encoding.PEM).decode() for crl in crls)
    except (TypeError, x509.ExtensionNotFound, x509.DuplicateExtension, UnsupportedAlgorithm) as error:
        raise ValueError("Invalid parent CRL bundle.") from error


def crl_distribution_url(authority_id: int) -> str | None:
    base = get_setting("public_base_url", "").rstrip("/")
    return f"{base}/crl/{authority_id}.crl" if base else None


def create_app(test_config: dict | None = None) -> Flask:
    templates = Path(__file__).parent / "templates"
    if not templates.is_dir():
        templates = Path(sys.prefix) / "share" / "pkimaster" / "templates"
    static = templates.parent / "static"
    app = Flask(__name__, template_folder=str(templates), static_folder=str(static))
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
    app.jinja_env.globals["has_endpoint"] = lambda name: name in app.view_functions
    init_enterprise(app)
    from audit_integrity import init_audit, verify_chain, AuditIntegrityError
    from security import security
    init_audit(app)
    app.register_blueprint(security)
    from key_storage import init_key_storage, authority_signing_key, provision_authority_key
    init_key_storage(app)

    @app.before_request
    def protect_audit_integrity():
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            try:
                verify_chain(get_db(), app.config["KEY_ENCRYPTION_SECRET"])
            except AuditIntegrityError:
                return Response("Audit integrity verification failed. Operation refused; preserve the state for investigation.", status=503)

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
                               authority=authorities[0] if authorities else None,
                               block_reason=authority_block_reason(authorities[0]) if authorities else "",
                               ca_requests=db.execute("SELECT r.*, u.username AS requester FROM ca_requests r LEFT JOIN users u ON u.id=r.requested_by ORDER BY r.id DESC LIMIT 100").fetchall(),
                               issued_authorities=db.execute("SELECT * FROM issued_authorities ORDER BY id DESC LIMIT 100").fetchall(),
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
        children = db.execute("SELECT * FROM issued_authorities WHERE authority_id = ? ORDER BY id", (authority_id,)).fetchall()
        certificates = db.execute("SELECT id, common_name FROM certificates WHERE authority_id = ? ORDER BY id DESC LIMIT 100", (authority_id,)).fetchall()
        return render_template("authority_detail.html", title=authority["name"], authority=authority,
                               child_authorities=children, issued_certificates=certificates,
                               active=authority_is_active(authority), revocation_reasons=REVOCATION_REASONS,
                               block_reason=authority_block_reason(authority),
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
            if db.execute("SELECT 1 FROM authorities LIMIT 1").fetchone():
                raise ValueError("Only one CA is permitted per server. Use a separate server for another CA.")
            if parent_id:
                raise ValueError("A parent CA must run on a separate server. Exchange a CSR and signed certificates through the web console.")
            signer, backend, reference = provision_authority_key()
            if role == "root":
                pem, key, serial, start, end = create_ca_certificate(common_name=common_name, validity_days=days, role=role, signer=signer)
                csr, state = "", "active"
            else:
                csr, key = create_ca_request(common_name, role, signer=signer)
                pem, serial, start, end, state = "", "", "", "", "pending"
            result = db.execute("""INSERT INTO authorities
                (name, role, common_name, certificate_pem, private_key_pem, serial_number, not_before, not_after, csr_pem, state, key_backend, key_reference)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, role, common_name, pem, encrypt_private_key(key) if key else "", serial, start, end, csr, state, backend, reference))
            audit_event("authority.created", "authority", str(result.lastrowid), f"{role}: {name}")
            db.commit()
            flash(f"Created {role} CA '{name}'." if role == "root" else "CA key and CSR created. Download the CSR for signing on the parent CA server.")
        except sqlite3.IntegrityError:
            db.rollback()
            flash("Only one CA is permitted per server; its identity cannot be replaced.")
        except ValueError as error:
            db.rollback()
            flash(str(error))
        return redirect(url_for("index"))

    @app.post("/ca/activate")
    def activate_authority() -> Response:
        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            authority = db.execute("SELECT * FROM authorities").fetchone()
            if authority is None or authority["state"] != "pending" or authority["revoked_at"]:
                raise ValueError("Only a pending local CA can be activated.")
            pem = request.form.get("certificate_pem", "").strip()
            chain = validate_ca_activation(pem, request.form.get("chain_pem", ""),
                authority_signing_key(authority), authority["common_name"], authority["role"])
            root_cert = x509.load_pem_x509_certificates(chain.encode())[-1]
            trusted_fingerprint = request.form.get("trusted_root_sha256", "").replace(":", "").replace(" ", "").strip().lower()
            if not trusted_fingerprint.isascii() or not compare_digest(trusted_fingerprint, root_cert.fingerprint(hashes.SHA256()).hex()):
                raise ValueError("Enter the root CA SHA-256 fingerprint obtained through your trusted verification channel.")
            cert = x509.load_pem_x509_certificate(pem.encode())
            db.execute("UPDATE authorities SET certificate_pem=?, parent_chain_pem=?, serial_number=?, not_before=?, not_after=?, state='active' WHERE id=?",
                       (cert.public_bytes(serialization.Encoding.PEM).decode(), chain, format(cert.serial_number, "x"),
                        cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat(), authority["id"]))
            audit_event("authority.activated", "authority", str(authority["id"]), cert.fingerprint(hashes.SHA256()).hex())
            db.commit()
            flash("CA certificate imported. Import current parent CRLs to enable signing.")
        except ValueError as error:
            db.rollback()
            flash(str(error))
        return redirect(url_for("index"))

    @app.post("/ca/parent-crls")
    def update_parent_crls() -> Response:
        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            authority = db.execute("SELECT * FROM authorities").fetchone()
            if authority is None or authority["state"] != "active" or authority["role"] == "root":
                raise ValueError("Parent CRLs require an activated subordinate CA.")
            pem = request.form.get("parent_crls_pem", "")
            # Revoked status must be retained, not discarded as an invalid upload.
            revoked = False
            try:
                canonical = validate_parent_crls(authority, pem)
            except ValueError as error:
                if str(error) != "The CA or an ancestor is revoked in its issuer's CRL.":
                    raise
                canonical, revoked = pem, True
            # Reject rollback even after a cached CRL expires.
            old_blocks = split_pem_crl_blocks(authority["parent_crls_pem"])
            new_blocks = split_pem_crl_blocks(canonical)
            if old_blocks:
                if len(old_blocks) != len(new_blocks):
                    raise ValueError("Parent CRL bundle is inconsistent with stored CRLs.")
                old_crls = [x509.load_pem_x509_crl(block.encode()) for block in old_blocks]
                new_crls = [x509.load_pem_x509_crl(block.encode()) for block in new_blocks]
                for old, new in zip(old_crls, new_crls):
                    if new.last_update_utc < old.last_update_utc:
                        raise ValueError("An older parent CRL cannot replace a newer CRL.")
                    try:
                        old_number = old.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
                        new_number = new.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
                        if new_number < old_number or (new_number == old_number and new.public_bytes(serialization.Encoding.DER) != old.public_bytes(serialization.Encoding.DER)):
                            raise ValueError("Parent CRL number rollback is not allowed.")
                    except x509.ExtensionNotFound:
                        raise ValueError("Parent CRLs must include a CRL number.") from None
            db.execute("UPDATE authorities SET parent_crls_pem=? WHERE id=?", (canonical, authority["id"]))
            if revoked:
                db.execute("UPDATE authorities SET revoked_at=COALESCE(revoked_at, ?), revocation_reason=COALESCE(revocation_reason, 'unspecified') WHERE id=?", (utc_now().isoformat(), authority["id"]))
            audit_event("authority.parent_crls_updated", "authority", str(authority["id"]), "revoked" if revoked else "valid")
            db.commit()
            flash("Parent CRLs imported. CA signing is blocked." if revoked else "Parent CRLs validated and imported.")
        except ValueError as error:
            db.rollback()
            flash(str(error))
        return redirect(url_for("index"))

    @app.post("/ca/requests")
    def sign_subordinate() -> Response:
        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            authority = db.execute("SELECT * FROM authorities").fetchone()
            role = request.form.get("role", "")
            if not authority or not valid_parent_child_roles(authority["role"], role) or not authority_is_active(authority):
                raise ValueError("An active Root or Intermediate CA with a permitted child role is required.")
            csr_pem = request.form.get("csr_pem", "").strip()
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            if not csr.is_signature_valid:
                raise ValueError("The CSR signature is invalid.")
            names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(names) != 1:
                raise ValueError("The CSR must contain one common name.")
            days = parse_positive_int(request.form.get("validity_days"), 365, 1, 7300)
            fingerprint = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()
            result = db.execute("INSERT INTO ca_requests (authority_id, common_name, role, validity_days, csr_pem, fingerprint, requested_by) VALUES (?,?,?,?,?,?,?)",
                (authority["id"], names[0].value, role, days, csr.public_bytes(serialization.Encoding.PEM).decode(), fingerprint, g.user["id"]))
            audit_event("ca_request.submitted", "ca_request", str(result.lastrowid), fingerprint)
            db.commit()
            flash("CA request recorded. A different administrator must review and approve it before signing.")
        except (UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
            db.rollback()
            flash("The CA request contains unsupported cryptographic data or extensions.")
        except (ValueError, sqlite3.IntegrityError) as error:
            db.rollback()
            flash(str(error) if isinstance(error, ValueError) else "This CA request has already been submitted.")
        return redirect(url_for("index"))

    @app.post("/ca/requests/<int:request_id>/approve")
    def approve_subordinate(request_id: int) -> Response:
        if not 0 < request_id <= 9223372036854775807:
            return Response("Not found", status=404)
        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            pending = db.execute("SELECT * FROM ca_requests WHERE id=?", (request_id,)).fetchone()
            if not pending or pending["status"] != "pending":
                raise ValueError("This CA request is not pending.")
            if pending["requested_by"] == g.user["id"]:
                raise ValueError("Four-eyes control: the requester cannot approve their own CA request.")
            authority = get_authority(pending["authority_id"])
            if not authority_is_active(authority):
                raise ValueError(authority_block_reason(authority))
            pem, serial, start, end = sign_ca_request(pending["csr_pem"], pending["role"], pending["validity_days"],
                authority["role"], authority["certificate_pem"], authority_signing_key(authority),
                crl_url=crl_distribution_url(authority["id"]))
            result = db.execute("INSERT INTO issued_authorities (authority_id, common_name, role, certificate_pem, serial_number, not_before, not_after) VALUES (?,?,?,?,?,?,?)",
                (authority["id"], pending["common_name"], pending["role"], pem, serial, start, end))
            db.execute("UPDATE ca_requests SET status='approved', reviewed_by=?, reviewed_at=?, issued_id=? WHERE id=?",
                (g.user["id"], utc_now().isoformat(), result.lastrowid, request_id))
            audit_event("ca_request.approved", "ca_request", str(request_id), f"requester={pending['requested_by']}; sha256={pending['fingerprint']}")
            audit_event("subordinate.issued", "issued_authority", str(result.lastrowid), pending["common_name"])
            db.commit()
            flash("Subordinate CA certificate signed. Transfer its certificate and parent chain to its own server.")
        except (ValueError, sqlite3.IntegrityError) as error:
            db.rollback()
            flash(str(error) if isinstance(error, ValueError) else "The CA request could not be signed.")
        return redirect(url_for("index"))

    @app.post("/ca/requests/<int:request_id>/reject")
    def reject_subordinate(request_id: int) -> Response:
        if not 0 < request_id <= 9223372036854775807:
            return Response("Not found", status=404)
        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        updated = db.execute("UPDATE ca_requests SET status='rejected', reviewed_by=?, reviewed_at=? WHERE id=? AND status='pending'",
                            (g.user["id"], utc_now().isoformat(), request_id)).rowcount
        if updated:
            audit_event("ca_request.rejected", "ca_request", str(request_id))
        db.commit()
        flash("CA request rejected." if updated else "This CA request is not pending.")
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
                raise ValueError(authority_block_reason(authority))
            pem, key, serial, start, end = issue_end_entity_certificate(
                common_name=common_name, issuer_certificate_pem=authority["certificate_pem"],
                issuer_private_key_pem=authority_signing_key(authority), validity_days=days,
                subject_alt_names=request.form.get("subject_alt_names", ""), profile=profile,
                csr_pem=request.form.get("csr_pem", "").strip() or None, crl_url=crl_distribution_url(authority["id"]), minimum_rsa_bits=3072)
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
            issuer_id = None if table == "authorities" else record["authority_id"]
            db.execute(f"UPDATE {table} SET revoked_at = ?, revocation_reason = ? WHERE id = ?", (utc_now().isoformat(), reason, record_id))
            db.execute("UPDATE crls SET next_update = NULL WHERE authority_id = ?", (issuer_id,))
            kind = {"authorities": "authority", "certificates": "certificate", "issued_authorities": "subordinate"}[table]
            audit_event(f"{kind}.revoked", kind, str(record_id), reason)
            db.commit()
            if table == "authorities" and issuer_id is None:
                flash("Local CA disabled. For a subordinate CA, request revocation on its parent server and distribute its updated CRL. For a root, remove trust on relying parties.")
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

    @app.post("/subordinates/<int:subordinate_id>/revoke")
    def revoke_subordinate(subordinate_id: int) -> Response:
        return revoke("issued_authorities", subordinate_id)

    @app.get("/subordinates/<int:subordinate_id>/<artifact>")
    def download_subordinate(subordinate_id: int, artifact: str) -> Response:
        if not 0 < subordinate_id <= 9223372036854775807:
            return Response("Not found", status=404)
        record = get_db().execute("SELECT * FROM issued_authorities WHERE id=?", (subordinate_id,)).fetchone()
        if record is None or artifact not in {"cert", "chain", "parents"}:
            return Response("Not found", status=404)
        body = record["certificate_pem"] if artifact == "cert" else build_ca_chain(record["authority_id"])
        if artifact == "chain":
            body = record["certificate_pem"] + body
        return text_download(record["common_name"], artifact + ".pem", body)

    @app.get("/crl/<int:authority_id>.crl")
    def download_crl(authority_id: int) -> Response:
        db = get_db()
        authority = get_authority(authority_id)
        if authority is None:
            return Response("Not found", status=404)
        if authority["state"] != "active":
            return Response("The local CA is awaiting activation.", status=409)
        db.execute("BEGIN IMMEDIATE")
        try:
            cached = db.execute("SELECT * FROM crls WHERE authority_id = ?", (authority_id,)).fetchone()
            if cached and cached["next_update"] and datetime.fromisoformat(cached["next_update"]) > utc_now():
                der = cached["der"]
            else:
                revoked = db.execute("""SELECT serial_number, revoked_at, revocation_reason FROM certificates
                    WHERE authority_id = ? AND revoked_at IS NOT NULL UNION ALL
                    SELECT serial_number, revoked_at, revocation_reason FROM issued_authorities
                    WHERE authority_id = ? AND revoked_at IS NOT NULL""", (authority_id, authority_id)).fetchall()
                number = (cached["number"] if cached else 0) + 1
                der = build_crl(authority["certificate_pem"], authority_signing_key(authority),
                                [dict(row) for row in revoked], number, int(get_setting("crl_days", 7)))
                next_update = x509.load_der_x509_crl(der).next_update_utc.isoformat()
                db.execute("""INSERT INTO crls(authority_id, number, der, next_update) VALUES (?, ?, ?, ?)
                    ON CONFLICT(authority_id) DO UPDATE SET number=excluded.number, der=excluded.der, next_update=excluded.next_update""",
                    (authority_id, number, der, next_update))
                audit_event("crl.published", "authority", str(authority_id), f"number={number}; entries={len(revoked)}")
            db.commit()
        except ValueError as error:
            db.rollback()
            current_app.logger.warning("CRL publication failed for authority %s: %s", authority_id, error)
            return Response("The CRL could not be generated.", status=409)
        as_pem = request.args.get("format") == "pem"
        body = x509.load_der_x509_crl(der).public_bytes(serialization.Encoding.PEM) if as_pem else der
        response = Response(body, mimetype="application/x-pem-file" if as_pem else "application/pkix-crl")
        extension = ".crl.pem" if as_pem else ".crl"
        response.headers["Content-Disposition"] = f'attachment; filename="authority-{authority_id}{extension}"'
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
            if authority["state"] != "active":
                return Response("The local CA is awaiting activation.", status=409)
            return text_download(authority["name"], "crt.pem", authority["certificate_pem"])
        if artifact == "key":
            return Response("CA private keys cannot be exported through the web interface.", status=403)
        if artifact == "csr" and authority["csr_pem"]:
            return text_download(authority["name"], "csr.pem", authority["csr_pem"])
        if artifact == "chain":
            if authority["state"] != "active":
                return Response("The local CA is awaiting activation.", status=409)
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
        existing = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authorities'").fetchone()
        if existing and connection.execute("SELECT COUNT(*) FROM authorities").fetchone()[0] > 1:
            raise RuntimeError("This installation contains multiple local CAs. Startup is blocked: only one CA is permitted per server. Preserve the database and runtime secrets; see docs/BSI-READINESS.md for migration planning. No CA data has been deleted.")
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
            CREATE TABLE IF NOT EXISTS issued_authorities (
              id INTEGER PRIMARY KEY AUTOINCREMENT, authority_id INTEGER NOT NULL REFERENCES authorities(id),
              common_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('intermediate','issuing')),
              certificate_pem TEXT NOT NULL, serial_number TEXT NOT NULL UNIQUE,
              not_before TEXT NOT NULL, not_after TEXT NOT NULL,
              revoked_at TEXT, revocation_reason TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ca_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT, authority_id INTEGER NOT NULL REFERENCES authorities(id),
              common_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('intermediate','issuing')),
              validity_days INTEGER NOT NULL, csr_pem TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
              requested_by INTEGER NOT NULL, reviewed_by INTEGER, reviewed_at TEXT,
              status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
              issued_id INTEGER REFERENCES issued_authorities(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              CHECK(status != 'approved' OR (reviewed_by IS NOT NULL AND requested_by != reviewed_by AND issued_id IS NOT NULL))
            );
        """)
        connection.execute("BEGIN IMMEDIATE")
        for table in ("authorities", "certificates"):
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            for name in ("revoked_at", "revocation_reason"):
                if name not in columns:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} TEXT")
            if table == "certificates" and "profile" not in columns:
                connection.execute("ALTER TABLE certificates ADD COLUMN profile TEXT NOT NULL DEFAULT 'dual'")
            if table == "authorities":
                for name, declaration in (("state", "TEXT NOT NULL DEFAULT 'active'"), ("csr_pem", "TEXT NOT NULL DEFAULT ''"),
                                          ("parent_chain_pem", "TEXT NOT NULL DEFAULT ''"), ("parent_crls_pem", "TEXT NOT NULL DEFAULT ''"),
                                          ("key_backend", "TEXT NOT NULL DEFAULT 'software'"), ("key_reference", "TEXT NOT NULL DEFAULT ''")):
                    if name not in columns:
                        connection.execute(f"ALTER TABLE authorities ADD COLUMN {name} {declaration}")
        connection.executescript("""
            CREATE TRIGGER IF NOT EXISTS immutable_ca_key_binding BEFORE UPDATE OF key_backend, key_reference ON authorities
            BEGIN SELECT RAISE(ABORT, 'The CA key provider and identity are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS single_local_ca BEFORE INSERT ON authorities
            WHEN EXISTS (SELECT 1 FROM authorities)
            BEGIN SELECT RAISE(ABORT, 'Only one CA is permitted per server'); END;
            CREATE TRIGGER IF NOT EXISTS no_local_parent BEFORE INSERT ON authorities
            WHEN NEW.parent_id IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'Parent CAs must run on separate servers'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_ca_identity BEFORE UPDATE OF id, role, common_name, private_key_pem, parent_id, csr_pem ON authorities
            BEGIN SELECT RAISE(ABORT, 'The local CA identity is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS preserve_local_ca BEFORE DELETE ON authorities
            BEGIN SELECT RAISE(ABORT, 'The local CA cannot be deleted or replaced'); END;
            CREATE TRIGGER IF NOT EXISTS preserve_active_ca_certificate BEFORE UPDATE OF certificate_pem, parent_chain_pem ON authorities
            WHEN OLD.state = 'active'
            BEGIN SELECT RAISE(ABORT, 'An active CA certificate cannot be replaced'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_ca_request BEFORE UPDATE OF authority_id, common_name, role, validity_days, csr_pem, fingerprint, requested_by ON ca_requests
            BEGIN SELECT RAISE(ABORT, 'CA signing requests are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS final_ca_decision BEFORE UPDATE ON ca_requests WHEN OLD.status != 'pending'
            BEGIN SELECT RAISE(ABORT, 'CA signing decisions are final'); END;
        """)
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
    authority = get_authority(authority_id)
    if authority is None or authority["state"] != "active":
        raise ValueError("The local CA has not been activated.")
    return authority["certificate_pem"] + authority["parent_chain_pem"]


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
