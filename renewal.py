"""Explicit certificate renewal with an immutable predecessor/successor link."""
from __future__ import annotations

import sqlite3
from contextlib import closing

from cryptography import x509
from flask import Blueprint, Response, current_app, flash, g, redirect, render_template, request, url_for

renewal = Blueprint("renewal", __name__)


def init_renewal(app):
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(certificates)")}
        if "renewed_from_id" not in columns:
            db.execute("ALTER TABLE certificates ADD COLUMN renewed_from_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL")
        db.executescript("""
            CREATE UNIQUE INDEX IF NOT EXISTS certificate_one_successor
                ON certificates(renewed_from_id) WHERE renewed_from_id IS NOT NULL;
            CREATE TRIGGER IF NOT EXISTS immutable_certificate_predecessor
                BEFORE UPDATE OF renewed_from_id ON certificates
                WHEN NEW.renewed_from_id IS NOT OLD.renewed_from_id
                  AND NOT (NEW.renewed_from_id IS NULL AND NOT EXISTS
                      (SELECT 1 FROM certificates WHERE id=OLD.renewed_from_id))
                BEGIN SELECT RAISE(ABORT, 'Certificate renewal history is immutable'); END;
        """)
    app.register_blueprint(renewal)


def _certificate(db, certificate_id):
    if not 0 < certificate_id <= 9223372036854775807:
        return None
    return db.execute("""SELECT c.*, a.name AS authority_name FROM certificates c
        JOIN authorities a ON a.id=c.authority_id WHERE c.id=?""", (certificate_id,)).fetchone()


@renewal.get("/certificates/<int:certificate_id>")
def detail(certificate_id):
    from app import authority_block_reason, get_db, get_authority, key_download_enabled, utc_now
    db = get_db()
    db.execute("BEGIN")
    certificate = _certificate(db, certificate_id)
    if certificate is None:
        return Response("Not found", status=404)
    predecessor = _certificate(db, certificate["renewed_from_id"]) if certificate["renewed_from_id"] else None
    successor = db.execute("SELECT id, common_name, serial_number FROM certificates WHERE renewed_from_id=?", (certificate_id,)).fetchone()
    endpoint_check = db.execute("SELECT * FROM certificate_endpoint_checks WHERE certificate_id=?", (certificate_id,)).fetchone()
    return render_template("certificate_detail.html", title="Certificate details", certificate=certificate,
                           predecessor=predecessor, successor=successor, now=utc_now().isoformat(),
                           issuer_block_reason=authority_block_reason(get_authority(certificate["authority_id"])),
                           key_download_enabled=key_download_enabled(), endpoint_check=endpoint_check)


@renewal.route("/certificates/<int:certificate_id>/renew", methods=["GET", "POST"])
def renew(certificate_id):
    from app import (authority_block_reason, authority_is_active, crl_distribution_url, current_authority,
                     encrypt_private_key, get_db, issuer_certificate_url)
    from enterprise import audit_event, get_setting
    from key_storage import authority_signing_key
    from pki import issue_end_entity_certificate
    from certificate_profiles import available_templates, validate_issuance

    db = get_db()
    db.execute("BEGIN IMMEDIATE" if request.method == "POST" else "BEGIN")
    original = _certificate(db, certificate_id)
    if original is None:
        return Response("Not found", status=404)
    successor = db.execute("SELECT id FROM certificates WHERE renewed_from_id=?", (certificate_id,)).fetchone()
    if successor:
        flash("This certificate already has a successor. Renew the latest certificate in the chain.", "info")
        return redirect(url_for("renewal.detail", certificate_id=successor["id"]))
    maximum = int(get_setting("max_leaf_days", 397))
    authority_id = (request.form.get("authority_id", "").strip() if request.method == "POST"
                    else str(original["authority_id"]))
    if not authority_id and request.method == "GET":
        fallback = current_authority(db)
        authority_id = str(fallback["id"]) if fallback else ""
    authority = (current_authority(db, int(authority_id))
                 if authority_id.isascii() and authority_id.isdigit() and len(authority_id) <= 18 else None)
    issuing_authorities = [item for item in db.execute(
        "SELECT * FROM authorities WHERE role='issuing' AND state='active' AND revoked_at IS NULL ORDER BY id"
    ).fetchall() if authority_is_active(item)]
    if request.method == "GET" and (
        authority is None or not any(item["id"] == authority["id"] for item in issuing_authorities)
    ):
        authority = issuing_authorities[0] if issuing_authorities else None
        authority_id = str(authority["id"]) if authority else ""
    blocked = ("Revoked certificates cannot be renewed. Issue a new certificate after resolving the revocation reason."
               if original["revoked_at"] else
               "Select an active Issuing CA for renewal." if authority is None or authority["role"] != "issuing"
               else authority_block_reason(authority))
    values = {"common_name": original["common_name"], "subject_alt_names": original["subject_alt_names"],
              "profile": original["profile"], "validity_days": str(min(397, maximum)),
              "key_source": "csr", "csr_pem": "", "authority_id": str(authority["id"]) if authority else authority_id,
              "template_id": str(original["template_id"]) if original["template_id"] else ""}
    if request.method == "POST":
        values.update({key: request.form.get(key, "").strip() for key in values})
        authority_id = values["authority_id"]
        authority = (current_authority(db, int(authority_id))
                     if authority_id.isascii() and authority_id.isdigit() and len(authority_id) <= 18 else None)
        try:
            blocked = ("Revoked certificates cannot be renewed. Issue a new certificate after resolving the revocation reason."
                       if original["revoked_at"] else
                       "Select an active Issuing CA for renewal." if authority is None or authority["role"] != "issuing"
                       else authority_block_reason(authority))
            if blocked:
                raise ValueError(blocked)
            if not values["validity_days"].isascii() or not values["validity_days"].isdigit() or len(values["validity_days"]) > 5:
                raise ValueError("Enter a valid certificate lifetime.")
            days = int(values["validity_days"])
            if not 1 <= days <= maximum:
                raise ValueError(f"Validity must be between 1 and {maximum} days.")
            if values["key_source"] not in {"csr", "generated"}:
                raise ValueError("Select a new CSR or a newly generated key.")
            if values["key_source"] == "csr" and not values["csr_pem"]:
                raise ValueError("Provide the new certificate signing request.")
            if values["key_source"] == "generated" and values["csr_pem"]:
                raise ValueError("Select CSR signing to use the provided request.")
            policy = validate_issuance(db, values["template_id"], common_name=values["common_name"],
                                      subject_alt_names=values["subject_alt_names"], validity_days=days,
                                      role=g.user["role"], profile=values["profile"],
                                      csr_pem=values["csr_pem"] if values["key_source"] == "csr" else None)
            values["profile"] = policy["profile"]
            pem, key, serial, start, end = issue_end_entity_certificate(
                common_name=values["common_name"], issuer_certificate_pem=authority["certificate_pem"],
                issuer_private_key_pem=authority_signing_key(authority), validity_days=days,
                subject_alt_names=policy["subject_alt_names"], profile=values["profile"],
                csr_pem=values["csr_pem"] if values["key_source"] == "csr" else None,
                crl_url=crl_distribution_url(authority["id"]), aia_url=issuer_certificate_url(authority["id"]),
                minimum_rsa_bits=3072)
            certificate = x509.load_pem_x509_certificate(pem.encode())
            try:
                sans = ", ".join(str(item.value) for item in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
            except x509.ExtensionNotFound:
                sans = ""
            result = db.execute("""INSERT INTO certificates
                (common_name,authority_id,subject_alt_names,certificate_pem,private_key_pem,serial_number,
                 not_before,not_after,profile,renewed_from_id,template_id,template_snapshot) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (values["common_name"], authority["id"], sans, pem, encrypt_private_key(key) if key else "",
                 serial, start, end, values["profile"], certificate_id,policy["template_id"],policy["template_snapshot"]))
            from inventory import copy_metadata
            copy_metadata(db, certificate_id, result.lastrowid)
            audit_event("certificate.renewed", "certificate", str(result.lastrowid),
                        f"predecessor={certificate_id}; previous_serial={original['serial_number']}; issuer={authority['id']}; profile={values['profile']}; source={values['key_source']}")
            db.commit()
            flash("Certificate renewed. Deploy the new certificate and key before deciding whether to revoke its predecessor.", "success")
            return redirect(url_for("renewal.detail", certificate_id=result.lastrowid))
        except ValueError as error:
            db.rollback()
            flash(str(error), "error")
        except sqlite3.IntegrityError:
            db.rollback()
            current_app.logger.warning("Certificate renewal conflicted for certificate %s", certificate_id)
            flash("The certificate could not be renewed. Reload its details and try again.", "error")
    return render_template("certificate_renew.html", title="Renew certificate", certificate=original,
                           authority=authority, blocked=blocked, values=values, maximum=maximum,
                           multi_ca_enabled=get_setting("multi_ca_enabled", False),
                           issuing_authorities=issuing_authorities,
                           issuance_templates=available_templates(db, g.user["role"])), (400 if request.method == "POST" else 200)
