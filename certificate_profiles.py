"""Shared certificate templates and server-enforced issuance policy."""
from __future__ import annotations

from contextlib import closing
import ipaddress
import json
import sqlite3

from cryptography import x509
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from enterprise import audit_event, get_setting, require_roles
from pki import CERTIFICATE_PROFILES, _csr_key_and_names, _dns_name, parse_subject_alt_names

certificate_profiles = Blueprint("certificate_profiles", __name__)


def init_profiles(app):
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS certificate_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            description TEXT NOT NULL DEFAULT '', profile TEXT NOT NULL,
            default_validity_days INTEGER NOT NULL, max_validity_days INTEGER NOT NULL,
            dns_suffixes TEXT NOT NULL DEFAULT '[]', ip_networks TEXT NOT NULL DEFAULT '[]',
            allow_wildcards INTEGER NOT NULL DEFAULT 0, allow_ip INTEGER NOT NULL DEFAULT 0,
            roles TEXT NOT NULL DEFAULT '["admin","operator"]', enabled INTEGER NOT NULL DEFAULT 1,
            builtin TEXT UNIQUE, revision INTEGER NOT NULL DEFAULT 1)""")
        for profile, name in (("server", "TLS server"), ("client", "TLS client"), ("dual", "TLS server and client")):
            db.execute("""INSERT OR IGNORE INTO certificate_templates
                (name,profile,default_validity_days,max_validity_days,allow_wildcards,allow_ip,builtin)
                VALUES (?,?,90,36500,1,1,?)""", (name, profile, profile))
        columns = {row[1] for row in db.execute("PRAGMA table_info(certificates)")}
        for name, definition in (("template_id", "INTEGER REFERENCES certificate_templates(id)"),
                                 ("template_snapshot", "TEXT NOT NULL DEFAULT ''")):
            if name not in columns:
                db.execute(f"ALTER TABLE certificates ADD COLUMN {name} {definition}")
    app.register_blueprint(certificate_profiles)


def _template(row):
    result = dict(row)
    for field in ("dns_suffixes", "ip_networks", "roles"):
        result[field] = json.loads(result[field])
    return result


def available_templates(db, role=None):
    rows = [_template(row) for row in db.execute("SELECT * FROM certificate_templates ORDER BY name COLLATE NOCASE")]
    return rows if role is None else [row for row in rows if row["enabled"] and role in row["roles"]]


def validate_issuance(db, template_id, *, common_name, subject_alt_names, validity_days,
                      role, profile="server", csr_pem=None):
    if template_id is None or template_id == "":
        row = db.execute("SELECT * FROM certificate_templates WHERE builtin=?", (profile,)).fetchone()
    else:
        try:
            identifier = int(template_id)
            if isinstance(template_id, bool) or not 0 < identifier <= 2**63 - 1:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("Select a valid certificate template.") from None
        row = db.execute("SELECT * FROM certificate_templates WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise ValueError("Select a valid certificate template.")
    policy = _template(row)
    if not policy["enabled"] or role not in policy["roles"]:
        raise ValueError("This certificate template is disabled or not permitted for your role.")
    maximum = min(policy["max_validity_days"], int(get_setting("max_leaf_days", 397)))
    if type(validity_days) is not int or not 1 <= validity_days <= maximum:
        raise ValueError(f"This template permits a validity of 1 to {maximum} days.")
    names = parse_subject_alt_names(subject_alt_names)
    if csr_pem:
        _, inherited = _csr_key_and_names(csr_pem, 3072)
        names = names or inherited
    if not names and policy["profile"] in {"server", "dual"}:
        names = parse_subject_alt_names([common_name])
    # Server CNs can be used by older clients. Apply the same namespace policy
    # even when a separate SAN was explicitly supplied.
    checked = list(names)
    if policy["profile"] in {"server", "dual"}:
        checked.extend(parse_subject_alt_names([common_name]))
    networks = [ipaddress.ip_network(value) for value in policy["ip_networks"]]
    for name in checked:
        if isinstance(name, x509.DNSName):
            wildcard = name.value.startswith("*.")
            hostname = name.value[2:] if wildcard else name.value
            if wildcard and not policy["allow_wildcards"]:
                raise ValueError("Wildcards are not permitted by this certificate template.")
            if policy["dns_suffixes"] and not any(hostname == suffix or hostname.endswith("." + suffix)
                                                   for suffix in policy["dns_suffixes"]):
                raise ValueError("A requested DNS name is outside this template's permitted domains.")
        elif isinstance(name, x509.IPAddress):
            if not policy["allow_ip"] or (networks and not any(name.value.version == net.version and name.value in net for net in networks)):
                raise ValueError("A requested IP address is not permitted by this certificate template.")
        else:
            raise ValueError("Only DNS and IP subject alternative names are supported.")
    return {"template_id": policy["id"], "template_snapshot": json.dumps(policy, sort_keys=True),
            "profile": policy["profile"], "subject_alt_names": ", ".join(str(name.value) for name in names),
            "validity_days": validity_days}


def _form_values():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name or len(name) > 100 or any(ord(char) < 32 for char in name) or len(description) > 500:
        raise ValueError("Provide a template name of up to 100 characters and a description of up to 500 characters.")
    profile = request.form.get("profile", "server")
    if profile not in CERTIFICATE_PROFILES:
        raise ValueError("Select TLS server, TLS client, or both.")
    try:
        default = int(request.form.get("default_validity_days", "90"))
        maximum = int(request.form.get("max_validity_days", "90"))
        if not 1 <= default <= maximum <= 36500:
            raise ValueError
    except ValueError:
        raise ValueError("Default validity must be between 1 and the template maximum (up to 36500 days).") from None
    domains = [part.strip() for part in request.form.get("dns_suffixes", "").replace("\n", ",").split(",") if part.strip()]
    domains = list(dict.fromkeys(_dns_name(value) for value in domains))
    if len(domains) > 50 or any(value.startswith("*.") for value in domains):
        raise ValueError("Provide at most 50 domain suffixes without wildcards, for example corp.example.")
    try:
        networks = list(dict.fromkeys(str(ipaddress.ip_network(part.strip(), strict=True))
                        for part in request.form.get("ip_networks", "").replace("\n", ",").split(",") if part.strip()))
        if len(networks) > 50:
            raise ValueError
    except ValueError:
        raise ValueError("Provide at most 50 valid IP networks in CIDR notation.") from None
    roles = list(dict.fromkeys(request.form.getlist("roles")))
    if not roles or set(roles) - {"admin", "operator", "acme"}:
        raise ValueError("Select at least one permitted role.")
    if "acme" in roles and (profile != "server" or not domains):
        raise ValueError("ACME templates must use TLS server and explicitly permitted DNS domains.")
    return (name, description, profile, default, maximum, json.dumps(domains), json.dumps(networks),
            int("allow_wildcards" in request.form), int("allow_ip" in request.form), json.dumps(roles), int("enabled" in request.form))


@certificate_profiles.route("/settings/certificate-templates", methods=["GET", "POST"])
@require_roles("admin")
def manage():
    from app import get_db
    db = get_db()
    if request.method == "POST":
        try:
            values = _form_values()
            identifier = request.form.get("template_id", "")
            db.execute("BEGIN IMMEDIATE")
            if identifier:
                if not identifier.isascii() or not identifier.isdigit() or len(identifier) > 18:
                    raise ValueError("Invalid template.")
                changed = db.execute("""UPDATE certificate_templates SET name=?,description=?,profile=?,default_validity_days=?,
                    max_validity_days=?,dns_suffixes=?,ip_networks=?,allow_wildcards=?,allow_ip=?,roles=?,enabled=?,revision=revision+1
                    WHERE id=?""", (*values, int(identifier))).rowcount
                if not changed:
                    raise ValueError("Template not found.")
            else:
                identifier = db.execute("""INSERT INTO certificate_templates
                    (name,description,profile,default_validity_days,max_validity_days,dns_suffixes,ip_networks,
                     allow_wildcards,allow_ip,roles,enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", values).lastrowid
            audit_event("template.updated", "certificate_template", str(identifier), values[0])
            db.commit()
            flash("Certificate template saved. Changes apply to new issuance and renewal.", "success")
            return redirect(url_for("certificate_profiles.manage"))
        except (ValueError, sqlite3.IntegrityError) as exc:
            db.rollback()
            flash(str(exc) if isinstance(exc, ValueError) else "A template with this name already exists.", "error")
            return render_template("certificate_templates.html", title="Certificate templates", templates=available_templates(db)), 400
    return render_template("certificate_templates.html", title="Certificate templates", templates=available_templates(db))
