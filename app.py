from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
from hmac import compare_digest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import (
    Flask,
    Response,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_positive_int(raw_value: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return default
    return min(max(value, minimum), maximum)


def key_download_enabled() -> bool:
    configured_token = current_app.config.get("ADMIN_TOKEN", "")
    return bool(configured_token) and session.get("private_key_access") is True


def max_subordinate_depth(role: str) -> int:
    return {"root": 2, "intermediate": 1, "issuing": 0}[role]


def allowed_ca_path_length(role: str, issuer_role: str | None = None) -> int:
    role_depth = max_subordinate_depth(role)
    if issuer_role is None:
        return role_depth
    return min(role_depth, max(max_subordinate_depth(issuer_role) - 1, 0))


def valid_parent_child_roles(parent_role: str, child_role: str) -> bool:
    allowed_pairs = {
        "root": {"intermediate", "issuing"},
        "intermediate": {"issuing"},
        "issuing": set(),
    }
    return child_role in allowed_pairs.get(parent_role, set())


def private_key_cipher() -> Fernet:
    secret = current_app.config.get("KEY_ENCRYPTION_SECRET", current_app.config["SECRET_KEY"])
    key = base64.urlsafe_b64encode(hashlib.sha256(str(secret).encode("utf-8")).digest())
    return Fernet(key)


def encrypt_private_key(private_key_pem: str) -> str:
    return private_key_cipher().encrypt(private_key_pem.encode("utf-8")).decode("utf-8")


def decrypt_private_key(encrypted_private_key: str) -> str:
    return private_key_cipher().decrypt(encrypted_private_key.encode("utf-8")).decode("utf-8")


def authority_key_identifier_from_certificate(certificate: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    try:
        subject_key_identifier = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier(
            key_identifier=subject_key_identifier.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(certificate.public_key())


def build_subject(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def serialize_certificate(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def create_ca_certificate(
    common_name: str,
    validity_days: int,
    role: str,
    issuer_role: str | None = None,
    issuer_certificate_pem: str | None = None,
    issuer_private_key_pem: str | None = None,
) -> tuple[str, str, str, str, str]:
    private_key = generate_private_key()
    public_key = private_key.public_key()
    subject = build_subject(common_name)
    now = utc_now()
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=validity_days)
    serial_number = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    path_length = allowed_ca_path_length(role, issuer_role)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
    if issuer_certificate_pem and issuer_private_key_pem:
        issuer_certificate = x509.load_pem_x509_certificate(issuer_certificate_pem.encode("utf-8"))
        issuer_private_key = serialization.load_pem_private_key(issuer_private_key_pem.encode("utf-8"), None)
        builder = (
            builder.issuer_name(issuer_certificate.subject)
            .add_extension(authority_key_identifier_from_certificate(issuer_certificate), critical=False)
        )
        certificate = builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
    else:
        builder = (
            builder.issuer_name(subject)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        )
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    return (
        serialize_certificate(certificate),
        serialize_private_key(private_key),
        hex(serial_number),
        not_before.isoformat(),
        not_after.isoformat(),
    )


def issue_end_entity_certificate(
    common_name: str,
    issuer_certificate_pem: str,
    issuer_private_key_pem: str,
    validity_days: int,
    subject_alt_names: Iterable[str],
) -> tuple[str, str, str, str, str]:
    private_key = generate_private_key()
    public_key = private_key.public_key()
    now = utc_now()
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=validity_days)
    serial_number = x509.random_serial_number()
    issuer_certificate = x509.load_pem_x509_certificate(issuer_certificate_pem.encode("utf-8"))
    issuer_private_key = serialization.load_pem_private_key(issuer_private_key_pem.encode("utf-8"), None)
    names = sorted({entry.strip() for entry in subject_alt_names if entry.strip()})
    if not names:
        names = [common_name]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(build_subject(common_name))
        .issuer_name(issuer_certificate.subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier_from_certificate(issuer_certificate), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False)
        .sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
    )
    return (
        serialize_certificate(certificate),
        serialize_private_key(private_key),
        hex(serial_number),
        not_before.isoformat(),
        not_after.isoformat(),
    )


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    instance_path = Path(test_config["INSTANCE_PATH"]) if test_config and "INSTANCE_PATH" in test_config else Path("instance")
    instance_path.mkdir(parents=True, exist_ok=True)
    app.config.update(
        SECRET_KEY=os.environ.get("PKIMASTER_SECRET_KEY", ""),
        DATABASE=os.environ.get("PKIMASTER_DB_PATH", str(instance_path / "pkimaster.sqlite")),
        ADMIN_TOKEN=os.environ.get("PKIMASTER_ADMIN_TOKEN", ""),
        KEY_ENCRYPTION_SECRET=os.environ.get("PKIMASTER_KEY_ENCRYPTION_SECRET", ""),
        INSTANCE_PATH=str(instance_path),
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("TESTING"):
        required_settings = {
            "SECRET_KEY": "PKIMASTER_SECRET_KEY",
            "KEY_ENCRYPTION_SECRET": "PKIMASTER_KEY_ENCRYPTION_SECRET",
        }
        missing_settings = [
            env_name
            for config_name, env_name in required_settings.items()
            if not str(app.config.get(config_name, "")).strip()
        ]
        if missing_settings:
            missing_csv = ", ".join(missing_settings)
            raise RuntimeError(f"Missing required security configuration: {missing_csv}")
    init_db(app)

    @app.teardown_appcontext
    def close_db(_: object | None) -> None:
        database = g.pop("db", None)
        if database is not None:
            database.close()

    @app.get("/")
    def index() -> str:
        authorities = list_authorities()
        issuing_authorities = [authority for authority in authorities if authority["role"] == "issuing"]
        certificates = get_db().execute(
            """
            SELECT certificates.*, authorities.name AS authority_name
            FROM certificates
            JOIN authorities ON authorities.id = certificates.authority_id
            ORDER BY certificates.id DESC
            """
        ).fetchall()
        return render_template(
            "index.html",
            title="PKIMaster",
            admin_token_configured=bool(app.config["ADMIN_TOKEN"]),
            authorities=authorities,
            certificates=certificates,
            issuing_authorities=issuing_authorities,
            key_download_enabled=key_download_enabled(),
        )

    @app.get("/authorities/<int:authority_id>")
    def authority_detail(authority_id: int) -> str:
        authority = get_authority(authority_id)
        if authority is None:
            return Response("Not found", status=404)
        db = get_db()
        child_authorities = db.execute(
            "SELECT id, name, role FROM authorities WHERE parent_id = ? ORDER BY id", (authority_id,)
        ).fetchall()
        issued_certificates = db.execute(
            "SELECT id, common_name FROM certificates WHERE authority_id = ? ORDER BY id DESC", (authority_id,)
        ).fetchall()
        return render_template(
            "authority_detail.html",
            title=authority["name"],
            authority=authority,
            child_authorities=child_authorities,
            issued_certificates=issued_certificates,
            key_download_enabled=key_download_enabled(),
        )

    @app.post("/unlock-private-keys")
    def unlock_private_keys() -> Response:
        configured_token = app.config.get("ADMIN_TOKEN", "")
        submitted_token = request.form.get("token", "")
        if not configured_token:
            flash("Private-key downloads are disabled until PKIMASTER_ADMIN_TOKEN is configured.")
        elif compare_digest(submitted_token, configured_token):
            session["private_key_access"] = True
            flash("Private-key downloads unlocked for this session.")
        else:
            flash("Invalid admin token.")
        return redirect(url_for("index"))

    @app.post("/authorities")
    def create_authority() -> Response:
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "").strip().lower()
        common_name = request.form.get("common_name", "").strip()
        parent_id = request.form.get("parent_id", "").strip()
        validity_days = parse_positive_int(request.form.get("validity_days"), 3650, 1, 7300)
        if not name or not common_name or role not in {"root", "intermediate", "issuing"}:
            flash("Provide a name, role, and certificate common name.")
            return redirect(url_for("index"))
        if role == "root" and parent_id:
            flash("Root CAs must be self-signed.")
            return redirect(url_for("index"))
        parent = None
        if role != "root":
            if not parent_id:
                flash("Intermediate and Issuing CAs require a parent CA.")
                return redirect(url_for("index"))
            if not parent_id.isdigit():
                flash("Selected parent CA is invalid.")
                return redirect(url_for("index"))
            parent = get_authority(int(parent_id))
            if parent is None:
                flash("Selected parent CA does not exist.")
                return redirect(url_for("index"))
            if not valid_parent_child_roles(parent["role"], role):
                flash("Invalid CA hierarchy. Allowed pairs are Root → Intermediate/Issuing and Intermediate → Issuing.")
                return redirect(url_for("index"))
        try:
            certificate_pem, private_key_pem, serial_number, not_before, not_after = create_ca_certificate(
                common_name=common_name,
                validity_days=validity_days,
                role=role,
                issuer_role=parent["role"] if parent else None,
                issuer_certificate_pem=parent["certificate_pem"] if parent else None,
                issuer_private_key_pem=decrypt_private_key(parent["private_key_pem"]) if parent else None,
            )
            db = get_db()
            db.execute(
                """
                INSERT INTO authorities
                (name, role, common_name, parent_id, certificate_pem, private_key_pem, serial_number, not_before, not_after)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    role,
                    common_name,
                    int(parent_id) if parent_id else None,
                    certificate_pem,
                    encrypt_private_key(private_key_pem),
                    serial_number,
                    not_before,
                    not_after,
                ),
            )
            db.commit()
            flash(f"Created {role} CA '{name}'.")
        except sqlite3.IntegrityError:
            flash("CA names must be unique.")
        return redirect(url_for("index"))

    @app.post("/certificates")
    def create_certificate() -> Response:
        common_name = request.form.get("common_name", "").strip()
        authority_id = request.form.get("authority_id", "").strip()
        validity_days = parse_positive_int(request.form.get("validity_days"), 397, 1, 825)
        sans = request.form.get("subject_alt_names", "").split(",")
        if not common_name or not authority_id:
            flash("Provide a certificate common name and issuing authority.")
            return redirect(url_for("index"))
        if not authority_id.isdigit():
            flash("Selected issuing authority is invalid.")
            return redirect(url_for("index"))
        authority = get_authority(int(authority_id))
        if authority is None:
            flash("Selected issuing authority does not exist.")
            return redirect(url_for("index"))
        if authority["role"] != "issuing":
            flash("End-entity certificates must be issued by an Issuing CA.")
            return redirect(url_for("index"))
        certificate_pem, private_key_pem, serial_number, not_before, not_after = issue_end_entity_certificate(
            common_name=common_name,
            issuer_certificate_pem=authority["certificate_pem"],
            issuer_private_key_pem=decrypt_private_key(authority["private_key_pem"]),
            validity_days=validity_days,
            subject_alt_names=sans,
        )
        db = get_db()
        db.execute(
            """
            INSERT INTO certificates
            (common_name, authority_id, subject_alt_names, certificate_pem, private_key_pem, serial_number, not_before, not_after)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                common_name,
                int(authority_id),
                ", ".join(name.strip() for name in sans if name.strip()),
                certificate_pem,
                encrypt_private_key(private_key_pem),
                serial_number,
                not_before,
                not_after,
            ),
        )
        db.commit()
        flash(f"Issued certificate '{common_name}'.")
        return redirect(url_for("index"))

    @app.get("/authorities/<int:authority_id>/<artifact>")
    def download_authority(authority_id: int, artifact: str) -> Response:
        authority = get_authority(authority_id)
        if authority is None:
            return Response("Not found", status=404)
        if artifact == "cert":
            return text_download(authority["name"], "crt.pem", authority["certificate_pem"])
        if artifact == "key":
            if not key_download_enabled():
                return Response("Forbidden", status=403)
            return text_download(authority["name"], "key.pem", decrypt_private_key(authority["private_key_pem"]))
        if artifact == "chain":
            return text_download(authority["name"], "chain.pem", build_ca_chain(authority_id))
        return Response("Not found", status=404)

    @app.get("/certificates/<int:certificate_id>/<artifact>")
    def download_certificate(certificate_id: int, artifact: str) -> Response:
        db = get_db()
        certificate = db.execute("SELECT * FROM certificates WHERE id = ?", (certificate_id,)).fetchone()
        if certificate is None:
            return Response("Not found", status=404)
        if artifact == "cert":
            return text_download(certificate["common_name"], "crt.pem", certificate["certificate_pem"])
        if artifact == "key":
            if not key_download_enabled():
                return Response("Forbidden", status=403)
            return text_download(
                certificate["common_name"], "key.pem", decrypt_private_key(certificate["private_key_pem"])
            )
        if artifact == "chain":
            return text_download(
                certificate["common_name"], "chain.pem", build_certificate_chain(certificate["certificate_pem"], certificate["authority_id"])
            )
        return Response("Not found", status=404)

    @app.get("/healthz")
    def healthz() -> Response:
        return {"status": "ok"}

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def init_db(app: Flask) -> None:
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS authorities (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              role TEXT NOT NULL CHECK(role IN ('root', 'intermediate', 'issuing')),
              common_name TEXT NOT NULL,
              parent_id INTEGER REFERENCES authorities(id),
              certificate_pem TEXT NOT NULL,
              private_key_pem TEXT NOT NULL,
              serial_number TEXT NOT NULL,
              not_before TEXT NOT NULL,
              not_after TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS certificates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              common_name TEXT NOT NULL,
              authority_id INTEGER NOT NULL REFERENCES authorities(id),
              subject_alt_names TEXT NOT NULL DEFAULT '',
              certificate_pem TEXT NOT NULL,
              private_key_pem TEXT NOT NULL,
              serial_number TEXT NOT NULL,
              not_before TEXT NOT NULL,
              not_after TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


def list_authorities() -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT authorities.*, parent.name AS parent_name
        FROM authorities
        LEFT JOIN authorities parent ON parent.id = authorities.parent_id
        ORDER BY authorities.id
        """
    ).fetchall()


def get_authority(authority_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        """
        SELECT authorities.*, parent.name AS parent_name
        FROM authorities
        LEFT JOIN authorities parent ON parent.id = authorities.parent_id
        WHERE authorities.id = ?
        """,
        (authority_id,),
    ).fetchone()


def build_ca_chain(authority_id: int) -> str:
    chain: list[str] = []
    current_id = authority_id
    while current_id is not None:
        authority = get_db().execute(
            "SELECT id, parent_id, certificate_pem FROM authorities WHERE id = ?", (current_id,)
        ).fetchone()
        if authority is None:
            break
        chain.append(authority["certificate_pem"])
        current_id = authority["parent_id"]
    return "".join(chain)


def build_certificate_chain(certificate_pem: str, authority_id: int) -> str:
    return certificate_pem + build_ca_chain(authority_id)


def text_download(stem: str, suffix: str, body: str) -> Response:
    safe_name = secure_filename(stem) or "pkimaster"
    response = Response(body, mimetype="application/x-pem-file")
    response.headers["Content-Disposition"] = f'attachment; filename="{safe_name}-{suffix}"'
    return response


def main() -> None:
    os.environ.setdefault("PKIMASTER_SECRET_KEY", secrets.token_urlsafe(32))
    os.environ.setdefault("PKIMASTER_KEY_ENCRYPTION_SECRET", secrets.token_urlsafe(32))
    development_app = create_app()
    development_app.run(
        host=os.environ.get("PKIMASTER_HOST", "127.0.0.1"),
        port=int(os.environ.get("PKIMASTER_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
