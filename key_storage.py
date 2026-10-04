"""Browser-only configuration and immutable binding of the local CA signing key."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from enterprise import audit_event, require_roles

key_storage = Blueprint("key_storage", __name__)
LABELS = {"software": "Encrypted software key", "pkcs11": "PKCS#11 / SoftHSM", "azure": "Azure Key Vault"}
SECRET_FIELDS = {"user_pin", "client_secret"}
CONFIG_FIELDS = {"module_path", "token_label", "token_serial", "user_pin", "key_id", "vault_url", "tenant_id", "client_id", "client_secret", "key_name", "key_type"}


def configuration():
    from app import get_db, private_key_cipher
    row = get_db().execute("SELECT value FROM settings WHERE key='key_storage_config'").fetchone()
    return json.loads(private_key_cipher().decrypt(row[0].encode())) if row else {"backend": "software"}


def _save(values):
    from app import get_db, private_key_cipher
    _archive_revoked_credentials()
    encrypted = private_key_cipher().encrypt(json.dumps(values).encode()).decode()
    get_db().execute("INSERT INTO settings (key,value) VALUES ('key_storage_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encrypted,))


def _archive_revoked_credentials():
    """Keep retired providers usable for their existing CRL URLs."""
    from app import get_db, private_key_cipher
    db = get_db()
    saved = configuration()
    for authority in db.execute("SELECT * FROM authorities WHERE revoked_at IS NOT NULL AND key_backend != 'software'"):
        name = f"authority_key_storage:{authority['id']}"
        if db.execute("SELECT 1 FROM settings WHERE key=?", (name,)).fetchone():
            continue
        values = {**saved, **json.loads(authority["key_reference"]), "backend": authority["key_backend"]}
        encrypted = private_key_cipher().encrypt(json.dumps(values).encode()).decode()
        db.execute("INSERT INTO settings (key,value) VALUES (?,?)", (name, encrypted))


def _new_authority_configuration(saved):
    """An inherited provider binding must create a new key after revocation."""
    from app import get_db
    values = dict(saved)
    fingerprint = values.get("public_key_sha256")
    if fingerprint:
        for authority in get_db().execute("SELECT key_reference FROM authorities WHERE revoked_at IS NOT NULL AND key_backend=?", (values["backend"],)):
            if json.loads(authority["key_reference"]).get("public_key_sha256") == fingerprint:
                if values["backend"] == "azure" and not values.get("key_name"):
                    values["key_name"] = urlsplit(values["key_id"]).path.split("/")[-2]
                values.pop("key_id", None)
                values.pop("public_key_sha256", None)
                break
    return values


def delete_authority_key_material(db, authority):
    """Forget local credentials and bindings, never destroy an external key."""
    from app import current_authority, private_key_cipher
    from key_backends import public_key_fingerprint
    if not db.in_transaction or not authority["revoked_at"]:
        raise RuntimeError("Key cleanup requires a revoked CA and a transaction.")
    public_key = (x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).public_key()
                  if authority["certificate_pem"] else x509.load_pem_x509_csr(authority["csr_pem"].encode()).public_key())
    fingerprint = public_key_fingerprint(public_key)
    db.execute("INSERT OR IGNORE INTO retired_ca_keys(public_key_sha256) VALUES (?)", (fingerprint,))
    # Preserve other archives before changing the shared provider settings.
    _archive_revoked_credentials()
    saved = configuration()
    reference = json.loads(authority["key_reference"] or "{}")
    fingerprint_matches = saved.get("public_key_sha256") == fingerprint
    reference_matches = (not saved.get("public_key_sha256") and saved.get("key_id")
                         and saved["key_id"] == reference.get("key_id")
                         and all(saved.get(field) == reference.get(field) for field in
                                 ("module_path", "token_label", "token_serial", "vault_url")))
    if (current_authority(db) is None and saved["backend"] == authority["key_backend"] != "software"
            and (fingerprint_matches or reference_matches)):
        if saved["backend"] == "azure" and not saved.get("key_name"):
            saved["key_name"] = urlsplit(saved["key_id"]).path.split("/")[-2]
        saved.pop("key_id", None)
        saved.pop("public_key_sha256", None)
        encrypted = private_key_cipher().encrypt(json.dumps(saved).encode()).decode()
        db.execute("UPDATE settings SET value=? WHERE key='key_storage_config'", (encrypted,))
    db.execute("DELETE FROM settings WHERE key=?", (f"authority_key_storage:{authority['id']}",))


def _reject_revoked_key(signer):
    from app import get_db
    from key_backends import public_key_fingerprint
    fingerprint = public_key_fingerprint(signer.public_key())
    if get_db().execute("SELECT 1 FROM retired_ca_keys WHERE public_key_sha256=?", (fingerprint,)).fetchone():
        raise ValueError("The selected signing key belongs to a revoked CA. Select a different key or leave the existing key ID empty to generate a new one.")
    for authority in get_db().execute("SELECT certificate_pem, csr_pem FROM authorities WHERE revoked_at IS NOT NULL"):
        public_key = (x509.load_pem_x509_certificate(authority["certificate_pem"].encode()).public_key()
                      if authority["certificate_pem"] else x509.load_pem_x509_csr(authority["csr_pem"].encode()).public_key())
        if public_key_fingerprint(public_key) == fingerprint:
            raise ValueError("The selected signing key belongs to a revoked CA. Select a different key or leave the existing key ID empty to generate a new one.")


def managed_softhsm(config):
    """SoftHSM state lives inside the service's private, writable state directory."""
    if Path(config.get("module_path", "")).name != "libsofthsm2.so":
        return
    directory = Path(current_app.config["INSTANCE_PATH"]) / "softhsm"
    tokens = directory / "tokens"
    tokens.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = directory / "softhsm2.conf"
    if not path.exists():
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(f"directories.tokendir = {tokens.as_posix()}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
        if os.name != "nt":
            path.chmod(0o600)
    os.environ["SOFTHSM2_CONF"] = str(path)


def provision_authority_key():
    from key_backends import provision_signer
    config = _new_authority_configuration(configuration())
    backend = config["backend"]
    if backend == "software":
        return None, backend, ""
    managed_softhsm(config)
    signer, pinned = provision_signer(backend, config)
    _reject_revoked_key(signer)
    # Credentials remain replaceable; binding to module/token/object or the
    # exact Azure key version and public key remains immutable in the CA row.
    reference = {key: value for key, value in pinned.items() if key not in SECRET_FIELDS}
    _save({**pinned, "backend": backend})
    return signer, backend, json.dumps(reference, sort_keys=True)


def authority_signing_key(authority):
    from app import decrypt_private_key, get_db, private_key_cipher
    from key_backends import load_signer
    if authority["key_backend"] == "software":
        return decrypt_private_key(authority["private_key_pem"])
    archived = get_db().execute("SELECT value FROM settings WHERE key=?", (f"authority_key_storage:{authority['id']}",)).fetchone()
    credentials = json.loads(private_key_cipher().decrypt(archived[0].encode())) if archived else configuration()
    config = {**credentials, **json.loads(authority["key_reference"])}
    managed_softhsm(config)
    return load_signer(authority["key_backend"], config)


def init_key_storage(app):
    app.register_blueprint(key_storage)

    @app.context_processor
    def key_context():
        from app import current_authority
        row = current_authority()
        return {"key_backend_label": LABELS.get(row["key_backend"] if row else configuration()["backend"], "External key")}


def _validate(values):
    backend = values["backend"]
    if backend not in LABELS:
        raise ValueError("Select a supported key provider.")
    if backend == "pkcs11":
        if not Path(values.get("module_path", "")).is_absolute() or not values.get("token_label") or not values.get("user_pin"):
            raise ValueError("Provide an absolute PKCS#11 module path, token label and user PIN.")
        if len(values["token_label"].encode()) > 32:
            raise ValueError("Token labels must fit within 32 UTF-8 bytes.")
    if backend == "azure":
        parsed = urlsplit(values.get("vault_url", ""))
        if (parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith((".vault.azure.net", ".managedhsm.azure.net"))
                or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
            raise ValueError("Use an HTTPS Azure vault or managed HSM URL without a path or credentials.")
        if not all(values.get(field) for field in ("tenant_id", "client_id", "client_secret")) or not (values.get("key_id") or values.get("key_name")):
            raise ValueError("Provide the Azure tenant, application ID, client secret and key name or versioned key ID.")
        if values.get("key_type") not in {"RSA", "RSA-HSM"}:
            raise ValueError("Select RSA or RSA-HSM explicitly.")


@key_storage.route("/settings/keys", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    from app import current_authority, get_db
    db = get_db()
    authority = current_authority(db)
    saved = configuration() if authority else _new_authority_configuration(configuration())
    if request.method == "POST":
        from approvals import approval_gate
        approval_response = approval_gate()
        if approval_response is not None:
            return approval_response
        try:
            db.execute("BEGIN IMMEDIATE")
            # Re-read under the same lock used by CA creation.
            authority = current_authority(db)
            saved = configuration() if authority else _new_authority_configuration(configuration())
            backend = request.form.get("backend", saved["backend"])
            if authority:
                if backend != authority["key_backend"]:
                    raise ValueError("The CA key provider is fixed after initialization.")
                values = dict(saved)
                for field in SECRET_FIELDS:
                    if request.form.get(field):
                        values[field] = request.form[field]
                # Verify replacements against the pinned key before storing.
                if backend != "software":
                    from key_backends import load_signer
                    pinned = {**values, **json.loads(authority["key_reference"])}
                    managed_softhsm(pinned)
                    signer = load_signer(backend, pinned)
                    signer.sign(os.urandom(32))
                if request.form.get("initialize_token"):
                    raise ValueError("Token initialization is only available before CA creation.")
            else:
                values = {field: request.form.get(field, "").strip() for field in CONFIG_FIELDS if field not in SECRET_FIELDS}
                values.update({field: request.form.get(field) or (saved.get(field, "") if saved["backend"] == backend else "") for field in SECRET_FIELDS})
                values["backend"] = backend
                if backend == "azure":
                    values["key_id"] = request.form.get("azure_key_id", "").strip()
                _validate(values)
                if request.form.get("initialize_token"):
                    if backend != "pkcs11" or Path(values["module_path"]).name != "libsofthsm2.so":
                        raise ValueError("Browser token initialization is restricted to SoftHSM.")
                    so_pin = request.form.get("so_pin", "")
                    if len(so_pin) < 8 or len(values["user_pin"]) < 8 or so_pin == values["user_pin"]:
                        raise ValueError("Use different security-officer and user PINs, each at least 8 characters.")
                    from key_backends import initialize_softhsm
                    managed_softhsm(values)
                    initialize_softhsm(values, so_pin)
            _save(values)
            audit_event("key_storage.updated", "settings", detail=backend + (" credentials verified" if authority else " configured"))
            db.commit()
            flash("Key storage saved. The CA key is permanently bound when the CA is initialized." if not authority else "Credentials verified against the existing CA key and saved.", "success")
            return redirect(url_for("key_storage.settings"))
        except (ValueError, OSError) as exc:
            db.rollback()
            flash(str(exc), "error")
            saved = configuration() if authority else _new_authority_configuration(configuration())
            status = 400
    else:
        status = 200
    public = {key: value for key, value in saved.items() if key not in SECRET_FIELDS}
    return render_template("key_storage.html", title="Key storage", provider=public, authority=authority, labels=LABELS,
                           has_pin=bool(saved.get("user_pin")), has_client_secret=bool(saved.get("client_secret"))), status
