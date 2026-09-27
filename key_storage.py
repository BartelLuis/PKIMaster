"""Browser-only configuration and immutable binding of the local CA signing key."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

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
    encrypted = private_key_cipher().encrypt(json.dumps(values).encode()).decode()
    get_db().execute("INSERT INTO settings (key,value) VALUES ('key_storage_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encrypted,))


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
    config = configuration()
    backend = config["backend"]
    if backend == "software":
        return None, backend, ""
    managed_softhsm(config)
    signer, pinned = provision_signer(backend, config)
    # Credentials remain replaceable; binding to module/token/object or the
    # exact Azure key version and public key remains immutable in the CA row.
    reference = {key: value for key, value in pinned.items() if key not in SECRET_FIELDS}
    _save({**pinned, "backend": backend})
    return signer, backend, json.dumps(reference, sort_keys=True)


def authority_signing_key(authority):
    from app import decrypt_private_key
    from key_backends import load_signer
    if authority["key_backend"] == "software":
        return decrypt_private_key(authority["private_key_pem"])
    config = {**configuration(), **json.loads(authority["key_reference"])}
    managed_softhsm(config)
    return load_signer(authority["key_backend"], config)


def init_key_storage(app):
    app.register_blueprint(key_storage)

    @app.context_processor
    def key_context():
        from app import get_db
        row = get_db().execute("SELECT key_backend FROM authorities LIMIT 1").fetchone()
        return {"key_backend_label": LABELS.get(row[0] if row else configuration()["backend"], "External key")}


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
    from app import get_db
    db = get_db()
    authority = db.execute("SELECT * FROM authorities LIMIT 1").fetchone()
    saved = configuration()
    if request.method == "POST":
        try:
            db.execute("BEGIN IMMEDIATE")
            # Re-read under the same lock used by CA creation.
            authority = db.execute("SELECT * FROM authorities LIMIT 1").fetchone()
            saved = configuration()
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
            saved = configuration()
            status = 400
    else:
        status = 200
    public = {key: value for key, value in saved.items() if key not in SECRET_FIELDS}
    return render_template("key_storage.html", title="Key storage", provider=public, authority=authority, labels=LABELS,
                           has_pin=bool(saved.get("user_pin")), has_client_secret=bool(saved.get("client_secret"))), status
