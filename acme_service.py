"""An EAB-gated RFC 8555 service for the installation's active Issuing CA.

Protocol requests authenticate with JWS, never a browser session. Challenge
connections are bounded and pinned after address validation. Leaf private keys
are generated and retained by the ACME client.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID
from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from enterprise import audit_event, get_setting, require_roles


acme_protocol = Blueprint("acme_protocol", __name__, url_prefix="/acme")
acme_admin = Blueprint("acme_admin", __name__)
PROBLEM = "urn:ietf:params:acme:error:"
_VALIDATORS = threading.BoundedSemaphore(8)
_PRIVATE = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


class AcmeError(ValueError):
    def __init__(self, kind, detail, status=400):
        self.kind, self.detail, self.status = kind, detail, status
        super().__init__(detail)


def _db():
    from app import get_db
    return get_db()


def _now():
    return datetime.now(UTC)


def _stamp(value=None):
    return (value or _now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field.")
        result[key] = value
    return result


def _loads(value):
    return json.loads(value, object_pairs_hook=_unique_object)


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value, maximum=100000):
    if not isinstance(value, str) or len(value) > maximum or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("Invalid base64url value.")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64(decoded) != value:
        raise ValueError("Noncanonical base64url value.")
    return decoded


def configuration():
    values = {"enabled": False, "allow_private": False, "http01": True, "dns01": True, "validity_days": 90}
    values.update(json.loads(get_setting("acme_config", "{}")))
    return values


def _base():
    value = get_setting("public_base_url", "").rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AcmeError("serverInternal", "Configure the public HTTPS base URL before enabling ACME.", 503)
    return value


def _url(endpoint, **values):
    return _base() + url_for("acme_protocol." + endpoint, **values)


def _jwk_key(jwk):
    if not isinstance(jwk, dict) or any(field in jwk for field in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")):
        raise ValueError("Use a public JWK.")
    if jwk.get("kty") == "RSA":
        clean = {name: jwk[name] for name in ("e", "kty", "n")}
        encoded = [_unb64(clean[field], 2048) for field in ("n", "e")]
        if any(not value or value[0] == 0 for value in encoded):
            raise ValueError("JWK integers must use minimal unsigned encoding.")
        n, e = (int.from_bytes(value, "big") for value in encoded)
        if not 2048 <= n.bit_length() <= 8192 or not 3 <= e <= 2**32 - 1 or not e % 2:
            raise ValueError("RSA account keys must be 2048 to 8192 bits.")
        return clean, rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "EC":
        clean = {name: jwk[name] for name in ("crv", "kty", "x", "y")}
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}.get(clean["crv"])
        if curve is None:
            raise ValueError("Unsupported account curve.")
        x, y = (_unb64(clean[field], 100) for field in ("x", "y"))
        if len(x) != (curve().key_size + 7) // 8 or len(y) != len(x):
            raise ValueError("Invalid EC coordinate length.")
        return clean, ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve()).public_key()
    raise ValueError("Use an RSA or EC account key.")


def _thumb(jwk):
    return _b64(hashlib.sha256(_json(_jwk_key(jwk)[0]).encode()).digest())


def _verify(jws, jwk, *, nonce=True):
    if not isinstance(jws, dict) or set(jws) != {"protected", "payload", "signature"}:
        raise AcmeError("malformed", "Use a flattened JWS with protected headers only.")
    try:
        header = _loads(_unb64(jws["protected"], 16000))
        if not isinstance(header, dict) or header.get("crit") or "b64" in header:
            raise ValueError("Unsupported JWS header.")
        clean, key = _jwk_key(jwk)
        algorithm = header.get("alg", "")
        digest = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512,
                  "ES256": hashes.SHA256, "ES384": hashes.SHA384, "ES512": hashes.SHA512}.get(algorithm)
        if digest is None:
            raise AcmeError("badSignatureAlgorithm", "Supported algorithms: RS256, RS384, RS512, ES256, ES384, ES512.")
        payload = _unb64(jws["payload"])
        signature = _unb64(jws["signature"], 2000)
        signed = (jws["protected"] + "." + jws["payload"]).encode("ascii")
        if isinstance(key, rsa.RSAPublicKey) and algorithm.startswith("RS"):
            key.verify(signature, signed, padding.PKCS1v15(), digest())
        elif isinstance(key, ec.EllipticCurvePublicKey) and algorithm == {256: "ES256", 384: "ES384", 521: "ES512"}[key.key_size]:
            size = (key.key_size + 7) // 8
            if len(signature) != size * 2:
                raise ValueError("Invalid ECDSA signature size.")
            key.verify(utils.encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")), signed, ec.ECDSA(digest()))
        else:
            raise ValueError("JWS algorithm does not match its key.")
        expected_url = _base() + request.path
        if header.get("url") != expected_url or request.query_string:
            raise AcmeError("malformed", "The protected URL must exactly match this resource's public URL.")
        if nonce:
            token = header.get("nonce")
            if not isinstance(token, str) or len(token) > 100:
                raise AcmeError("badNonce", "Obtain a fresh Replay-Nonce and retry.")
            found = _db().execute("DELETE FROM acme_nonces WHERE nonce=? AND expires>? RETURNING nonce", (token, int(time.time()))).fetchone()
            _db().commit()
            if not found:
                raise AcmeError("badNonce", "The nonce is unknown, expired or already used. Retry with the fresh Replay-Nonce.")
        elif "nonce" in header:
            raise ValueError("Nested JWS must not contain a nonce.")
        return header, payload, clean
    except AcmeError:
        raise
    except (ValueError, TypeError, KeyError, InvalidSignature, UnsupportedAlgorithm, OverflowError) as error:
        raise AcmeError("malformed", "Invalid JWS, signature, or account key.") from error


def _authenticated(*, new_account=False, allow_jwk=False):
    request.max_content_length = 131072
    if request.mimetype != "application/jose+json":
        raise AcmeError("malformed", "Use Content-Type application/jose+json.", 415)
    if request.content_length is not None and request.content_length > 131072:
        raise AcmeError("malformed", "ACME requests are limited to 128 KiB.", 413)
    try:
        raw_body = request.get_data(cache=False)
        if len(raw_body) > 131072:
            raise AcmeError("malformed", "ACME requests are limited to 128 KiB.", 413)
        jws = _loads(raw_body)
        header = _loads(_unb64(jws["protected"], 16000))
        if not isinstance(header, dict) or ("jwk" in header) == ("kid" in header):
            raise ValueError("Provide exactly one account key identifier.")
        account = None
        if "jwk" in header:
            if not new_account and not allow_jwk:
                raise AcmeError("unauthorized", "Authenticate with the account URL.", 403)
            jwk = header["jwk"]
        else:
            if new_account:
                raise ValueError("Account creation requires a JWK.")
            prefix = _url("account", account_id="")
            kid = header["kid"]
            if not isinstance(kid, str) or not kid.startswith(prefix):
                raise AcmeError("accountDoesNotExist", "Unknown ACME account.")
            account = _db().execute("SELECT * FROM acme_accounts WHERE id=?", (kid[len(prefix):],)).fetchone()
            if account is None or kid != _url("account", account_id=account["id"]):
                raise AcmeError("accountDoesNotExist", "Unknown ACME account.")
            if account["status"] != "valid":
                raise AcmeError("unauthorized", "This ACME account is deactivated.", 403)
            jwk = _loads(account["jwk"])
        _, raw, clean = _verify(jws, jwk)
        payload = None if not raw else _loads(raw)
        if payload is not None and not isinstance(payload, dict):
            raise ValueError("JWS payload must be an object or empty.")
        if account is not None:
            _verify_audit()
        return account, payload, clean
    except RequestEntityTooLarge as error:
        raise AcmeError("malformed", "ACME requests are limited to 128 KiB.", 413) from error
    except AcmeError:
        raise
    except (ValueError, TypeError, KeyError) as error:
        raise AcmeError("malformed", "Invalid ACME JWS body.") from error


def _verify_audit():
    # Anonymous/self-signed requests cannot force an O(history) audit scan.
    # EAB enrollment and certificate-key revocation call this only once their
    # separate authorization proof is verified.
    from audit_integrity import AuditIntegrityError, verify_chain
    try:
        verify_chain(_db(), current_app.config["KEY_ENCRYPTION_SECRET"])
    except AuditIntegrityError as error:
        raise AcmeError("serverInternal", "Audit integrity verification failed; ACME operations are blocked.", 503) from error


def _post_as_get(payload):
    if payload is not None:
        raise AcmeError("malformed", "Fetching this resource requires an empty JWS payload.")


def _rate(key, maximum, seconds):
    slot = int(time.time()) // seconds
    db = _db()
    db.execute("DELETE FROM acme_limits WHERE expires < ?", (int(time.time()),))
    row = db.execute("INSERT INTO acme_limits (key,slot,count,expires) VALUES (?,?,1,?) ON CONFLICT(key,slot) DO UPDATE SET count=count+1 RETURNING count",
                     (key, slot, (slot + 1) * seconds)).fetchone()
    db.commit()
    if row[0] > maximum:
        raise AcmeError("rateLimited", "ACME request limit reached. Retry later.", 429)


def init_acme(app):
    with closing(sqlite3.connect(app.config["DATABASE"])) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS acme_nonces (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS acme_nonce_expiry ON acme_nonces(expires);
            CREATE TABLE IF NOT EXISTS acme_limits (key TEXT NOT NULL,slot INTEGER NOT NULL,count INTEGER NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(key,slot));
            CREATE TABLE IF NOT EXISTS acme_eab (
                id TEXT PRIMARY KEY, label TEXT NOT NULL, secret TEXT NOT NULL, domains TEXT NOT NULL,
                profile_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires TEXT NOT NULL,
                used_at TEXT, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS acme_accounts (
                id TEXT PRIMARY KEY, jwk TEXT NOT NULL, thumbprint TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
                contacts TEXT NOT NULL, eab_id TEXT NOT NULL, eab_binding TEXT NOT NULL, domains TEXT NOT NULL,
                profile_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS acme_orders (
                id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES acme_accounts(id),
                authority_id INTEGER NOT NULL REFERENCES authorities(id) ON DELETE CASCADE,
                status TEXT NOT NULL, identifiers TEXT NOT NULL, expires TEXT NOT NULL, created_at TEXT NOT NULL,
                certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL, csr_sha256 TEXT,
                error TEXT, chain_pem TEXT);
            CREATE INDEX IF NOT EXISTS acme_account_orders ON acme_orders(account_id,created_at);
            CREATE TABLE IF NOT EXISTS acme_authorizations (
                id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
                identifier TEXT NOT NULL, wildcard INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS acme_challenges (
                id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
                type TEXT NOT NULL, token TEXT NOT NULL, status TEXT NOT NULL, validated TEXT, error TEXT, started TEXT);
        """)
    app.register_blueprint(acme_protocol)
    app.register_blueprint(acme_admin)


@acme_protocol.before_request
def enabled():
    if not configuration()["enabled"]:
        raise AcmeError("serverInternal", "ACME is disabled on this installation.", 503)
    _base()


@acme_protocol.errorhandler(AcmeError)
def problem(error):
    _db().rollback()
    response = jsonify({"type": PROBLEM + error.kind, "detail": error.detail, "status": error.status})
    response.status_code = error.status
    response.mimetype = "application/problem+json"
    if error.status == 429:
        response.headers["Retry-After"] = "3600"
    return response


@acme_protocol.after_request
def protocol_headers(response):
    db = _db()
    # Never accidentally commit a partially executed handler on an error path.
    db.rollback()
    db.execute("DELETE FROM acme_nonces WHERE expires<=?", (int(time.time()),))
    if db.execute("SELECT COUNT(*) FROM acme_nonces").fetchone()[0] >= 10000:
        db.execute("DELETE FROM acme_nonces WHERE nonce IN (SELECT nonce FROM acme_nonces ORDER BY expires LIMIT 1000)")
    nonce = secrets.token_urlsafe(32)
    db.execute("INSERT INTO acme_nonces VALUES (?,?)", (nonce, int(time.time()) + 600))
    db.commit()
    response.headers["Replay-Nonce"] = nonce
    response.headers["Cache-Control"] = "no-store"
    try:
        response.headers.add("Link", '<' + _url("directory") + '>;rel="index"')
    except AcmeError:
        pass
    return response


@acme_protocol.route("/directory", methods=["GET", "POST"])
def directory():
    if request.method == "POST":
        _, payload, _ = _authenticated()
        _post_as_get(payload)
    return jsonify({"newNonce": _url("new_nonce"), "newAccount": _url("new_account"),
                    "newOrder": _url("new_order"), "revokeCert": _url("revoke_certificate"),
                    "keyChange": _url("key_change"), "meta": {"externalAccountRequired": True}})


@acme_protocol.route("/new-nonce", methods=["GET", "HEAD", "POST"])
def new_nonce():
    _rate("nonce:" + (request.remote_addr or ""), 120, 60)
    if request.method == "POST":
        _, payload, _ = _authenticated()
        _post_as_get(payload)
    return Response(status=200 if request.method == "HEAD" else 204)


def _contacts(payload):
    contacts = payload.get("contact", [])
    if not isinstance(contacts, list) or len(contacts) > 5 or any(not isinstance(item, str) or not re.fullmatch(r"mailto:[^\s@?]+@[^\s@?]+", item) or len(item) > 260 for item in contacts):
        raise AcmeError("invalidContact", "Use up to five mailto email addresses.")
    return contacts


def _account_json(record):
    return {"status": record["status"], "contact": _loads(record["contacts"]),
            "orders": _url("orders", account_id=record["id"]), "externalAccountBinding": _loads(record["eab_binding"])}


def _resource(data, status=200, location=None):
    response = jsonify(data)
    response.status_code = status
    if location:
        response.headers["Location"] = location
    return response


@acme_protocol.post("/new-account")
def new_account():
    _, payload, jwk = _authenticated(new_account=True)
    if payload is None:
        raise AcmeError("malformed", "Provide an account object.")
    thumb = _thumb(jwk)
    existing = _db().execute("SELECT * FROM acme_accounts WHERE thumbprint=?", (thumb,)).fetchone()
    if existing:
        _verify_audit()
        return _resource(_account_json(existing), location=_url("account", account_id=existing["id"]))
    if payload.get("onlyReturnExisting"):
        raise AcmeError("accountDoesNotExist", "No ACME account exists for this key.")
    _rate("account:" + (request.remote_addr or ""), 20, 3600)
    binding = payload.get("externalAccountBinding")
    if not binding:
        raise AcmeError("externalAccountRequired", "Create a one-use external account credential in the administration console.")
    from app import decrypt_private_key
    db = _db()
    try:
        contacts = _contacts(payload)
        if not isinstance(binding, dict) or set(binding) != {"protected", "payload", "signature"}:
            raise ValueError
        header = _loads(_unb64(binding["protected"], 4000))
        if set(header) != {"alg", "kid", "url"} or header["alg"] != "HS256" or header["url"] != _url("new_account"):
            raise ValueError
        if not isinstance(header["kid"], str) or not 1 <= len(header["kid"]) <= 100:
            raise ValueError
        db.execute("BEGIN IMMEDIATE")
        credential = db.execute("SELECT * FROM acme_eab WHERE id=? AND used_at IS NULL AND revoked=0 AND expires>?", (header["kid"], _stamp())).fetchone()
        if not credential:
            raise ValueError
        secret = _unb64(decrypt_private_key(credential["secret"]))
        expected = hmac.new(secret, (binding["protected"] + "." + binding["payload"]).encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(binding["signature"], 100)) or _jwk_key(_loads(_unb64(binding["payload"], 12000)))[0] != jwk:
            raise ValueError
        _verify_audit()
        account_id = secrets.token_urlsafe(18)
        db.execute("INSERT INTO acme_accounts VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (account_id, _json(jwk), thumb, "valid", _json(contacts), credential["id"], _json(binding), credential["domains"], credential["profile_id"], _stamp()))
        db.execute("UPDATE acme_eab SET used_at=?,secret='' WHERE id=?", (_stamp(), credential["id"]))
        audit_event("acme.account.created", "acme_account", account_id, "EAB=" + credential["id"])
        db.commit()
    except AcmeError:
        db.rollback()
        raise
    except (ValueError, TypeError, KeyError, sqlite3.IntegrityError) as error:
        db.rollback()
        raise AcmeError("unauthorized", "The external account binding is invalid, expired or already used.", 403) from error
    record = db.execute("SELECT * FROM acme_accounts WHERE id=?", (account_id,)).fetchone()
    return _resource(_account_json(record), 201, _url("account", account_id=account_id))


@acme_protocol.post("/account/<account_id>")
def account(account_id):
    record, payload, _ = _authenticated()
    if record["id"] != account_id:
        raise AcmeError("unauthorized", "This resource belongs to another account.", 403)
    if payload:
        db = _db()
        db.execute("BEGIN IMMEDIATE")
        if "status" in payload:
            if payload["status"] != "deactivated":
                raise AcmeError("malformed", "Only account deactivation is supported.")
            db.execute("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (account_id,))
            audit_event("acme.account.deactivated", "acme_account", account_id)
        if "contact" in payload:
            db.execute("UPDATE acme_accounts SET contacts=? WHERE id=?", (_json(_contacts(payload)), account_id))
            audit_event("acme.account.updated", "acme_account", account_id)
        db.commit()
        record = db.execute("SELECT * FROM acme_accounts WHERE id=?", (account_id,)).fetchone()
    return _resource(_account_json(record), location=_url("account", account_id=account_id))


def _dns_name(value, *, wildcard=True):
    if not isinstance(value, str) or not value.isascii() or len(value) > 253:
        raise ValueError("Use an ASCII DNS name (IDNs must use punycode).")
    value = value.lower()
    bare = value[2:] if wildcard and value.startswith("*.") else value
    if len(bare.split(".")) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in bare.split(".")):
        raise ValueError("Use fully qualified DNS names without trailing dots.")
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        return value
    raise ValueError("ACME currently accepts DNS identifiers only.")


def _domain_allowed(name, domains):
    # A '*.example.org' grant covers descendants and wildcard certificates;
    # the apex itself must be granted separately.
    return any(name == domain or domain.startswith("*.") and name.endswith(domain[1:]) and name != domain[2:] for domain in domains)


def _issuer(expected_id=None):
    from app import current_authority, authority_block_reason
    authority = current_authority()
    if not authority or authority["role"] != "issuing" or expected_id is not None and authority["id"] != expected_id:
        raise AcmeError("serverInternal", "An active Issuing CA matching this order is required.", 503)
    reason = authority_block_reason(authority)
    if reason:
        raise AcmeError("serverInternal", reason, 503)
    return authority


@acme_protocol.post("/new-order")
def new_order():
    record, payload, _ = _authenticated()
    if not payload or not isinstance(payload.get("identifiers"), list) or not 1 <= len(payload["identifiers"]) <= 50:
        raise AcmeError("malformed", "An order requires between 1 and 50 DNS identifiers.")
    if "notBefore" in payload or "notAfter" in payload:
        raise AcmeError("malformed", "Custom certificate dates are not supported; the configured lifetime applies.")
    try:
        names = []
        for identifier in payload["identifiers"]:
            if not isinstance(identifier, dict) or identifier.get("type") != "dns":
                raise AcmeError("unsupportedIdentifier", "Only DNS identifiers are supported.")
            name = _dns_name(identifier.get("value"))
            if not _domain_allowed(name, _loads(record["domains"])):
                raise AcmeError("rejectedIdentifier", "An identifier is outside this account's permitted domains.")
            if name not in names:
                names.append(name)
    except ValueError as error:
        if isinstance(error, AcmeError):
            raise
        raise AcmeError("rejectedIdentifier", str(error)) from error
    config = configuration()
    if min(map(len, names)) > 64:
        raise AcmeError("rejectedIdentifier", "At least one ordered DNS name must fit the 64-character certificate common-name limit.")
    if any(name.startswith("*.") for name in names) and not config["dns01"]:
        raise AcmeError("rejectedIdentifier", "Wildcard certificates require DNS-01 validation.")
    _rate("order:" + record["id"], 100, 3600)
    db = _db()
    db.execute("BEGIN IMMEDIATE")
    from certificate_profiles import available_templates
    if not any(str(item["id"]) == record["profile_id"] for item in available_templates(db, role="acme")):
        raise AcmeError("unauthorized", "This account's certificate template no longer permits ACME issuance.", 403)
    if db.execute("SELECT status FROM acme_accounts WHERE id=?", (record["id"],)).fetchone()[0] != "valid":
        raise AcmeError("unauthorized", "This ACME account is deactivated.", 403)
    authority = _issuer()
    try:
        _issuance_policy(record, names)
    except ValueError as error:
        raise AcmeError("rejectedIdentifier", str(error)) from error
    if db.execute("SELECT COUNT(*) FROM acme_orders WHERE account_id=? AND status IN ('pending','ready','processing') AND expires>?", (record["id"], _stamp())).fetchone()[0] >= 20:
        raise AcmeError("rateLimited", "Complete existing orders before creating more.", 429)
    order_id = secrets.token_urlsafe(18)
    identifiers = [{"type": "dns", "value": name} for name in names]
    db.execute("INSERT INTO acme_orders (id,account_id,authority_id,status,identifiers,expires,created_at) VALUES (?,?,?,'pending',?,?,?)",
               (order_id, record["id"], authority["id"], _json(identifiers), _stamp(_now() + timedelta(hours=24)), _stamp()))
    for name in names:
        auth_id = secrets.token_urlsafe(18)
        wildcard = name.startswith("*.")
        db.execute("INSERT INTO acme_authorizations VALUES (?,?,?,?,'pending')", (auth_id, order_id, name[2:] if wildcard else name, wildcard))
        for kind in (["http-01"] if config["http01"] and not wildcard else []) + (["dns-01"] if config["dns01"] else []):
            db.execute("INSERT INTO acme_challenges (id,authorization_id,type,token,status) VALUES (?,?,?,?,'pending')", (secrets.token_urlsafe(18), auth_id, kind, secrets.token_urlsafe(32)))
    audit_event("acme.order.created", "acme_order", order_id, "account=" + record["id"] + "; " + ",".join(names))
    db.commit()
    return _resource(_order_json(_order(record, order_id)), 201, _url("order", order_id=order_id))


def _order(account_record, order_id):
    record = _db().execute("SELECT * FROM acme_orders WHERE id=? AND account_id=?", (order_id, account_record["id"])).fetchone()
    if record is None:
        raise AcmeError("unauthorized", "Order not found for this account.", 403)
    if record["status"] not in {"valid", "invalid"} and record["expires"] <= _stamp():
        _db().execute("UPDATE acme_orders SET status='invalid',error=? WHERE id=?", (_json({"type": PROBLEM + "unauthorized", "detail": "Order expired."}), order_id))
        _db().commit()
        record = _db().execute("SELECT * FROM acme_orders WHERE id=?", (order_id,)).fetchone()
    return record


def _order_json(record):
    data = {"status": record["status"], "expires": record["expires"], "identifiers": _loads(record["identifiers"]),
            "authorizations": [_url("authorization", authorization_id=row[0]) for row in _db().execute("SELECT id FROM acme_authorizations WHERE order_id=? ORDER BY rowid", (record["id"],))],
            "finalize": _url("finalize", order_id=record["id"])}
    if record["status"] == "valid":
        data["certificate"] = _url("certificate", order_id=record["id"])
    if record["error"]:
        data["error"] = _loads(record["error"])
    return data


@acme_protocol.post("/order/<order_id>")
def order(order_id):
    record, payload, _ = _authenticated()
    _post_as_get(payload)
    return _resource(_order_json(_order(record, order_id)), location=_url("order", order_id=order_id))


@acme_protocol.post("/account/<account_id>/orders")
def orders(account_id):
    record, payload, _ = _authenticated()
    _post_as_get(payload)
    if record["id"] != account_id:
        raise AcmeError("unauthorized", "This resource belongs to another account.", 403)
    return jsonify({"orders": [_url("order", order_id=row[0]) for row in _db().execute("SELECT id FROM acme_orders WHERE account_id=? ORDER BY created_at DESC LIMIT 1000", (account_id,))]})


def _authorization(account_record, authorization_id):
    record = _db().execute("SELECT * FROM acme_authorizations WHERE id=?", (authorization_id,)).fetchone()
    if record is None:
        raise AcmeError("unauthorized", "Authorization not found for this account.", 403)
    order_record = _order(account_record, record["order_id"])
    return record, order_record


def _challenge_json(record):
    result = {"type": record["type"], "url": _url("challenge", challenge_id=record["id"]), "status": record["status"], "token": record["token"]}
    if record["validated"]:
        result["validated"] = record["validated"]
    if record["error"]:
        result["error"] = _loads(record["error"])
    return result


@acme_protocol.post("/authorization/<authorization_id>")
def authorization(authorization_id):
    account_record, payload, _ = _authenticated()
    record, order_record = _authorization(account_record, authorization_id)
    if payload is not None:
        if payload != {"status": "deactivated"}:
            raise AcmeError("malformed", "Only authorization deactivation or POST-as-GET is supported.")
        _db().execute("UPDATE acme_authorizations SET status='deactivated' WHERE id=?", (authorization_id,))
        _db().execute("UPDATE acme_orders SET status='invalid' WHERE id=? AND status!='valid'", (order_record["id"],))
        audit_event("acme.authorization.deactivated", "acme_authorization", authorization_id, "account=" + account_record["id"])
        _db().commit()
        record = _db().execute("SELECT * FROM acme_authorizations WHERE id=?", (authorization_id,)).fetchone()
    status = "expired" if order_record["expires"] <= _stamp() and record["status"] in {"pending", "valid"} else record["status"]
    result = {"identifier": {"type": "dns", "value": record["identifier"]}, "status": status, "expires": order_record["expires"],
              "challenges": [_challenge_json(row) for row in _db().execute("SELECT * FROM acme_challenges WHERE authorization_id=? ORDER BY rowid", (authorization_id,))]}
    if record["wildcard"]:
        result["wildcard"] = True
    return jsonify(result)


def _allowed_address(value, allow_private):
    address = ipaddress.ip_address(value)
    address = getattr(address, "ipv4_mapped", None) or address
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    return address.is_global or bool(allow_private and any(address.version == network.version and address in network for network in _PRIVATE))


def validate_http01(host, token, expected, *, allow_private=False):
    import dns.exception
    import dns.resolver
    import socket
    from monitoring_transports import _deadline_timer
    deadline = time.monotonic() + 12
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    addresses = []
    try:
        for kind in ("A", "AAAA"):
            try:
                addresses.extend(str(answer) for answer in resolver.resolve(host + ".", kind, lifetime=max(0.1, min(3, deadline - time.monotonic()))))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
        if not addresses or len(addresses) > 32 or any(not _allowed_address(address, allow_private) for address in addresses):
            raise AcmeError("connection", "The HTTP-01 destination is unresolved or disallowed by network policy.")
        connection = http.client.HTTPConnection(host, 80, timeout=3)
        connection._create_connection = lambda unused, timeout, source_address=None: socket.create_connection((addresses[0], 80), timeout)
        timer = None
        try:
            connection.connect()
            timer = _deadline_timer(connection.sock, max(0.1, deadline - time.monotonic()))
            connection.request("GET", "/.well-known/acme-challenge/" + token, headers={"User-Agent": "PKIMaster ACME", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise AcmeError("connection", "HTTP-01 requires a direct uncompressed HTTP 200 response on port 80.")
            body = response.read(1025)
            if len(body) > 1024 or not hmac.compare_digest(body.rstrip(b" \t\r\n"), expected.encode("ascii")):
                raise AcmeError("incorrectResponse", "HTTP-01 key authorization does not match.")
        finally:
            if timer:
                timer.cancel()
            connection.close()
    except AcmeError:
        raise
    except (OSError, dns.exception.DNSException, http.client.HTTPException) as error:
        raise AcmeError("connection", "The HTTP-01 challenge could not be retrieved within the network deadline.") from error


def validate_dns01(host, expected):
    import dns.exception
    import dns.resolver
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        answers = resolver.resolve("_acme-challenge." + host + ".", "TXT", lifetime=6)
        records = list(answers)
        digest = _b64(hashlib.sha256(expected.encode("ascii")).digest()).encode("ascii")
        if len(records) > 64 or not any(hmac.compare_digest(b"".join(record.strings), digest) for record in records):
            raise AcmeError("incorrectResponse", "DNS-01 TXT proof does not match.")
    except dns.exception.DNSException as error:
        raise AcmeError("dns", "DNS-01 TXT proof is missing or resolution timed out.") from error


@acme_protocol.post("/challenge/<challenge_id>")
def challenge(challenge_id):
    account_record, payload, jwk = _authenticated()
    db = _db()
    record = db.execute("SELECT * FROM acme_challenges WHERE id=?", (challenge_id,)).fetchone()
    if not record:
        raise AcmeError("unauthorized", "Challenge not found for this account.", 403)
    auth, order_record = _authorization(account_record, record["authorization_id"])
    if payload is None:
        return jsonify(_challenge_json(record))
    if payload != {}:
        raise AcmeError("malformed", "A challenge response must be an empty JSON object.")
    config = configuration()
    if not config["http01" if record["type"] == "http-01" else "dns01"]:
        raise AcmeError("unauthorized", "This challenge type has been disabled by the administrator.", 403)
    if record["status"] != "pending" or auth["status"] != "pending" or order_record["status"] != "pending":
        return jsonify(_challenge_json(record))
    if not _VALIDATORS.acquire(blocking=False):
        raise AcmeError("rateLimited", "Challenge validation is busy. Retry later.", 429)
    try:
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute("UPDATE acme_challenges SET status='processing',started=? WHERE id=? AND status='pending'", (_stamp(), challenge_id)).rowcount
        db.commit()
        if not changed:
            return jsonify(_challenge_json(db.execute("SELECT * FROM acme_challenges WHERE id=?", (challenge_id,)).fetchone()))
        failure = None
        try:
            expected = record["token"] + "." + _thumb(jwk)
            if record["type"] == "http-01":
                validate_http01(auth["identifier"], record["token"], expected, allow_private=configuration()["allow_private"])
            else:
                validate_dns01(auth["identifier"], expected)
        except AcmeError as error:
            failure = {"type": PROBLEM + error.kind, "detail": error.detail}
        db.execute("BEGIN IMMEDIATE")
        status = "invalid" if failure else "valid"
        db.execute("UPDATE acme_challenges SET status=?,validated=?,error=? WHERE id=?", (status, None if failure else _stamp(), _json(failure) if failure else None, challenge_id))
        db.execute("UPDATE acme_authorizations SET status=? WHERE id=? AND status='pending'", (status, auth["id"]))
        if failure:
            db.execute("UPDATE acme_orders SET status='invalid',error=? WHERE id=? AND status='pending'", (_json(failure), order_record["id"]))
        elif not db.execute("SELECT 1 FROM acme_authorizations WHERE order_id=? AND status!='valid'", (order_record["id"],)).fetchone():
            db.execute("UPDATE acme_orders SET status='ready' WHERE id=? AND status='pending'", (order_record["id"],))
        audit_event("acme.challenge." + status, "acme_order", order_record["id"], "account=" + account_record["id"] + "; type=" + record["type"])
        db.commit()
        response = jsonify(_challenge_json(db.execute("SELECT * FROM acme_challenges WHERE id=?", (challenge_id,)).fetchone()))
        response.headers.add("Link", '<' + _url("authorization", authorization_id=auth["id"]) + '>;rel="up"')
        return response
    finally:
        _VALIDATORS.release()


def _issuance_policy(account_record, names, csr_pem=None, common_name=None):
    from certificate_profiles import validate_issuance
    if not account_record["profile_id"]:
        raise ValueError("Assign an ACME-enabled certificate template to this account.")
    template = _db().execute("SELECT default_validity_days,max_validity_days FROM certificate_templates WHERE id=?", (account_record["profile_id"],)).fetchone()
    if template is None:
        raise ValueError("The account's certificate template is unavailable.")
    days = min(configuration()["validity_days"], int(get_setting("max_leaf_days", 397)), template["default_validity_days"], template["max_validity_days"])
    policy = validate_issuance(_db(), account_record["profile_id"], common_name=common_name or sorted(names, key=lambda item: (len(item), item))[0],
        subject_alt_names=", ".join("DNS:" + name for name in sorted(names)), validity_days=days, role="acme", profile="server", csr_pem=csr_pem)
    if policy["profile"] != "server":
        raise ValueError("The ACME template must permit TLS server authentication only.")
    return policy


@acme_protocol.post("/order/<order_id>/finalize")
def finalize(order_id):
    account_record, payload, _ = _authenticated()
    if not payload or not isinstance(payload.get("csr"), str):
        raise AcmeError("badCSR", "Provide a base64url DER CSR.")
    from app import crl_distribution_url, issuer_certificate_url
    from key_storage import authority_signing_key
    from pki import issue_end_entity_certificate
    db = _db()
    order_record = _order(account_record, order_id)
    try:
        der = _unb64(payload["csr"], 90000)
        csr = x509.load_der_x509_csr(der)
        if not csr.is_signature_valid:
            raise ValueError("The CSR signature is invalid.")
        names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if any(not isinstance(name, x509.DNSName) for name in names):
            raise ValueError("CSR SANs must contain only the ordered DNS identifiers.")
        requested = {_dns_name(name.value) for name in names}
        ordered = {item["value"] for item in _loads(order_record["identifiers"])}
        if requested != ordered or len(names) != len(requested):
            raise ValueError("CSR SANs must exactly match the order, with no duplicate identifiers.")
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) > 1 or common_names and _dns_name(common_names[0].value) not in ordered:
            raise ValueError("The CSR common name must be one of the ordered identifiers.")
        common_name = common_names[0].value if common_names else sorted(ordered, key=lambda item: (len(item), item))[0]
        fingerprint = hashlib.sha256(der).hexdigest()
        db.execute("BEGIN IMMEDIATE")
        current_account = db.execute("SELECT * FROM acme_accounts WHERE id=?", (account_record["id"],)).fetchone()
        order_record = db.execute("SELECT * FROM acme_orders WHERE id=?", (order_id,)).fetchone()
        if current_account["status"] != "valid" or any(not _domain_allowed(name, _loads(current_account["domains"])) for name in ordered):
            raise AcmeError("unauthorized", "The account no longer permits this order.", 403)
        if order_record["status"] == "valid":
            if order_record["csr_sha256"] != fingerprint:
                raise AcmeError("badCSR", "This order was finalized using a different CSR.")
            db.rollback()
            return _resource(_order_json(order_record), location=_url("order", order_id=order_id))
        if order_record["status"] != "ready" or order_record["expires"] <= _stamp():
            raise AcmeError("orderNotReady", "All authorizations must be valid before finalization.", 403)
        if db.execute("SELECT 1 FROM acme_authorizations WHERE order_id=? AND status!='valid'", (order_id,)).fetchone():
            raise AcmeError("orderNotReady", "An authorization is no longer valid.", 403)
        authority = _issuer(order_record["authority_id"])
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        policy = _issuance_policy(current_account, ordered, csr_pem=csr_pem, common_name=common_name)
        pem, _, serial, start, end = issue_end_entity_certificate(common_name, authority["certificate_pem"], authority_signing_key(authority), policy["validity_days"],
            policy["subject_alt_names"], profile=policy["profile"], csr_pem=csr_pem,
            crl_url=crl_distribution_url(authority["id"]), aia_url=issuer_certificate_url(authority["id"]), minimum_rsa_bits=3072)
        certificate_record = db.execute("INSERT INTO certificates (common_name,authority_id,subject_alt_names,certificate_pem,private_key_pem,serial_number,not_before,not_after,profile,template_id,template_snapshot) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (common_name, authority["id"], ", ".join(sorted(ordered)), pem, "", serial, start, end, policy["profile"], policy["template_id"], policy["template_snapshot"]))
        chain = pem + authority["certificate_pem"] + authority["parent_chain_pem"]
        db.execute("UPDATE acme_orders SET status='valid',certificate_id=?,csr_sha256=?,chain_pem=? WHERE id=?", (certificate_record.lastrowid, fingerprint, chain, order_id))
        audit_event("certificate.issued", "certificate", str(certificate_record.lastrowid), "source=ACME; account=" + account_record["id"] + "; order=" + order_id)
        db.commit()
    except AcmeError:
        db.rollback()
        raise
    except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension, UnsupportedAlgorithm) as error:
        db.rollback()
        raise AcmeError("badCSR", str(error)) from error
    return _resource(_order_json(_order(account_record, order_id)), location=_url("order", order_id=order_id))


@acme_protocol.post("/certificate/<order_id>")
def certificate(order_id):
    account_record, payload, _ = _authenticated()
    _post_as_get(payload)
    record = _order(account_record, order_id)
    if record["status"] != "valid" or not record["chain_pem"]:
        raise AcmeError("orderNotReady", "This order has no issued certificate.", 403)
    return Response(record["chain_pem"], mimetype="application/pem-certificate-chain")


@acme_protocol.post("/revoke-cert")
def revoke_certificate():
    account_record, payload, jwk = _authenticated(allow_jwk=True)
    from publication import queue_publication
    try:
        supplied = x509.load_der_x509_certificate(_unb64(payload["certificate"]))
        reason = payload.get("reason", 0)
        reasons = {0: "unspecified", 1: "key_compromise", 3: "affiliation_changed", 4: "superseded", 5: "cessation_of_operation"}
        if type(reason) is not int or reason not in reasons:
            raise AcmeError("badRevocationReason", "Supported revocation reason codes: 0, 1, 3, 4, 5.")
        db = _db()
        db.execute("BEGIN IMMEDIATE")
        record = db.execute("SELECT c.*,o.account_id FROM certificates c JOIN acme_orders o ON o.certificate_id=c.id WHERE c.serial_number=?", (hex(supplied.serial_number),)).fetchone()
        if not record or x509.load_pem_x509_certificate(record["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER) != supplied.public_bytes(serialization.Encoding.DER):
            raise AcmeError("unauthorized", "This certificate was not issued through ACME here.", 403)
        if account_record:
            allowed = account_record["id"] == record["account_id"]
        else:
            allowed = _jwk_key(jwk)[1].public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == supplied.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if not allowed:
            raise AcmeError("unauthorized", "Use the issuing account or certificate private key.", 403)
        if account_record is None:
            _verify_audit()
        if record["revoked_at"]:
            raise AcmeError("alreadyRevoked", "This certificate is already revoked.")
        db.execute("UPDATE certificates SET revoked_at=?,revocation_reason=? WHERE id=?", (_now().isoformat(), reasons[reason], record["id"]))
        db.execute("UPDATE crls SET next_update=NULL WHERE authority_id=?", (record["authority_id"],))
        queue_publication(db)
        audit_event("certificate.revoked", "certificate", str(record["id"]), "source=ACME; reason=" + reasons[reason])
        db.commit()
        return Response(status=200)
    except AcmeError:
        raise
    except (ValueError, TypeError, KeyError, UnsupportedAlgorithm) as error:
        raise AcmeError("malformed", "Invalid certificate revocation request.") from error


@acme_protocol.post("/key-change")
def key_change():
    account_record, payload, old_jwk = _authenticated()
    try:
        header = _loads(_unb64(payload["protected"], 16000))
        if "jwk" not in header or "kid" in header:
            raise ValueError
        _, raw, new_jwk = _verify(payload, header["jwk"], nonce=False)
        content = _loads(raw)
        if not isinstance(content, dict) or content.get("account") != _url("account", account_id=account_record["id"]) or _jwk_key(content.get("oldKey"))[0] != old_jwk or new_jwk == old_jwk:
            raise ValueError
        db = _db()
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute("UPDATE acme_accounts SET jwk=?,thumbprint=? WHERE id=? AND jwk=? AND status='valid'", (_json(new_jwk), _thumb(new_jwk), account_record["id"], account_record["jwk"]))
        if not changed.rowcount:
            raise AcmeError("unauthorized", "The account key or account status changed. Retry with the current account key.", 403)
        audit_event("acme.account.key_changed", "acme_account", account_record["id"])
        db.commit()
        return jsonify(_account_json(db.execute("SELECT * FROM acme_accounts WHERE id=?", (account_record["id"],)).fetchone()))
    except AcmeError:
        raise
    except (ValueError, TypeError, KeyError, sqlite3.IntegrityError) as error:
        raise AcmeError("malformed", "Invalid account key rollover or key already in use.") from error


@acme_admin.route("/settings/acme", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    from app import encrypt_private_key
    from certificate_profiles import available_templates
    db = _db()
    credential = None
    if request.method == "POST":
        try:
            action = request.form.get("action")
            db.execute("BEGIN IMMEDIATE")
            if action == "save":
                config = {key: request.form.get(key) == "on" for key in ("enabled", "allow_private", "http01", "dns01")}
                config["validity_days"] = int(request.form.get("validity_days", "90"))
                if not 1 <= config["validity_days"] <= int(get_setting("max_leaf_days", 397)):
                    raise ValueError("Select a lifetime within the configured certificate limit.")
                if config["enabled"]:
                    _base()
                    _issuer()
                    if not config["http01"] and not config["dns01"]:
                        raise ValueError("Enable at least one challenge type.")
                db.execute("INSERT INTO settings VALUES ('acme_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (_json(config),))
                audit_event("acme.settings.updated", "settings", "acme")
                flash("ACME settings saved.", "success")
            elif action == "create_eab":
                label = request.form.get("label", "").strip()
                domains = list(dict.fromkeys(_dns_name(value.strip()) for value in request.form.get("domains", "").replace(",", "\n").splitlines() if value.strip()))
                if not label or len(label) > 100 or not 1 <= len(domains) <= 50:
                    raise ValueError("Provide a label and 1 to 50 permitted domains.")
                profile_id = request.form.get("profile_id", "")
                if not any(str(item["id"]) == profile_id and item["profile"] == "server" for item in available_templates(db, role="acme")):
                    raise ValueError("Select an enabled server certificate template with the ACME role.")
                credential = {"id": secrets.token_urlsafe(18), "secret": secrets.token_urlsafe(32)}
                db.execute("INSERT INTO acme_eab (id,label,secret,domains,profile_id,created_at,expires) VALUES (?,?,?,?,?,?,?)",
                           (credential["id"], label, encrypt_private_key(credential["secret"]), _json(domains), profile_id, _stamp(), _stamp(_now() + timedelta(days=7))))
                audit_event("acme.eab.created", "acme_eab", credential["id"], label + "; domains=" + ",".join(domains))
            elif action == "revoke_eab":
                db.execute("UPDATE acme_eab SET revoked=1,secret='' WHERE id=? AND used_at IS NULL", (request.form.get("id", ""),))
                audit_event("acme.eab.revoked", "acme_eab", request.form.get("id", ""))
                flash("Enrollment credential revoked.", "success")
            elif action == "deactivate_account":
                db.execute("UPDATE acme_accounts SET status='deactivated' WHERE id=?", (request.form.get("id", ""),))
                audit_event("acme.account.deactivated", "acme_account", request.form.get("id", ""))
                flash("ACME account deactivated. Already issued certificates retain their status.", "success")
            else:
                raise ValueError("Unknown ACME action.")
            db.commit()
            if credential is None:
                return redirect(url_for("acme_admin.settings"))
        except (ValueError, TypeError) as error:
            db.rollback()
            credential = None
            flash(str(error), "error")
    try:
        directory_url = _url("directory")
    except AcmeError:
        directory_url = "Configure the public HTTPS base URL first."
    return render_template("acme_settings.html", title="ACME enrollment", config=configuration(), directory_url=directory_url, credential=credential,
        templates=[item for item in available_templates(db, role="acme") if item["profile"] == "server"],
        credentials=db.execute("SELECT id,label,domains,created_at,expires,used_at,revoked FROM acme_eab ORDER BY created_at DESC LIMIT 100").fetchall(),
        accounts=db.execute("SELECT id,status,contacts,domains,created_at FROM acme_accounts ORDER BY created_at DESC LIMIT 100").fetchall(),
        recent_orders=db.execute("SELECT id,status,identifiers,created_at FROM acme_orders ORDER BY created_at DESC LIMIT 50").fetchall())
