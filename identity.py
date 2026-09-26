"""Web-configured first factors. External identities never assign local roles."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import ssl
import time
from urllib.parse import quote_plus, urlencode, urlsplit

import jwt
import ldap3
import requests
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, session, url_for
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from werkzeug.security import check_password_hash

from enterprise import _db, _start_session, audit_event, require_roles

identity = Blueprint("identity", __name__)
DEFAULTS = {
    "mode": "local", "allow_local_breakglass": True, "revision": "initial",
    "oidc_issuer": "", "oidc_client_id": "", "oidc_client_secret": "", "oidc_redirect_uri": "",
    "oidc_authorization_origin": "",
    "ldap_url": "", "ldap_base_dn": "", "ldap_bind_dn": "", "ldap_bind_password": "",
    "ldap_user_attribute": "uid", "ldap_ca_pem": "",
}
SECRET_FIELDS = {"oidc_client_secret", "ldap_bind_password"}
ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
FLOW_COOKIE = "__Host-pkimaster_oidc"
CALLBACK_PATH = "/auth/oidc/callback"


def init_identity(connection):
    columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    for name, definition in (("auth_source", "TEXT NOT NULL DEFAULT 'local'"),
                             ("external_issuer", "TEXT NOT NULL DEFAULT ''"), ("external_subject", "TEXT NOT NULL DEFAULT ''")):
        if name not in columns:
            connection.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS external_identity_unique ON users(auth_source, external_issuer, external_subject) WHERE auth_source != 'local'")
    connection.execute("CREATE TABLE IF NOT EXISTS identity_settings (id INTEGER PRIMARY KEY CHECK(id = 1), payload TEXT NOT NULL)")
    connection.execute("CREATE TABLE IF NOT EXISTS oidc_flows (state_hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL)")


def _encrypt(value: str) -> str:
    from app import private_key_cipher
    return private_key_cipher().encrypt(("pkimaster-identity-v1:" + value).encode()).decode()


def _decrypt(value: str) -> str:
    from app import private_key_cipher
    raw = private_key_cipher().decrypt(value.encode()).decode()
    if not raw.startswith("pkimaster-identity-v1:"):
        raise ValueError("Invalid identity secret envelope")
    return raw.removeprefix("pkimaster-identity-v1:")


def config(*, secrets_visible=False) -> dict:
    row = _db().execute("SELECT payload FROM identity_settings WHERE id = 1").fetchone()
    value = DEFAULTS | (json.loads(row[0]) if row else {})
    for key in SECRET_FIELDS:
        value[key + "_configured"] = bool(value[key])
        value[key] = _decrypt(value[key]) if value[key] and secrets_visible else ""
    return value


def public_config() -> dict:
    value = config()
    return {key: value[key] for key in ("mode", "allow_local_breakglass")}


def _authorization_origin(endpoint):
    parsed = urlsplit(_https_url(endpoint, "OIDC authorization endpoint"))
    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname)
        hostname = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if len(hostname) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in hostname.rstrip(".").split(".")):
            raise ValueError("The authorization endpoint must use a valid DNS name or IP address.")
    return "https://" + hostname + (f":{parsed.port}" if parsed.port and parsed.port != 443 else "")


def form_action_origin():
    """Use only the origin accepted at settings save; never fetch discovery on login."""
    value = config()
    if value["mode"] != "oidc" or not value["oidc_authorization_origin"]:
        return ""
    return _authorization_origin(value["oidc_authorization_origin"])


def user_allowed(user, value=None) -> bool:
    value = value or config()
    source = user["auth_source"]
    if source == "local":
        return value["mode"] == "local" or (value["allow_local_breakglass"] and user["role"] == "admin")
    provider = value.get("oidc_issuer" if source == "oidc" else "ldap_url", "")
    return source == value["mode"] and user["external_issuer"] == provider


def validate_binding(source, issuer, subject):
    if source not in {"local", "ldap", "oidc"}:
        raise ValueError("Select local, LDAP, or OpenID Connect authentication.")
    if source == "local":
        return "", ""
    issuer = _https_url(issuer, "OIDC issuer") if source == "oidc" else _ldap_url(issuer)
    if not subject or len(subject) > 1024 or any(ord(char) < 32 for char in subject):
        raise ValueError("Provide the exact external subject (OIDC sub or LDAP distinguished name).")
    return issuer, subject


def _https_url(value, label):
    if not isinstance(value, str) or not value or len(value) > 2048 or not value.isascii() or any(ord(c) <= 32 for c in value) or "\\" in value:
        raise ValueError(f"{label} must be an absolute ASCII HTTPS URL.")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError(f"{label} must use HTTPS without credentials, query parameters, or fragments.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError(f"{label} has an invalid port.")
    return value


def _ldap_url(value):
    if not isinstance(value, str) or not value.isascii() or any(ord(c) <= 32 for c in value) or "\\" in value:
        raise ValueError("Enter an ASCII LDAP server URL.")
    parsed = urlsplit(value)
    if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Use ldaps://host:636 or ldap://host:389 (mandatory StartTLS).")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("LDAP port is invalid.")
    return value.rstrip("/")


def _reserve_attempt(buckets):
    """Reserve attempts before network operations; parallel workers cannot evade limits."""
    db, now = _db(), int(time.time())
    db.execute("BEGIN IMMEDIATE")
    db.execute("DELETE FROM login_throttles WHERE window_started < ? AND blocked_until < ?", (now - 86400, now))
    entries = [db.execute("SELECT * FROM login_throttles WHERE bucket = ?", (bucket,)).fetchone() for bucket in buckets]
    if any(entry and entry["blocked_until"] > now for entry in entries):
        db.commit()
        return False
    for bucket, entry in zip(buckets, entries):
        current = entry and now - entry["window_started"] < 900
        attempts = entry["attempts"] + 1 if current else 1
        limit = 10 if bucket.startswith("user:") else 40
        db.execute("INSERT INTO login_throttles VALUES (?, ?, ?, ?) ON CONFLICT(bucket) DO UPDATE SET attempts=excluded.attempts, window_started=excluded.window_started, blocked_until=excluded.blocked_until",
                   (bucket, attempts, entry["window_started"] if current else now, now + 900 if attempts >= limit else 0))
    db.commit()
    return True


def _throttled():
    return Response("Too many login attempts. Try again in 15 minutes.", 429, {"Retry-After": "900"})


def password_login(username, password):
    from flask import current_app
    buckets = ("user:" + username.casefold(), "ip:" + (request.remote_addr or "unknown"))
    if not _reserve_attempt(buckets):
        return _throttled()
    db, value = _db(), config(secrets_visible=True)
    user = db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    expected = user["password_hash"] if user and user["auth_source"] == "local" else current_app.extensions["pkimaster_dummy_password_hash"]
    valid = len(password) <= 256 and check_password_hash(expected, password)
    if user and user["active"] and user_allowed(user, value) and user["auth_source"] == "ldap" and password and len(password) <= 256:
        try:
            valid = ldap_authenticate(value, user, username, password)
        except (LDAPException, OSError, ValueError):
            valid = False
    elif not user or user["auth_source"] != "local":
        valid = False
    db.execute("BEGIN IMMEDIATE")
    fresh = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone() if user else None
    if (valid and fresh and fresh["active"] and fresh["session_version"] == user["session_version"]
            and config()["revision"] == value["revision"] and user_allowed(fresh, value)):
        db.execute("DELETE FROM login_throttles WHERE bucket = ?", (buckets[0],))
        _start_session(fresh)
        audit_event("session.password_verified", "user", fresh["id"], "provider=" + fresh["auth_source"])
        db.commit()
        return redirect(url_for("mfa.challenge" if fresh["mfa_secret"] else "mfa.enroll"))
    audit_event("session.login_failed", "user", "", "Invalid credentials")
    db.commit()
    flash("Invalid username or password.")
    return render_template("login.html", title="Sign in"), 401


def ldap_authenticate(value, user, username, password):
    parsed = urlsplit(value["ldap_url"])
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=value["ldap_ca_pem"] or None, sni=parsed.hostname)
    server = ldap3.Server(parsed.hostname, port=parsed.port or (636 if parsed.scheme == "ldaps" else 389),
                          use_ssl=parsed.scheme == "ldaps", tls=tls, connect_timeout=5, get_info=ldap3.NONE)

    def connect(dn, credential):
        connection = ldap3.Connection(server, user=dn, password=credential, authentication=ldap3.SIMPLE,
                                      auto_referrals=False, receive_timeout=5, raise_exceptions=True)
        try:
            connection.open()
            if parsed.scheme == "ldap" and not connection.start_tls():
                raise ValueError("LDAP StartTLS failed")
            if not connection.bind():
                raise ValueError("LDAP bind failed")
            return connection
        except Exception:
            connection.unbind()
            raise

    search = connect(value["ldap_bind_dn"], value["ldap_bind_password"])
    try:
        query = f"({value['ldap_user_attribute']}={escape_filter_chars(username)})"
        if not search.search(value["ldap_base_dn"], query, search_scope=ldap3.SUBTREE, attributes=[value["ldap_user_attribute"]], size_limit=2, time_limit=5):
            return False
        if len(search.entries) != 1 or search.entries[0].entry_dn != user["external_subject"]:
            return False
        distinguished_name = search.entries[0].entry_dn
    finally:
        search.unbind()
    bound = connect(distinguished_name, password)
    bound.unbind()
    return True


def _request_json(method, url, **kwargs):
    _https_url(url, "Identity provider endpoint")
    with requests.Session() as client:
        client.trust_env = False  # No ambient proxies, netrc credentials, or TLS overrides.
        with client.request(method, url, timeout=(5, 10), allow_redirects=False, stream=True, **kwargs) as response:
            if response.status_code != 200:
                raise ValueError("Identity provider did not return a successful response.")
            body = bytearray()
            for chunk in response.iter_content(16384):
                body.extend(chunk)
                if len(body) > 1024 * 1024:
                    raise ValueError("Identity provider response is too large.")
            result = json.loads(body, object_pairs_hook=_unique_object)
            if not isinstance(result, dict):
                raise ValueError("Identity provider returned invalid JSON.")
            return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _metadata(value):
    metadata = _request_json("GET", value["oidc_issuer"].rstrip("/") + "/.well-known/openid-configuration")
    if metadata.get("issuer") != value["oidc_issuer"]:
        raise ValueError("OIDC discovery issuer does not exactly match the configured issuer.")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        _https_url(metadata.get(field), "OIDC " + field)
    if "code" not in metadata.get("response_types_supported", ["code"]):
        raise ValueError("The provider must support the authorization code flow.")
    if "S256" not in metadata.get("code_challenge_methods_supported", ["S256"]):
        raise ValueError("The provider must support PKCE S256.")
    if "client_secret_basic" not in metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"]):
        raise ValueError("The provider must support client_secret_basic authentication.")
    return metadata


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


@identity.post("/auth/oidc/start")
def oidc_start():
    value = config()
    if value["mode"] != "oidc":
        abort(404)
    if not _reserve_attempt(("oidc-ip:" + (request.remote_addr or "unknown"),)):
        return _throttled()
    try:
        metadata = _metadata(value)
        if _authorization_origin(metadata["authorization_endpoint"]) != value["oidc_authorization_origin"]:
            raise ValueError("The provider authorization origin changed; save authentication settings again.")
    except (requests.RequestException, ValueError):
        return Response("The identity provider is unavailable or its configuration is invalid.", 503)
    state, browser, verifier, nonce = (secrets.token_urlsafe(32) for _ in range(4))
    payload = {"verifier": verifier, "nonce": nonce, "revision": value["revision"], "metadata": metadata}
    now, db = int(time.time()), _db()
    db.execute("BEGIN IMMEDIATE")
    db.execute("DELETE FROM oidc_flows WHERE created_at < ?", (now - 600,))
    if config()["revision"] != value["revision"]:
        db.rollback()
        return Response("Authentication configuration changed. Start sign-in again.", 400)
    db.execute("INSERT INTO oidc_flows VALUES (?, ?, ?, ?)", (_digest(state), _digest(browser), _encrypt(json.dumps(payload)), now))
    db.commit()
    parameters = {"response_type": "code", "scope": "openid", "client_id": value["oidc_client_id"],
                  "redirect_uri": value["oidc_redirect_uri"], "state": state, "nonce": nonce,
                  "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(),
                  "code_challenge_method": "S256", "response_mode": "query"}
    response = redirect(metadata["authorization_endpoint"] + "?" + urlencode(parameters))
    response.set_cookie(FLOW_COOKIE, browser, max_age=600, secure=True, httponly=True, samesite="Lax", path="/")
    return response


def _verify_id_token(token, jwks, value, flow, created_at):
    encoded = token.get("id_token")
    if not isinstance(encoded, str) or len(encoded) > 65536:
        raise ValueError("Missing or oversized ID token")
    if encoded.count(".") != 2:
        raise ValueError("Use a signed, unencrypted ID token")
    # Eliminate ambiguous duplicate header/claim fields before library verification.
    for section in encoded.split(".")[:2]:
        json.loads(jwt.utils.base64url_decode(section), object_pairs_hook=_unique_object)
    header = jwt.get_unverified_header(encoded)
    if header.get("alg") not in ALGORITHMS or any(name in header for name in ("jwk", "jku", "x5u", "x5c", "crit")):
        raise ValueError("Unsupported token signature header")
    keys = [key for key in jwks.get("keys", []) if isinstance(key, dict)
            and key.get("kty") in {"RSA", "EC"} and key.get("use", "sig") == "sig"
            and "verify" in key.get("key_ops", ["verify"])
            and key.get("alg", header["alg"]) == header["alg"]
            and (not header.get("kid") or key.get("kid") == header["kid"])]
    if len(keys) != 1:
        raise ValueError("No unique trusted signing key")
    key = jwt.PyJWK.from_dict(keys[0], algorithm=header["alg"]).key
    if header["alg"].startswith(("RS", "PS")):
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError("OIDC RSA signing keys must contain at least 2048 bits")
    elif not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}[header["alg"]]:
        raise ValueError("OIDC curve does not match the signature algorithm")
    # The header has already passed the fixed asymmetric allowlist and trusted-key checks.
    claims = jwt.decode(encoded, key, algorithms=[header["alg"]], issuer=value["oidc_issuer"], audience=value["oidc_client_id"],
                        options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]}, leeway=60)
    if claims["iss"] != value["oidc_issuer"]:
        raise ValueError("Invalid issuer")
    if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 1024:
        raise ValueError("Invalid subject")
    if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], flow["nonce"]):
        raise ValueError("Invalid nonce")
    for name in ("exp", "iat"):
        if type(claims[name]) not in {int, float} or not math.isfinite(claims[name]):
            raise ValueError("Invalid token time")
    if claims["iat"] < created_at - 60:
        raise ValueError("ID token predates this sign-in")
    if (isinstance(claims["aud"], list) and len(claims["aud"]) > 1) or "azp" in claims:
        if claims.get("azp") != value["oidc_client_id"]:
            raise ValueError("Invalid authorized party")
    if "at_hash" in claims:
        access = token.get("access_token")
        if not isinstance(access, str) or not isinstance(claims["at_hash"], str):
            raise ValueError("Invalid access token hash")
        digest = hashlib.new("sha" + header["alg"][-3:], access.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest[:len(digest) // 2]).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, claims["at_hash"]):
            raise ValueError("Invalid access token hash")
    return claims


@identity.get(CALLBACK_PATH)
def oidc_callback():
    value, db, now = config(secrets_visible=True), _db(), int(time.time())
    state, browser = request.args.get("state", ""), request.cookies.get(FLOW_COOKIE, "")
    if value["mode"] != "oidc" or not 20 <= len(state) <= 128 or not 20 <= len(browser) <= 128:
        return Response("Invalid or expired sign-in. Start again.", 400)
    db.execute("BEGIN IMMEDIATE")
    flow = db.execute("SELECT * FROM oidc_flows WHERE state_hash = ?", (_digest(state),)).fetchone()
    if not flow or not hmac.compare_digest(flow["browser_hash"], _digest(browser)) or now - flow["created_at"] > 600:
        db.rollback()
        return Response("Invalid or expired sign-in. Start again.", 400)
    db.execute("DELETE FROM oidc_flows WHERE state_hash = ?", (_digest(state),))
    db.commit()  # Single use even if the network call or token verification fails.
    try:
        payload = json.loads(_decrypt(flow["payload"]))
        if payload["revision"] != value["revision"] or request.base_url != value["oidc_redirect_uri"]:
            raise ValueError("Authentication configuration or callback changed")
        if len(request.args.getlist("code")) != 1 or len(request.args.getlist("state")) != 1 or not request.args["code"] or len(request.args["code"]) > 4096 or "error" in request.args:
            raise ValueError("Invalid authorization response")
        if "iss" in request.args and (len(request.args.getlist("iss")) != 1 or request.args["iss"] != value["oidc_issuer"]):
            raise ValueError("Invalid authorization response issuer")
        metadata = payload["metadata"]
        token = _request_json("POST", metadata["token_endpoint"],
                              auth=(quote_plus(value["oidc_client_id"]), quote_plus(value["oidc_client_secret"])),
                              data={"grant_type": "authorization_code", "code": request.args["code"],
                                    "redirect_uri": value["oidc_redirect_uri"], "code_verifier": payload["verifier"]})
        claims = _verify_id_token(token, _request_json("GET", metadata["jwks_uri"]), value, payload, flow["created_at"])
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT * FROM users WHERE auth_source = 'oidc' AND external_issuer = ? AND external_subject = ? AND active = 1",
                          (value["oidc_issuer"], claims["sub"])).fetchone()
        if not user or config()["revision"] != value["revision"]:
            raise ValueError("Identity not provisioned or configuration changed")
        _start_session(user)
        audit_event("session.oidc_verified", "user", user["id"])
        db.commit()
        # Commit a same-origin document before continuing. A cross-site provider
        # redirect chain does not carry the newly issued SameSite=Strict session.
        response = Response(render_template("oidc_complete.html", title="Continue sign-in",
                                            factor_url=url_for("mfa.challenge" if user["mfa_secret"] else "mfa.enroll")))
    except (requests.RequestException, jwt.PyJWTError, ValueError, TypeError, KeyError, UnicodeError):
        db.rollback()
        audit_event("session.oidc_failed", "user", "", "Provider response or provisioned identity rejected")
        db.commit()
        response = Response("Sign-in failed. Check the provider and the provisioned identity, then start again.", 401)
    response.delete_cookie(FLOW_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    return response


@identity.route("/settings/identity", methods=["GET", "POST"])
@require_roles("admin")
def settings():
    value = config()
    if request.method == "POST":
        try:
            updated = {key: request.form.get(key, "").strip() for key in DEFAULTS if key not in SECRET_FIELDS | {"revision", "allow_local_breakglass", "oidc_authorization_origin"}}
            updated["oidc_authorization_origin"] = ""
            if updated["mode"] not in {"local", "ldap", "oidc"}:
                raise ValueError("Select a supported authentication mode.")
            updated["allow_local_breakglass"] = request.form.get("allow_local_breakglass") == "on"
            row = _db().execute("SELECT payload FROM identity_settings WHERE id = 1").fetchone()
            old = json.loads(row[0]) if row else {}
            for key in SECRET_FIELDS:
                secret = request.form.get(key, "")
                if len(secret) > 4096:
                    raise ValueError("Provider secrets must contain at most 4096 characters.")
                updated[key] = _encrypt(secret) if secret else old.get(key, "")
            if any(len(item) > 65536 for item in updated.values() if isinstance(item, str)):
                raise ValueError("An authentication setting is too long.")
            if updated["mode"] == "oidc":
                updated["oidc_issuer"] = _https_url(updated["oidc_issuer"], "OIDC issuer")
                _https_url(updated["oidc_redirect_uri"], "OIDC callback")
                if urlsplit(updated["oidc_redirect_uri"]).path != CALLBACK_PATH:
                    raise ValueError("OIDC callback must end with " + CALLBACK_PATH)
                if not updated["oidc_client_id"] or len(updated["oidc_client_id"]) > 256 or not updated["oidc_client_secret"]:
                    raise ValueError("Provide the OIDC client ID and client secret.")
                metadata = _metadata(updated)
                updated["oidc_authorization_origin"] = _authorization_origin(metadata["authorization_endpoint"])
            if updated["mode"] == "ldap":
                updated["ldap_url"] = _ldap_url(updated["ldap_url"])
                if not all(updated[key] for key in ("ldap_base_dn", "ldap_bind_dn", "ldap_bind_password")):
                    raise ValueError("Provide the LDAP search base, service bind DN, and service bind password.")
                if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]{0,63}", updated["ldap_user_attribute"]):
                    raise ValueError("Use a single LDAP username attribute, such as uid or sAMAccountName.")
                if updated["ldap_ca_pem"]:
                    ssl.create_default_context(cadata=updated["ldap_ca_pem"])
            db = _db()
            db.execute("BEGIN IMMEDIATE")
            admins = db.execute("SELECT * FROM users WHERE role = 'admin' AND active = 1").fetchall()
            if not any(user_allowed(admin, updated) for admin in admins):
                raise ValueError("Provision an administrator for the selected provider or retain local administrator access before changing authentication.")
            updated["revision"] = secrets.token_urlsafe(24)
            db.execute("INSERT INTO identity_settings VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (json.dumps(updated),))
            db.execute("DELETE FROM oidc_flows")
            db.execute("UPDATE users SET session_version = session_version + 1")
            audit_event("identity.settings_updated", "settings", "", "mode=" + updated["mode"])
            db.commit()
            session.clear()
            flash("Authentication settings saved. Sign in again; existing sessions have been revoked.")
            return redirect(url_for("enterprise.login"))
        except (ValueError, ssl.SSLError, requests.RequestException) as exc:
            _db().rollback()
            flash(str(exc) if isinstance(exc, ValueError) else "The identity provider or its TLS trust configuration could not be validated.")
            return render_template("identity.html", title="Authentication", identity_config=value), 400
    return render_template("identity.html", title="Authentication", identity_config=value)
