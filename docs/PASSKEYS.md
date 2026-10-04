# Passkeys

Passkeys are an optional, phishing-resistant alternative to the TOTP challenge
after the normal password or identity-provider sign-in. Mandatory MFA remains
in place; a passkey does not replace password authentication, and TOTP/recovery
codes remain available as fallback.

Users with a verified session can open **Account security → Passkeys** to
register or remove credentials. Registration and removal require a fresh TOTP
code. WebAuthn registration requires user verification and creates a discoverable
credential; the server stores only the credential public key, identifier,
authenticator counter, and a user-supplied label. Private key material remains
with the authenticator. An account can register up to 20 passkeys.

The relying-party ID and exact allowed origin are derived from the configured
HTTPS **Public base URL**. Passkey ceremonies reject non-HTTPS requests,
origin mismatches, expired challenges, and assertions without user presence and
verification. Deployments behind a TLS proxy must configure Flask's trusted
proxy handling; do not trust arbitrary forwarded-protocol headers. The
browser's origin must exactly match the configured public origin, including a
non-default port.

After entering their account password, a user with a registered passkey can
choose **Use a passkey** instead of entering a TOTP code. The passkey operation
is protected by the existing CSRF, audit-integrity, login-throttle, session
version and role controls. Removing every passkey never disables the
authenticator fallback.

Passkey credentials and counters are stored in the existing users database and
are included in encrypted, signed state backups. After restoring an installation,
verify its HTTPS origin and ensure browsers use the restored configured public
URL before attempting passkey sign-in.
