# SCEP and EST enrollment

SCEP and EST are optional features. They are not activated merely by registering
the module: both `enabled` and the selected protocol must be explicitly enabled
in **Settings → SCEP / EST enrollment**. The default is disabled, and disabled
protocol paths return HTTP 503. Configure a public HTTPS base URL and an active
Issuing CA before enabling either service.

## Application integration

The application startup initializes this module and registers its protocol and
admin blueprints. Its access-control hooks exempt the authenticated machine
protocols from browser-session and CSRF checks, include their requests in
audit-integrity protection, and restrict the SCEP/EST settings page to
administrators. No extra initializer call or host allowlist changes are needed.

Configure TLS at the application listener or a trusted TLS-terminating proxy.
EST verifies Flask's `request.is_secure`, so deployments behind a proxy must
configure trusted proxy handling before enabling EST. Do not trust arbitrary
forwarded-protocol headers.

## Credentials and policy

An administrator creates a single-use credential scoped to one protocol, CA,
template, domain suffix set, and maximum certificate lifetime. The secret is
generated from 256 random bits, shown once, and stored only as a SHA-256 hash.
It is consumed atomically on successful enrollment and can be revoked at any
time. EST uses HTTP Basic authentication (`credential-id:secret`); SCEP
credentials are carried as the CSR `challengePassword`. Protect these
credentials as passwords and provision them only over an authenticated,
encrypted management channel. Issuance is audited without recording secrets.

Both protocols verify the CSR signature, require exactly one common name,
enforce RSA keys of at least 3072 bits (or the shared policy's supported EC
curves), reject CA-signing requests, enforce the saved template's profile,
name constraints and validity, and apply the credential's domain scope.
Issued private keys remain with the requester. Request bodies are limited to
256 KiB and enrollments are rate-limited. Replay identifiers and issued CSR
fingerprints are persisted.

## Implemented endpoints and limits

* SCEP: `GET /scep?operation=GetCACaps`,
  `GET /scep?operation=GetCACert`, and `POST /scep?operation=PKIOperation`.
  Capabilities advertise AES, SHA-256 and POST PKIOperation. PKCSReq CMS
  signature verification, RSA key-transport/AES-CBC decryption and encrypted,
  signed CertRep responses are implemented.
* EST: `GET /.well-known/est/cacerts` and
  `POST /.well-known/est/simpleenroll`. The response is CMS/PKCS#7 certs-only.

Interoperability is intentionally bounded: SCEP currently accepts one CMS
signer, one RSA key-transport recipient, SHA-256/384/512 signed attributes,
RSA PKCS#1 v1.5 or ECDSA/SHA-256 CMS signatures, and AES-CBC/3DES-CBC encrypted
requests. SCEP response signing and its encryption/decryption CA key require a
software RSA Issuing CA; EST can use the application's configured signing-key
provider. SCEP GET-based PKIOperation is accepted for compatibility, but clients
should use POST due to URL-size and log-exposure risks. Only PKCSReq is
implemented; renewal, GetNextCACert, unsupported key-transport modes, and
protocol-specific failure CertRep messages are not. Validate interoperability
with the intended client software before production rollout.

Focused tests exercise the feature through the normal application startup
registration as well as authenticated protocol enrollment flows.
