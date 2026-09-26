# Identity and key providers

All PKIMaster settings are entered in the authenticated web console. Directory, identity-provider and cloud resources must exist in their respective operating environments. Keep at least two independently assigned administrators for subordinate CA approval. Each server still runs one CA.

## Local, LDAP and OIDC authentication

Local is the default. In **Users**, select the user's authentication source and assign a local role. External users require an exact provider binding; email addresses and identity-provider role claims never grant privileges. Application TOTP remains mandatory with every first factor.

For LDAP, provision a directory service account with search access to the selected base DN. In **Authentication**, enter an `ldaps://` URL or `ldap://` URL with mandatory StartTLS, the base DN, bind DN/password and a username attribute such as `uid` or `sAMAccountName`. Upload/paste the issuing CA bundle if the directory uses private TLS trust. Certificate validation cannot be disabled. Provision users with the same server URL and their exact distinguished name. Searches escape username values, require a unique result and reject referrals; a user bind verifies the password.

For OIDC, register a confidential web application at the provider. Register the exact HTTPS callback `https://your-pki-host/auth/oidc/callback` (including the actual port when needed). Configure issuer URL, client ID and secret in **Authentication**. The provider must publish discovery and JWKS over trusted HTTPS, support authorization code, PKCE S256 and client-secret-basic. Provision users with the exact issuer and stable `sub` claim. Supported signed ID tokens use RSA, RSA-PSS or supported EC algorithms; unsigned and symmetric tokens are rejected. State, browser binding, nonce, issuer, audience, time and single-use flow state are verified. No automatic account linking or provisioning occurs.

Authentication changes invalidate all existing sessions and pending OIDC flows. Keep **Allow local administrator sign-in** enabled if the operating policy permits a protected recovery account. Provision a working administrator for the destination provider before disabling it. Automated MFA reset/recovery is not implemented.

OIDC accepts RSA provider signing keys of at least 2048 bits for interoperability, or P-256/P-384/P-521 with their matching algorithms. This is separate from the stricter CA RSA3072 minimum and requires its own deployment cryptographic assessment. Token validation follows [OpenID Connect ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) using [PyJWT](https://pyjwt.readthedocs.io/en/stable/api.html); LDAP transport uses [ldap3 TLS verification](https://ldap3.readthedocs.io/en/latest/ssltls.html).

## SoftHSM and PKCS#11

APT normally installs `python3-pykcs11` and `softhsm2` as recommended packages. If recommendations were disabled, install those packages with APT. A Python development installation can use `pip install '.[pkcs11]'` on a supported platform. Production PKCS#11 libraries must be root-owned and reside in directories that unprivileged users cannot modify.

Before CA initialization, open **Key storage**, choose PKCS#11, and enter `/usr/lib/softhsm/libsofthsm2.so`, a token label and user PIN. Select **Initialize a new SoftHSM token** and provide a different security-officer PIN of at least eight characters. The officer PIN is not retained. The application generates its private SoftHSM configuration and token storage under the service state directory; no configuration file edits are required. Existing tokens are never reset by this action.

Save, then initialize the server's CA. The application generates a non-exportable RSA4096 signing key in the token and pins token serial, object ID and public-key fingerprint. An existing dedicated token key can instead be attached using its serial and hexadecimal object ID. The selected key must meet the provider's signing policy. Root certificates, subordinate CSRs, certificate issuance and CRLs all use the selected key.

SoftHSM provides a software implementation for testing and integration; it is not a physical or certified HSM. Physical PKCS#11 modules also need vendor middleware and device access compatible with the hardened systemd service. Their qualification, ceremonies, backup and dual control remain operational responsibilities.

## Azure Key Vault and Managed HSM

Create the Azure resource and a dedicated application identity. Assign only required data-plane rights: read key metadata and sign; creating a new key also requires key creation rights. Use a Premium vault for `RSA-HSM`, or an appropriately provisioned Managed HSM. `RSA` is explicitly software-backed. The application supports public Azure vault/managed-HSM endpoints; sovereign clouds and managed-identity authentication are not implemented in this version.

In **Key storage**, select Azure, enter the vault URL, tenant ID, application ID and client secret. Select `RSA-HSM` or `RSA` explicitly and enter a new key name, or attach an exact versioned key URL. New keys are RSA4096. Existing keys must be RSA3072 or stronger, use exponent 65537, be enabled/current/nonexportable and permit signing with only `sign`/`verify` operations. General-purpose keys allowing decrypt/wrap are rejected. Imported PKCS#11 keys must be sensitive and nonextractable. The returned key version and public fingerprint are permanently bound to the CA; automatic Azure key rotation does not replace them. Azure signs the SHA-256 digest using [the PS256 signing API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign?view=rest-keyvault-keys-2025-07-01).

Client secrets and token PINs are stored encrypted. After CA initialization, only credentials can be updated; the application verifies them by signing with the same pinned key. CA private-key download remains forbidden. Provider signatures are verified locally before accepting certificates, CSRs or CRLs. New RSA signatures use SHA-256 RSA-PSS with a 32-byte salt. Provider failure stops the operation, without generating replacement keys.

Treat creation as a key ceremony: a provider may have created a key even if a later database commit fails. Inventory and review an orphaned key before any retry or destruction; the application never destroys provider keys automatically. Never reuse one CA key across multiple active servers.

## Verification boundary

The complete state backup also includes `pkimaster.audit-sealed`, which prevents a database schema downgrade from silently resealing fabricated legacy audit records. Restore the whole state directory, not selected database files. Protected external checkpoints are still necessary to detect replacement with an earlier valid database.

Automated tests exercise a real SoftHSM token on Debian and simulated Azure signing responses with cryptographic verification and failure cases. OIDC tokens are signed and verified in tests, and LDAP transport/binding behavior is tested with controlled connections. Live interoperability with your Azure tenant, directory and OIDC provider must be validated in the deployment environment; this repository does not contain tenant credentials or claim a live cloud assessment.
