# ACME certificate automation

PKIMaster exposes an RFC 8555 ACME v2 directory at
`https://your-pki-host/acme/directory`. It issues private-PKI TLS certificates;
clients and relying applications must trust your root CA independently.

## Administrator setup

1. Activate an **Issuing CA**, import its parent chain and current parent CRLs,
   and configure the public HTTPS base URL. Clients must trust the console's
   HTTPS certificate. Keep parent CRLs current for subsequent renewals.
2. Create a certificate template permitting the `acme` role and server
   authentication. Configure permitted DNS suffixes, wildcard policy and
   lifetime limits for the intended clients.
3. Open **ACME**, select the enabled challenge types and certificate lifetime,
   and enable the service. HTTP-01 access to RFC1918/ULA destinations requires
   explicit administrator opt-in; loopback and metadata addresses stay blocked.
4. Generate an enrollment credential bound to that template and permitted DNS
   names. Copy its EAB key ID and HMAC key to the intended client. The secret is
   shown once, encrypted while awaiting enrollment, erased after use, and expires
   after seven days. Each credential enrolls exactly one account.

An exact domain grant authorizes that name. `*.services.example.com` permits
descendants and wildcard identifiers, but does not include the apex
`services.example.com`. Both the account grant and certificate template apply.
Account deactivation stops further authenticated operations; existing
certificates must be revoked separately when appropriate.

## Certbot example

Install Certbot and trust the PKIMaster HTTPS issuer on the client. On the host
whose DNS name is being validated, run:

```sh
certbot certonly --standalone \
  --server https://pki.example.com/acme/directory \
  --eab-kid YOUR_EAB_ID --eab-hmac-key YOUR_EAB_HMAC_KEY \
  --key-type ecdsa --email admin@example.com --agree-tos \
  -d app.example.com
```

Use your client's protected configuration or secret input facilities when
storing enrollment credentials. After account registration, renewals use the
account key; the one-use EAB credential is no longer needed. Keep the client's
account configuration and private keys safe. Use Certbot's normal renewal timer
and a deployment hook appropriate to your web service. RSA certificate keys
must be at least 3072 bits (`--rsa-key-size 3072`); ECDSA P-256/P-384/P-521 are
accepted by the signing policy.

For DNS-01, use a DNS plugin supported by your ACME client. The required TXT
record is `_acme-challenge.<domain>`. Wildcards use DNS-01 only. PKIMaster queries
the server's configured DNS resolvers, so private zones must be visible there.
The server never needs your DNS-provider credentials.

HTTP-01 retrieves the exact `/.well-known/acme-challenge/<token>` resource using
HTTP on port 80. The response must be HTTP 200 with the expected token proof;
redirects and content compression are rejected. Validation resolves and checks
all returned addresses once, pins the outbound connection to an approved IP,
and applies request/body/concurrency deadlines. DNS propagation or HTTP failures
invalidate the order; correct the proof and request a new order.

## Protocol and policy

Implemented resources include directory, nonces, EAB account creation, account
updates/deactivation, account order lists, orders, authorizations, HTTP-01 and
DNS-01 challenges, CSR finalization, certificate chain download, certificate
revocation, and account-key rollover. Resource retrieval uses signed
POST-as-GET. JWS supports RSA SHA-256/384/512 and ECDSA P-256/384/521 signatures.
Replay nonces are single-use and expire after ten minutes. Orders expire after
24 hours. Account/order creation and challenge concurrency are bounded.

Only DNS identifiers are accepted; encode IDNs as ASCII punycode. At least one
ordered DNS name must fit the 64-character common-name limit. CSR SANs must
exactly match the order and any CSR common name must be one of those names.
The CSR signature and key policy are verified; requested CA capabilities and
unsupported extensions cannot escalate the leaf certificate. Custom ACME
notBefore/notAfter requests are rejected in favor of the configured lifetime.
The certificate lifetime is capped by the ACME setting, the template's default
and maximum lifetimes, and the global limit. The current template and CA/ancestor
status are checked again at finalization.
Template restrictions are captured with the issued certificate. PKIMaster
does not receive or generate the client's certificate private key.

Protocol endpoints use JWS authentication and do not accept browser sessions
as authorization. Console settings retain administrator/MFA/CSRF requirements.
Issuance, account and challenge changes append to the existing integrity-checked
audit trail. The existing signing-key providers and CRL publication flow apply.
Normal database backups include ACME state and encrypted unused credentials.

The protocol follows [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html).
This is a private-PKI enrollment service, not a public WebPKI CA.
