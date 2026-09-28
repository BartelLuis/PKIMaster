# External publication over SFTP

Administrators configure the **CRL & AIA publication** page in the PKIMaster web
interface. SFTP transfers the public
CA certificate, certificate chain, and signed CRL to an existing publication
server. The publication server must already expose those files to certificate
clients over HTTP or HTTPS; PKIMaster does not configure its web server or infer
public URLs from an SFTP filesystem path.

For example, an SFTP account might write to `/public/issuing-ca`, while the web
server exposes these URLs:

| Artifact | Remote filename | Example public URL |
| --- | --- | --- |
| Signed CRL | `ca.crl` | `https://pki.example/issuing-ca/ca.crl` |
| Issuer certificate, DER | `ca.cer` | `https://pki.example/issuing-ca/ca.cer` |
| Certificate chain, PEM | `chain.pem` | `https://pki.example/issuing-ca/chain.pem` |

Enter the actual public CRL and issuer-certificate URLs separately in the web
configuration. Certificate clients use those URLs, not the SFTP connection.
Serve the CRL as `application/pkix-crl` and the DER issuer certificate as
`application/pkix-cert`. SFTP itself does not set HTTP response headers.

Public retrieval URLs can be saved while automatic SFTP publication is disabled;
this mode requires no SFTP credentials. It supports publication managed outside
PKIMaster. When the URL fields are blank, PKIMaster uses the public base URL from
Settings with `/crl/<authority-id>.crl` and `/aia/<authority-id>.cer`. Those local
endpoints provide public CRL and DER CA-certificate downloads without sign-in.
With neither an explicit URL nor a public base URL, the corresponding discovery
extension is omitted.

URLs are embedded when a leaf or subordinate CA certificate is issued. Changing
settings does not rewrite existing certificates, so keep their original URLs
available for their remaining lifetimes. Enabling SFTP requires distinct public
CRL and issuer-certificate URLs. The AIA entry identifies the issuer certificate;
it does not configure an OCSP service.

## Replacing a revoked local CA

After revoking the local CA, initialize its replacement from the CA console.
The retired CA, its issued certificates, keys, and CRLs remain stored, and its
existing `/crl/<authority-id>.crl` and `/aia/<authority-id>.cer` endpoints remain
available. The replacement receives a different authority ID and its own CRL.

Initialization disables automatic SFTP publication, clears the public URL and
remote directory fields, and resets the publication status for the new CA.
Configure different CRL and AIA URLs and a different SFTP directory or server
before enabling publication for the replacement. The most recently configured
locations of each retired CA are reserved to prevent replacement artifacts from
overwriting them. A replacement can only be initialized after any active upload
has finished; retry initialization if publication is in progress.

Keep every URL embedded in previously issued certificates available, including
earlier locations used before changing publication settings. Existing remote
files are left in place. After replacement, the automatic worker only publishes
the new CA; arrange continued delivery and renewal of the retired CA's CRL where
needed, using its retained local CRL endpoint and signing provider. Changing the
CA or its publication settings does not update trust stores or existing
certificates on relying parties.

Permanently deleting a revoked CA also removes its local CRL and AIA artifacts;
its ID-based public URLs then return HTTP 404. Its saved publication target is
removed. If the deleted CA owns the current publication configuration, deletion
disables uploads, clears its URLs, destination and upload credentials, and resets
the publication status. Deleting an older archive preserves the replacement CA's
configuration and pending publication work. The worker never falls back to a
different archived CA after deletion. Files already uploaded to SFTP remain on
the remote server and must be managed there. Deletion is blocked while an upload
is running; retry after it finishes.

## Connection fields

| Field | Meaning |
| --- | --- |
| Host | DNS name or IPv4/IPv6 address, without a scheme, username, or port. |
| Port | SSH port, normally `22`. |
| Directory | Existing absolute POSIX path within the account's SFTP view. A chrooted account uses the path inside its chroot. |
| Username | Dedicated publication account. |
| Host-key SHA-256 fingerprint | Required OpenSSH-style `SHA256:…` fingerprint, obtained from the server administrator through a trusted channel. |
| Authentication | Select **SSH private key** or **Password**. Saving a different method clears the other method's credential. |
| SSH private key | Optional PEM, PKCS#8, or OpenSSH key supplied through the web interface. |
| SSH key passphrase | Passphrase for the supplied encrypted private key, when applicable. |
| Password | Account password when private-key authentication is not configured. |

The host key is verified before any account authentication is attempted. A
changed or mismatched fingerprint stops publication. Coordinate legitimate
host-key rotation with the server administrator and update the pin through the
web interface. There is no trust-on-first-use behavior.

Credentials are stored encrypted and never redisplayed. Leaving a credential
field blank retains its saved value when the destination is unchanged. Re-enter
credentials when changing the host, port, username, or pinned host key; saved
credentials are not carried to a different destination. A newly supplied private
key uses the passphrase supplied with that key, so an unencrypted replacement
can leave the passphrase blank.

The selected authentication method is explicit. Switching to password clears
the saved private key and its passphrase; switching to a private key clears the
saved password. A rejected key does not silently fall back to a password. Keys
are parsed in memory. The transport does not consult local SSH
key files, `known_hosts`, SSH agents, proxy commands, or interactive prompts.
The application supplies the explicitly configured credentials to the transport.

Supported keys are RSA with at least 2048 bits, NIST P-256/P-384/P-521 ECDSA,
and Ed25519. SHA-1 RSA signatures and legacy SHA-1 Diffie–Hellman exchanges are
disabled. These SSH interoperability rules are separate from the CA signing
policy and do not establish BSI compliance.

Python installations require Paramiko 5.0.0 or newer within the 5.x series.
This release removes RSA/SHA-1 signing and verification, addressing
[PYSEC-2026-2858 / CVE-2026-44405](https://github.com/advisories/GHSA-r374-rxx8-8654).
Debian 13 uses its distribution-maintained Paramiko package. PKIMaster also
checks the actual server signature algorithm against the negotiated host-key
algorithm on each SFTP connection, including rekeying, and rejects RSA/SHA-1
before authentication. This protects the publication connection on the older
Debian library without changing Paramiko globally or suppressing audit findings.

## Automatic publication, status, and retries

The APT package installs a system timer that checks pending publication every
minute. CA creation or activation, revocation, CRL policy changes, and publication
settings changes queue work in the same database transaction as the change.
Pending work survives restarts. The **Publish now / retry** button requests an
immediate attempt and resets the retry delay.

Only one attempt can hold the installation's publication lock. Target settings
cannot be changed during an active upload. Certificate operations can continue
while SFTP transfers run; a revocation recorded during an upload remains queued
for a subsequent attempt. The worker records success only for the artifact
generation it actually uploaded.

Failures retain pending work and retry after 1, 2, 4, 8, 16, and 32 minutes,
then at most hourly. The page displays the queue state, most recently published
CRL number, last successful upload, current local CRL expiry, sanitized error,
and next retry time. Attempts, failures, successful publications, and newly
generated CRLs are audited. Disabling automatic publication stops worker uploads
and does not require working credentials.

Even without new revocations, an enabled worker renews a CRL when its remaining
lifetime reaches the smaller of one day or half its signed validity interval.
CRL expiry never exceeds the CA certificate's expiry. A CRL already capped at
that expiry is not repeatedly reissued with the same expiry. The worker cannot
extend an expired CA or operate an unavailable signing provider; publication
status and actual public retrieval should be monitored accordingly.

Use **Monitoring & alerts** for independent public HTTP(S) CRL retrieval checks,
expiry warnings and email/webhook delivery. The monitoring timer runs every five
minutes; it checks signatures, CRL numbers and known revocations rather than
assuming a successful SFTP upload proves fresh public data. See [monitoring
configuration](MONITORING.md). Relying-party revocation enforcement and external
monitoring of the CA host still require deployment configuration.

## Required SFTP behavior and permissions

The server must implement the OpenSSH `posix-rename@openssh.com` extension,
including atomic replacement of an existing file. Standard SFTP rename alone
is insufficient. PKIMaster checks replacement support using two uniquely named
temporary probe files before staging any published artifact.

The publication account needs permission to inspect the configured directory,
create and write files, inspect file sizes, set public file permissions, replace
files with POSIX rename, and remove its temporary files. It does not need a shell
or permission to create directories. Use a dedicated directory and restrict
other writers. New published files receive mode `0644`, so the external web
server can read these public artifacts.

Each attempt proceeds as follows:

1. Verify the pinned SSH host key and authenticate.
2. Check that the destination is an existing directory and probe atomic replacement.
3. Upload every artifact to an exclusively created `.pkimaster-<random>.tmp`
   file in that directory and verify its complete byte count.
4. Atomically replace `chain.pem`, then `ca.cer`, then `ca.crl`.
5. Report success only after every requested replacement succeeds.

The current public file is never deleted as a rename fallback. A failed or
interrupted upload leaves the existing CRL in place. An unsupported atomic
rename operation fails closed. After a connection loss, uniquely named temporary
files may remain; they contain only public artifacts and can be removed by the
publication server administrator after confirming that no publication is active.

Replacement is atomic **per file**, not across all three files. If an error
occurs during promotion, the certificate or chain may already be updated while
the old CRL remains. A retry must publish the complete artifact snapshot again;
the fixed filenames make that operation idempotent. SFTP success confirms the
remote write, not public HTTP reachability or cache freshness.

The transport limits each artifact to 64 MiB, uses a 5-second TCP connection
timeout, and applies 10-second SSH and SFTP I/O timeouts. A 60-second watchdog
closes an active publication connection. Hostname resolution additionally follows
the host operating system's DNS timeout behavior. Network errors returned to
the application omit remote exception text and credentials.

## Transport verification

Run `python -m unittest discover -s tests -p test_publication_transports.py`.
The tests start a real isolated Paramiko SFTP server on loopback. They cover
password and encrypted private-key authentication, host-pin rejection before
credentials, unsupported atomic replacement, interrupted uploads, and retry
after partial promotion. They do not contact an external publication server.

Protocol references: [Paramiko host-key and authentication behavior](https://docs.paramiko.org/en/stable/api/client.html),
[Paramiko POSIX rename semantics](https://docs.paramiko.org/en/stable/api/sftp.html#paramiko.sftp_client.SFTPClient.posix_rename),
and [Paramiko in-memory private-key loading](https://docs.paramiko.org/en/stable/api/keys.html#paramiko.pkey.PKey.from_private_key).
