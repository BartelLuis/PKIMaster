# Encrypted backups and recovery

Administrators can use **Backup and recovery** to download a complete local-state
archive. A fresh authenticator code is required for every export. Choose a unique
passphrase of 20–256 characters and store it separately from the archive. It cannot
be reset. Protect both: together they disclose the installation's keys and accounts.

The archive includes a consistent SQLite snapshot, the independent encryption
secret, the authenticated audit history and seal, users and MFA recovery state,
certificate and CA keys, provider credentials, all application settings, the HTTPS
identity, and managed SoftHSM token files. The SQLite writer lock coordinates the
snapshot with changes to managed keys and web TLS files; the publication lock keeps
the publication worker out of that snapshot. Ordinary CA-key download policy is
unchanged: this separate operation is an encrypted disaster-recovery export.

Each newly created archive signs its encrypted bytes using a local Ed25519
provenance key. The backup page displays the signer's SHA-256 public-key
fingerprint. Record that fingerprint through a separate trusted channel before
moving the backup to another host. Recovery verifies the signature and pin
before attempting decryption or staging files; an archive cannot establish its
own trust fingerprint. The private provenance key is held in the instance
directory with restricted file permissions and is deliberately excluded from
the snapshot. A restored host therefore starts a new signing identity. Keep
the old public fingerprint to verify old archives.

Backups created before signed provenance was introduced are unsigned. For those
archives, recovery requires an independently recorded archive SHA-256. This
compatibility mode does not provide signer authentication.

External PKCS#11/HSM and Azure private keys stay in their providers. Their references
and credentials are backed up, but provider availability, installed modules and
access on the replacement host remain necessary. Remote published files, package
binaries and system-journal logs are not part of local application state. Archives
are limited to 128 MiB and 10,000 state files. Browser backup requires the standard
`pkimaster.sqlite` database inside the instance directory.

## Recover on a replacement host

1. Install the same or a newer compatible PKIMaster version on a fresh host.
2. Stop the original installation. Keep only one active copy of a CA identity.
3. Connect to the replacement host through localhost, for example an SSH tunnel to
   `https://127.0.0.1:8443`. On initial setup, select **Restore an existing
   installation** before creating an administrator.
4. Upload the `.pkibackup` file, supply its passphrase and confirm that the source
   installation is stopped. Authentication, archive bounds, database consistency,
   foreign keys, the audit chain, encrypted credentials and the web TLS identity are
   checked before installation. Invalid archives leave the fresh installation usable.
5. The packaged HTTPS supervisor stops its web workers and waits for publication and
   monitoring workers to finish. It installs the staged state and restarts. A journal
   makes interrupted installation resumable on the next service start.
6. Sign in with a restored account and its existing authenticator or an unused
   recovery code. The destination's HTTPS address and port stay unchanged. The CA
   identity and application settings are restored. Old sessions and pending factor
   changes are invalidated. The recovered HTTPS certificate may require reconnecting
   your browser.
7. Check the public base URL, CRL/AIA reachability, publication destinations,
   monitoring delivery, clock synchronization and access to external key providers.
   Managed SoftHSM paths are rewritten to the destination's instance directory.
   Generate a fresh set of MFA recovery codes after signing in: restored usage state
   reflects the backup time, so codes consumed after that snapshot may be usable again.

Recovery cannot overwrite an installation that already has an administrator or CA.
Keep the original archive until a test certificate can be issued and its chain and
revocation data can be verified on the replacement host. Test recovery periodically.

## Custom WSGI deployments

The packaged supervisor performs installation automatically. A custom WSGI process
must never replace state while another web or background worker is using it. After
the browser has staged a restore, stop **all** application, publication and monitoring
processes. Run this with the same service account and virtual environment, replacing
the instance path with your deployment's actual state directory:

```python
from pathlib import Path
from backup import apply_pending_restore

apply_pending_restore(Path("/var/lib/pkimaster"))
```

Restart the deployment only after that call succeeds. The development launcher also
applies a staged restore on restart. A pending recovery blocks browser requests and
worker startup until the state has been installed. Storage or validation failures
leave the journal in place; preserve the state and resolve the reported problem
before restarting. Never remove the marker to force a partially installed state live.

## Format and cryptography

The encrypted payload format 1 uses a random 16-byte salt and 12-byte nonce, scrypt with fixed
`N=2^17, r=8, p=1` (128 MiB), and AES-256-GCM. The version, salt and nonce are
authenticated alongside the ciphertext. Passwords and archive contents are never
written to audit events or logs. The decrypted archive has an authenticated manifest
with SHA-256 hashes and only bounded, uncompressed ZIP members; path traversal,
duplicate filenames and symbolic links are rejected. Temporary plaintext snapshots
and staged recovery files stay inside the service's private state directory with
restricted permissions and are removed after completion.

The implementation uses the cryptography project's
[authenticated encryption API](https://cryptography.io/en/latest/hazmat/primitives/aead/)
and [scrypt KDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt).
