# Automation

Administrators configure these jobs under **Automation**. Saving settings and a
manual run require a fresh authenticator code. The packaged worker checks due
jobs regularly; a failed job retries with backoff. Monitoring reports failures,
overdue runs and recovery through the existing notification channel.

## Parent CRLs

For the current activated subordinate CA, configure one HTTP(S) CRL URL for each
parent, in immediate-issuer-to-root order. Each download is limited to 4 MiB,
bounded by time, and uses the monitoring transport's DNS/address checks and TLS
verification. Redirects and compressed responses are rejected.

Only fresh, signed, full direct CRLs with CRL numbers are accepted. The existing
parent validation policy is applied to the complete bundle. Older timestamps,
lower numbers and changed bytes for the same number are refused, including when
the cached CRL has expired. Expired cached status continues to block signing;
network failures never turn unknown status into good status. Verified revocation
of this CA or an ancestor permanently disables the local CA. Configuration is
bound to its CA ID; creating a replacement CA requires reviewing the URLs.

## Scheduled recovery backups

1. Generate and download a recovery key in the browser, or provide a dedicated
   RSA-3072/RSA-4096 public key (exponent 65537).
2. Verify that the private `.pem` download exists and save it securely outside
   the CA host. It is downloaded without a passphrase. Never paste that private
   recovery key into the SFTP credential field.
3. Configure the dedicated SFTP account, absolute destination directory and
   independently verified OpenSSH SHA-256 host fingerprint.
4. Enable backups, choose interval and retention, confirm possession of the
   recovery key and save with a fresh TOTP code. Run once and test restoration
   on a fresh, isolated host before relying on the schedule.

The browser generates its recovery key using Web Crypto. It never sends the
private key to the CA. The CA stores only the public recipient key and its
SHA-256 fingerprint. Scheduled archives use a version-2 envelope: a fresh
AES-256-GCM key encrypts the existing consistent state snapshot;
RSA-OAEP with SHA-256 encrypts the AES key. The envelope header is authenticated
as GCM additional data. This protects archive integrity during decryption, but
does **not** authenticate its producer: anyone holding the public recipient key
can encrypt a new archive, including a self-consistent database and new internal
audit secrets. Internal database/audit validation cannot establish that such an
archive came from your original installation.

Only restore archives from a trusted source. The Automation page displays the
last delivered archive's SHA-256; retain it independently of the SFTP storage,
along with the public recovery-key fingerprint. Recovery accepts an optional
independently recorded archive SHA-256 and rejects a mismatch **before**
decryption. A checksum delivered beside an untrusted archive does not establish
its origin; the retained value must come from your trusted original installation
or an independently protected record. The recipient fingerprint identifies the
decryption key, not the archive's producer.

The private recovery key is only supplied to a fresh
host during an explicit restore. The original passphrase-encrypted version-1
manual backup and TOTP workflow remain available and compatible.

On the fresh host's recovery page, select the scheduled `.pkibackup` and matching
private recovery key. For an externally generated encrypted private key, enter
its passphrase. For a manual version-1 archive, enter the archive passphrase.
Recovery retains the existing database, audit, key, host-isolation and
single-active-installation checks. External HSM key material cannot be recreated
from a local software backup and still needs its provider's recovery process.

Changing the recipient does not re-encrypt old backups. Keep every old private
recovery key until its backups are no longer needed. Losing the matching private
key makes those backups unrecoverable.

Transfers use host-key pinning before credentials are sent, modern SSH signature
algorithms, bounded connection/channel deadlines, private remote file modes and
read-back SHA-256 checks. No SSH agent or ambient client key is consulted.
Secrets are encrypted in the existing installation settings store. Changing the
host, account, fingerprint or authentication method requires a fresh credential.

Only filenames matching this installation's strict backup prefix, timestamp and
SHA-256 pattern are eligible for retention. Cleanup runs after verified delivery
and never removes unrelated files, other installations' backups or audit files.
The newest configured number of managed backups is retained. The installation
state and each archive retain the existing 128 MiB limit.

## External audit checkpoints

The audit job authenticates the complete local audit chain and its checkpoint in
one SQLite read snapshot before preparing its JSON archive. Each immutable name
contains the installation ID, last event ID and chain-head hash. Files include
all event fields, hashes and MACs plus the checkpoint, allowing an independent
hash-chain review and authentication using the original installation secret from
a recovery backup. That secret is not included in the audit JSON.

Retries verify an already present file rather than overwrite it. The delivery
cursor advances only after a verified upload. Existing external checkpoints are
compared with the corresponding local chain hashes; evidence of rollback or a
fork stops delivery and raises a finding. Audit archives are private operational
data; they are not encrypted beyond SFTP transport and remote access controls.
Each complete audit archive has a 128 MiB limit; exceeding it is reported as a
failed job, never as a successful partial export.

PKIMaster never deletes audit archives. Its immutable-name policy does not turn
an ordinary SFTP account into a write-once storage device. Configure independent
server-side retention, snapshots or WORM controls if storage-level immutability
is required. Protect the external storage administratively from the CA host.

The automation worker holds the same operating-system publication lock as manual
backups, CRL publication and restoration. Database write transactions protect
state changes. Recovery pending on the host pauses the worker. Parent download,
backup and audit failures are independent: a failed job does not prevent the
remaining enabled jobs from being attempted.
