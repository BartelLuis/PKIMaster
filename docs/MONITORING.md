# Monitoring and notifications

The Monitoring page is available to all authenticated roles. Administrators configure thresholds, notification delivery and manual checks. The Debian package runs `python -m monitoring_worker` every five minutes. A source installation can schedule the same command against the packaged state directory `/var/lib/pkimaster`.

Checks include non-revoked leaf and issued CA expiry, the current local CA and its parent chain, imported parent CRL validity/expiry, SFTP publication failures, configured TLS deployments and failed/overdue automation jobs. Default certificate thresholds are 30, 14 and 7 days; CRLs warn within 24 hours. Expired objects are errors. A new threshold escalates the existing finding instead of creating duplicates.

## Public CRL retrieval

When public retrieval checks are enabled (the default), the worker retrieves each configured CRL URL, including archived CAs until their expiry. It uses the distribution URLs or the public base URL from Settings. The response must be a complete PEM or DER CRL, signed by the correct CA, currently valid and at least as recent as the locally generated CRL. A matching CRL number must have matching content, and every locally recorded revocation must appear. An upload succeeding does not satisfy this check. A missing URL is reported explicitly.

CRL retrieval requests have socket and download deadlines, a 4 MiB body limit and a soft 45-second network budget per cycle, checked between requests. Deferred checks produce one coverage warning and the next cycle rotates its starting point. A deferred or disabled check preserves existing public findings and their last-checked time; it never announces an unverified recovery. DNS results are pinned for the connection. RFC1918 and IPv6 ULA destinations are supported; loopback, link-local, metadata and reserved addresses are blocked. Redirects, proxy environment variables and ambient credentials are not used. HTTPS uses the operating system's trust store. Install the required internal root certificates in that trust store; certificate verification cannot be disabled.

## Deployed TLS certificates

Open a certificate's details and use **Ownership & deployment → Check the deployed TLS certificate**. An administrator can enable the check, choose the connection hostname/IP and port, and optionally provide a different certificate hostname for SNI and hostname verification. Operators can maintain ownership metadata but cannot configure outbound TLS checks. Checks are disabled by default.

The worker connects using direct TLS, with TLS 1.2 or newer. HTTPS and LDAPS endpoints are examples; SMTP/LDAP STARTTLS and application login checks are not supported. Trust comes from that certificate's stored issuer and parent chain. The peer must present a valid chain and a certificate matching the requested hostname before its fingerprint and expiry are accepted. The operating system's public HTTPS trust store used for CRL retrieval is a separate configuration.

The result appears in the certificate's **Deployed certificate** panel:

| Status | Meaning |
| --- | --- |
| Current | The service presents the expected certificate, with a verified hostname and chain. |
| Mismatch | TLS verification succeeded, but the service presents a different certificate, such as the predecessor after renewal. |
| Revoked | The configured certificate or its issuer is locally marked revoked and needs replacement. |
| Failed | Connection, TLS handshake, chain, hostname or validity verification failed. |

Successful handshakes record the presented subject, SHA-256 fingerprint and expiry. Expiry findings use the configured certificate warning thresholds. Verification failures do not accept untrusted peer details as a successful observation. Public CRL and parent-CRL checks remain separate from this TLS handshake check.

Manual certificate renewal copies the deployment target to the linked successor and disables the predecessor's check. Monitoring then compares the service with the new certificate; it does not deploy that certificate. A concurrent endpoint edit or renewal cannot attach an old network result to the new configuration.

TLS checks use the same destination restrictions as monitoring retrieval: private intranet addresses are supported; loopback, link-local, metadata and reserved addresses are blocked, and the resolved address is pinned for the connection. Up to eight endpoints run per cycle within a soft 40-second budget, separate from public CRL retrieval. The least recently checked endpoints run first. Deferred checks preserve existing findings and observations until a later cycle; they do not announce recovery without a new observation.

## Automation health

The separate automation worker performs configured parent-CRL synchronization, encrypted SFTP backups and external audit delivery. Monitoring reads its durable job results without running those jobs itself. Failures become error findings; a missing successful run or one overdue beyond its interval plus a grace period becomes a warning. The grace period is the larger of five minutes or one quarter of the configured interval. Disabled jobs are not reported as overdue.

Use **Automation** to see the last attempt, last success and error, review a destination or schedule, or request a manual run with a fresh TOTP code. A successful retry clears the matching failure/overdue condition through the usual finding and notification flow. See [automation setup](AUTOMATION.md) for scheduling, backoff, archive verification and retention boundaries.

## Notifications

Notifications default to dashboard only. Select one channel:

- Email: STARTTLS or implicit TLS with verified certificates; optional account authentication and up to ten recipients.
- Webhook: HTTPS JSON POST with an optional Bearer token. Accept with any 2xx response. URL credentials and redirects are forbidden. Each request has an `Idempotency-Key`; each event contains a stable `id` plus `key`, `status` (`active` or `resolved`), `severity`, `title`, `detail` and `changed_at`.

Passwords and tokens are encrypted using the installation's key encryption secret. Blank credential fields preserve the stored value; moving a credential to another destination requires re-entry. Secrets and provider response text never enter the audit log or worker output.

Finding transitions are audited. Unchanged findings are suppressed after successful notification; resolved findings generate recovery notifications. A recurrence generates a new event. Delivery failures leave the updates pending and retry with exponential backoff up to one hour. Up to 100 updates are delivered per cycle. A crash after a receiver accepted a notification but before the database recorded success can cause a duplicate, so webhook receivers should deduplicate by event ID. SMTP messages have a stable Message-ID for the same batch. Conditions that arise and resolve while notifications are disabled do not send obsolete notices when notifications are enabled later. Changing destination sends currently active findings to the new destination.

The monitoring worker does not publish files, generate CRLs, synchronize parent CRLs or create backups. Publication and automation have separate workers and timers. Restores pause monitoring and notification delivery. Monitoring configuration, per-certificate deployment targets and recorded state are part of the encrypted complete backup.
