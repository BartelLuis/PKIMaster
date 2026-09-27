# Monitoring and notifications

The Monitoring page is available to all authenticated roles. Administrators configure thresholds, notification delivery and manual checks. The Debian package runs `python -m monitoring_worker` every five minutes. A source installation can schedule the same command against the packaged state directory `/var/lib/pkimaster`.

Checks include non-revoked leaf and issued CA expiry, the current local CA and its parent chain, imported parent CRL validity/expiry, and SFTP publication failures. Default certificate thresholds are 30, 14 and 7 days; CRLs warn within 24 hours. Expired objects are errors. A new threshold escalates the existing finding instead of creating duplicates.

When public retrieval checks are enabled (the default), the worker retrieves each configured CRL URL, including archived CAs until their expiry. It uses the distribution URLs or the public base URL from Settings. The response must be a complete PEM or DER CRL, signed by the correct CA, currently valid and at least as recent as the locally generated CRL. A matching CRL number must have matching content, and every locally recorded revocation must appear. An upload succeeding does not satisfy this check. A missing URL is reported explicitly.

Requests have socket and download deadlines, a 4 MiB body limit and a soft 45-second network budget per cycle, checked between requests. Deferred checks produce one coverage warning and the next cycle rotates its starting point. A deferred or disabled check preserves existing public findings and their last-checked time; it never announces an unverified recovery. DNS results are pinned for the connection. RFC1918 and IPv6 ULA destinations are supported; loopback, link-local, metadata and reserved addresses are blocked. Redirects, proxy environment variables and ambient credentials are not used. HTTPS uses the operating system's trust store. Install the required internal root certificates in that trust store; certificate verification cannot be disabled.

Notifications default to dashboard only. Select one channel:

- Email: STARTTLS or implicit TLS with verified certificates; optional account authentication and up to ten recipients.
- Webhook: HTTPS JSON POST with an optional Bearer token. Accept with any 2xx response. URL credentials and redirects are forbidden. Each request has an `Idempotency-Key`; each event contains a stable `id` plus `key`, `status` (`active` or `resolved`), `severity`, `title`, `detail` and `changed_at`.

Passwords and tokens are encrypted using the installation's key encryption secret. Blank credential fields preserve the stored value; moving a credential to another destination requires re-entry. Secrets and provider response text never enter the audit log or worker output.

Finding transitions are audited. Unchanged findings are suppressed after successful notification; resolved findings generate recovery notifications. A recurrence generates a new event. Delivery failures leave the updates pending and retry with exponential backoff up to one hour. Up to 100 updates are delivered per cycle. A crash after a receiver accepted a notification but before the database recorded success can cause a duplicate, so webhook receivers should deduplicate by event ID. SMTP messages have a stable Message-ID for the same batch. Conditions that arise and resolve while notifications are disabled do not send obsolete notices when notifications are enabled later. Changing destination sends currently active findings to the new destination.

The worker does not publish files or generate CRLs. These remain the responsibility of the existing publication service. Restores pause monitoring and notification delivery. Monitoring configuration and state are part of the encrypted complete backup.
