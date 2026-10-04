# CA key rollover

PKIMaster retains its one-current-CA-per-server model. Rekey rollovers therefore
use a replacement CA on a separate server; the old and replacement CAs can
operate in parallel during migration without putting two local CA identities
on one host.

## Intermediate and Issuing CA rollover

1. Initialize the replacement Intermediate or Issuing CA on its own server.
   This creates a new CA key and CSR; do not reuse the predecessor's key.
2. On the current parent CA server, submit the CSR under **Request subordinate
   CA signing** and select the existing active subordinate CA as the rollover
   target. The common name and CA role must match, and the new public key must
   differ.
3. A different administrator reviews and approves the CSR. The parent issues a
   replacement certificate and records its link to the predecessor.
4. Transfer the new certificate and parent chain to the replacement server.
   Verify the trusted Root fingerprint through the existing independent
   channel, import fresh parent CRLs, and validate the replacement's issuance
   and publication before migration.
5. Move workloads and relying-party trust/distribution to the replacement.
   Keep the predecessor active and its CRLs available during the overlap.
6. After migration is verified, revoke the predecessor's issued CA certificate
   on its parent and distribute the updated parent CRL. This permanently
   disables the old subordinate after it receives that CRL; clients that are
   disconnected remain unaware until they refresh status.

Old leaf certificates remain associated with the old CA and its CRL. Rollover
does not silently reissue leaf certificates or deploy them to services.

## Root rollover

1. Initialize the new Root CA on a separate server; it gets a new private key
   and a self-signed certificate.
2. Download **Root rollover CSR** from the new Root CA. It is signed by the new
   Root's private key and does not export key material.
3. Submit that CSR on the still-active old Root server with **issue an
   overlapping cross-certificate** selected. A different administrator must
   approve it. The old Root issues a cross-certificate for the new Root key.
4. Download the cross-certificate and its parent chain from the old Root server.
   Verify the new Root certificate and cross-certificate share the same public
   key, then distribute the self-signed and cross-signed forms through the
   deployment's trusted channels.
5. Migrate relying parties and issuing hierarchies to the new Root. Keep the old
   Root's public certificate and CRL available while old paths remain in use.

The cross-certificate is a public chain artifact; it is not imported as the new
Root's local identity. PKIMaster does not automatically update client trust
stores, re-parent subordinate CAs, rotate services, or revoke the old Root.
Those changes require an independently reviewed trust migration. Keep both
trust paths available until relying parties and child hierarchies have been
verified.
