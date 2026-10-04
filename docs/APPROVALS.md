# Four-eyes approvals

Four-eyes approval is optional and disabled by default. An administrator can
enable it under **Settings**. Enabling the control itself requires approval by
a second administrator and requires at least two active administrator accounts
with MFA enrolled.

When enabled, the following browser actions are submitted as pending requests:

- CA initialization and activation
- End-entity issuance and revocation, local or subordinate CA revocation, and
  deletion of a revoked CA; parent-CRL import
- Service, certificate-template, identity-provider, CA-key-storage,
  publication, automation, ACME and SCEP/EST configuration; manual publication
  and automation runs
- User access changes and complete backup export

Operators may request certificate issuance or revocation; an administrator
must approve it. The requester cannot approve or reject their own request.
Approval is bound to the original route, path parameters, form values and file
fingerprints. Uploaded files must be supplied again by the reviewer and must
match the originals. Passwords, provider credentials, PINs, backup passphrases
and TOTP codes are never retained in an approval request. A keyed HMAC
commitment binds the request to each submitted secret without storing the
secret itself; the reviewer must re-enter the same value. A TOTP code is
transient reauthentication, so the reviewer supplies their own current code.
Transfer other secrets to the reviewer through a separate protected channel.

The reviewer submits the original action through its normal endpoint. Existing
authorization, validation, certificate-template policy, audit-integrity checks
and operation-specific controls run again. An approval is recorded before the
operation is attempted; it does not guarantee success if current state or
policy has changed. A failed operation must be submitted again. Approval
requests and decisions are included in the authenticated audit history.

The control requires distinct administrator accounts, not merely separate
browser sessions. Protect administrator identities and their MFA recovery
material accordingly. Four-eyes approval is an application workflow; it does
not prove that two distinct humans are operating those accounts.
