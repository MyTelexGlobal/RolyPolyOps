# Product security

[Русский](../ru/security.md)

## 1 Protected assets

Protected assets include service data, backup history, encryption keys, provider credentials, DNS rights, and primary-role authority. The application, host service, privileged helper, control service, repository, and owner account are distinct trust boundaries.

## 2 Required controls

| Threat | Required protection |
|---|---|
| Two writable primaries | Single authority, source fencing, and safe rejoin |
| Replayed mutation | Idempotency key, revision, expiry, and reconciliation |
| Compromised application host | No permanent ability to delete all retained history |
| Stolen host identity | Per-host certificates, revocation, scoped commands |
| Plan substitution | Confirmation bound to plan hash and revision |
| Arbitrary command execution | Trusted service packages and restricted privileged actions |
| Restore side effects | Isolated credentials and outbound restrictions |

Secrets are referenced separately, encrypted at rest where stored, and excluded from logs and reports. External connections are authenticated and encrypted.

## 3 Limits and reporting

These are security requirements, not a statement of completed implementation or audit. Full administrative compromise remains a serious residual risk. Provider fencing, retention protection, and package trust must be checked for each supported deployment.

Report sensitive findings through the repository's private vulnerability-reporting channel when available. Never include credentials, real backup archives, or customer data in public issues. If a private channel is unavailable, request a contact without disclosing sensitive details.
