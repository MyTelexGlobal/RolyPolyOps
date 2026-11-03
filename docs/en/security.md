# Product security

[Русский](../ru/security.md)

## 1 Protected assets

Protected assets include service data, backup history, encryption keys, provider credentials, DNS rights, and primary-role authority. The application, host service, privileged helper, control service, repository, and owner account are distinct trust boundaries.

## 2 Current secret storage

The 0.2.0 browser seals storage credentials and the repository encryption password separately to each host. The controller receives sealed envelopes and public repository metadata. Each enrolled host keeps the decrypted credentials, repository password and its own identity in root-only persistent local files. The storage worker receives the credentials needed for each operation. Resolved application configuration and staged data can also contain plaintext secrets on the host before repository encryption. These files rely on host access controls; the product does not encrypt all local state at rest.

Protect the host state, staging directories and their backups as secret-bearing material. The downloaded recovery kit is plaintext and contains repository access and encryption credentials. Keep it in protected offline storage or a password manager. It does not contain the control catalog or administrator password. Repository encryption does not protect data from root on an enrolled host.

## 3 Required controls

| Threat | Required protection |
|---|---|
| Two writable primaries | Single authority, source fencing, and safe rejoin |
| Replayed mutation | Idempotency key, revision, expiry, and reconciliation |
| Compromised application host | No permanent ability to delete all retained history |
| Stolen host identity | Per-host certificates, revocation, scoped commands |
| Plan substitution | Confirmation bound to plan hash and revision |
| Arbitrary command execution | Trusted service packages and restricted privileged actions |
| Restore side effects | Isolated credentials and outbound restrictions |

The wider target profiles require separate secret references, encryption at rest and exclusion from logs and reports. External connections require authentication and encryption. These requirements do not replace the current local-storage limits above.

## 4 Limits and reporting

These are security requirements, not a statement of completed implementation or audit. Full administrative compromise remains a serious residual risk. Provider fencing, retention protection, and package trust must be checked for each supported deployment.

Report sensitive findings through the repository's private vulnerability-reporting channel when available. Never include credentials, real backup archives, or customer data in public issues. If a private channel is unavailable, request a contact without disclosing sensitive details.
