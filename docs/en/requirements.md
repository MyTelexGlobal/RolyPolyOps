# Requirements and limits

[Русский](../ru/requirements.md)

The numbered requirements below describe the wider product target, not implemented guarantees. The current Compose workflow uses two enrolled hosts, one selected repository per service and an operator-confirmed move with a reachable source. It does not configure replication, automatic failover, cluster authority or protection against deletion by a compromised host. See the [current service guide](compose-services.md).

## 1 Functional requirements

| ID | Requirement |
|---|---|
| FR-01 | Scheduled encrypted backups and retained history |
| FR-02 | Independent repositories with separate transfer and integrity state |
| FR-03 | A recovery point linking database, files, configuration, and application identity |
| FR-04 | Full-service recovery onto a selected compatible target |
| FR-05 | Scheduled isolated restore drills with useful application checks |
| FR-06 | Single-server, assisted-pair, automatic-pair, and cluster policies |
| FR-07 | Source-fenced pair switching and safe standby rejoin |
| FR-08 | Cluster authority through Patroni and etcd |
| FR-09 | Explicit profile transitions without silent policy weakening |
| FR-10 | Clear service state, plans, operation outcomes, and required decisions |

## 2 Safety and operating requirements

SR-01: one authorized writable primary. SR-02: no silent weakening of data-loss policy. SR-03: an application host cannot erase all backup history. SR-04: secrets stay out of source, logs, and reports. SR-05: restore drills cannot trigger real external actions.

OR-01: recover without the source or control service. OR-02: interrupted operations remain observable and resumable safely. OR-03: permitted local backups survive loss of control. OR-04: measure actual data loss and recovery time.

## 3 Verification scenarios

| ID | Scenario |
|---|---|
| T01 | Restore a database and matching attachment versions |
| T02 | Reject corrupt data or missing WAL |
| T03 | Recover after losing both source and control service |
| T04 | Partition a pair without creating two writable primaries |
| T05 | Lose each individual cluster site and observe role and data behavior |
| T06 | Retry, lose replies, and restart during mutations |
| T07 | Recover retained history after source deletion or compromise |
| T08 | Run a useful isolated application check without real external effects |
| T09 | Interrupt profile transitions without unsafe authority overlap |
| T10 | Return the old primary as a standby |
| T11 | Lose a repository and expose backlog and capacity risk |
| T12 | Recover an older application/package version |

The complete T01-T12 acceptance suite has not been executed. The bundled demo exercises a limited database/file recovery case and a separate application check; this does not certify these scenarios for arbitrary services. Schema checks do not count as T01-T12.
