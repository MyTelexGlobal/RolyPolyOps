# Recovery and operating behavior

[Русский](../ru/recovery.md)

## 1 Current availability

The 0.2.0 preview includes an installable control panel and host services for supported Compose projects. Follow the [installation guide](../../control/README.md), then the [Compose service guide](compose-services.md) for backup, exact isolated restore and controlled move.

A controlled move requires the source to be reachable and stopped before target activation. Public routing and DNS are configured separately. Automatic failover from an offline source, zero downtime and automatic controller replacement are unavailable. The previous source data remains stopped and retained.

The sequences below describe operating requirements for the wider target profiles. Database replication, Patroni/etcd and automatic rejoin are planned integrations; their behavior must not be inferred from the current Compose workflow.

## 2 Recovery sequence

1. Select a complete recovery point, repository, and compatible isolated target.
2. Check the full recovery chain, capacity, application image, package version, and keys.
3. Restore database, matching files, and configuration into new locations.
4. Start the application with external side effects disabled and run useful checks.
5. Record actual data age, duration, checks, and limits.
6. Treat replacement of a live service as a separate authorized transition.

## 3 Failover and rejoin

A pair must establish source fencing before promoting its standby. A cluster follows its authorized quorum and replica rules. Routing changes follow application readiness. DNS cache expiry and existing connections prevent a universal instant-switch guarantee.

The repaired old primary remains non-writable until its role and data are reconciled. It returns as a standby. New writes on a replacement primary prevent blindly returning to an older database.

## 4 Loss of dependencies

| Failure | Required behavior |
|---|---|
| Control service unavailable | Continue permitted local backups; stop new unsafe mutations |
| Host service unreachable | Mark observations unknown; do not infer power-off |
| Standby lag or missing files | Show data boundary; select a complete point if necessary |
| No etcd quorum | Do not create competing primary authority |
| Repository outage | Expose backlog and capacity risk; preserve required chains |
| Missing recovery key | Stop with an explicit cause |

Keep emergency keys and recovery instructions outside the source and control catalog.
