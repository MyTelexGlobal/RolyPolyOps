# Service-profile reference

[Русский](../ru/service-profiles.md)

## 1 Format

The initial contract is [service-package.schema.json](../../schemas/service-package.schema.json), using JSON Schema Draft 2020-12. Examples are available for [single](../../examples/service-single.json), [assisted pair](../../examples/service-pair.json), and [cluster](../../examples/service-cluster.json).

All examples are marked illustrative_only and use .invalid hosts. The schema validates declared structure and profile policy. It does not connect to a host or prove that fencing, snapshots, quorum, or recovery actually work.

## 2 Fields

| Field | Meaning |
|---|---|
| format_version | Manifest contract version |
| service_id | Stable service identity |
| package | Service-package identity and version |
| profile | single, pair_assisted, pair_automatic, or cluster |
| nodes | Host identities, failure domains, and declared roles |
| database | Engine, replication mode, and strict synchronization policy |
| failover | Automation policy, authority type, and source-fencing requirement |
| backup | Repositories, required copy count, checkpoint interval, and retention |
| targets | Desired RPO and RTO, not measured results |
| restore | Isolated default target and required application check |
| secret_references | Identifiers for separately stored secrets |

No passwords, access tokens, or private keys belong in a manifest.

## 3 Profile constraints

single requires one node, no database replication, no automatic failover, and operator authority. pair_assisted requires two nodes, asynchronous or synchronous replication, no automatic failover, and operator authority. pair_automatic requires two nodes, automatic failover, provider-fence authority, and a reference to a tested fencing policy.

cluster requires at least three declared database nodes, automatic failover, patroni-etcd authority, synchronous replication, and strict synchronization. Every profile requires source fencing before replacement authority and isolated restores with application checks.

## 4 Checks outside the schema

The schema cannot establish real failure-domain independence, measured lag, provider shutdown durability, image availability, key access, or capacity. Unique node IDs, repository independence, required-repository counts relative to available targets, and etcd membership need semantic checks before activation. Passing the schema does not approve an operation.
