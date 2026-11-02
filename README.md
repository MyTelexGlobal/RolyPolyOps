# RolyPolyOps

[Русский](README.ru.md)

**0.2 candidate:** adds the own-Compose service and REST/S3 storage wizard. See the [service guide](docs/en/compose-services.md) for workflow, supported scope and limitations. Live two-host acceptance and release approval remain separate requirements. The demo sections below describe the preserved 0.1 mode.

Service backups, verified recovery, and safe failover between independent hosting providers.

**Status: 0.2 implementation candidate. The existing 0.1 demo remains available.
Own Compose services use the new guided storage/import/backup/restore/schedule flow.
Automatic failover is unavailable; live acceptance is required before release.**

Start with the [control guide](control/README.md). The separately versioned
[recovery lab](demo/README.md) supplies the tested service package and backup mechanism.

## Intended capabilities

- Scheduled encrypted backups with retained history and independent storage locations.
- Recovery of a complete service: database, files, configuration, and application version.
- Restore drills that check an isolated application, beyond archive integrity alone.
- Profiles for one server, a primary/standby pair, and multiple independent sites.
- Explicit data-loss policies and protection against two writable primary databases.
- English and Russian product documentation with matching sections and contract identifiers.

## Profiles

| Profile | Intended behavior |
|---|---|
| Single server | Backups and recovery onto a compatible replacement server |
| Assisted pair | Prepared standby, source fencing, and operator-confirmed switchover |
| Automatic pair | Additional profile requiring tested external fencing and decision authority |
| Cluster | PostgreSQL role management through Patroni and an etcd quorum |

Server count alone does not establish independent failure domains or authorize automatic failover.
Storage replicas do not replace retained backup history.

## Documentation

- [Architecture](docs/en/architecture.md)
- [Requirements and limits](docs/en/requirements.md)
- [Service-profile format](docs/en/service-profiles.md)
- [Recovery and operating behavior](docs/en/recovery.md)
- [Security](docs/en/security.md)
- [Compatibility and current status](docs/en/compatibility.md)
- [Technical references](docs/en/references.md)

The [profile schema](schemas/service-package.schema.json) and [example manifests](examples/README.md)
describe the initial configuration contract. They do not perform operations on servers.

## License

[Apache License 2.0](LICENSE) applies to the original repository materials.
External components retain their own licenses. See [NOTICE](NOTICE).
