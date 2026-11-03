# RolyPolyOps

[Русский](README.ru.md)

**0.2 preview:** connect a supported Compose service and REST/S3 repository through the wizard, create an encrypted backup and restore it on another host. Both storage routes have been exercised on two Linux amd64 Docker hosts. See the [service guide](docs/en/compose-services.md) for the supported model and limits. The bundled demo remains available.

Encrypted service backups, tested recovery and operator-confirmed moves between hosting providers.

**Status: 0.2 preview for compatible Linux Docker hosts.
Guided storage connection, service import, backup, isolated recovery and scheduling are available.
The wizard uses two enrolled hosts and one selected repository per service.
Automatic failover, DNS switching and storage replication remain unimplemented.**

Start with the [control guide](control/README.md). The separately versioned
[recovery lab](demo/README.md) supplies the tested service package and backup mechanism.

## Intended capabilities

- Scheduled encrypted backups with retained history and independent storage locations.
- Recovery of a complete service: database, files, configuration, and application version.
- Restore drills that check an isolated application, beyond archive integrity alone.
- Profiles for one server, a primary/standby pair, and multiple independent sites.
- Explicit data-loss policies and protection against two writable primary databases.
- English and Russian product documentation with matching sections and contract identifiers.

## Planned profiles

These profiles describe the target architecture. The [Compose guide](docs/en/compose-services.md) defines the current implementation.

| Profile | Intended behavior |
|---|---|
| Single server | Backups and recovery onto a compatible replacement server |
| Assisted pair | Prepared standby, source fencing, and operator-confirmed switchover |
| Automatic pair | Additional profile requiring tested external fencing and decision authority |
| Cluster | PostgreSQL role management through Patroni and an etcd quorum |

Server count alone does not establish independent failure domains or authorize automatic failover.
Storage replicas do not replace retained backup history.

## Documentation

- [0.2 preview release notes](docs/en/release-0.2.md)

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
