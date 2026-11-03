# Compatibility and current status

[Русский](../ru/compatibility.md)

**0.2 preview:** connect a supported Compose service and REST/S3 repository through the wizard, create an encrypted backup and restore it on another host. Both storage routes have been exercised on two Linux amd64 Docker hosts. See the [service guide](../../docs/en/compose-services.md) for the supported model and limits. The bundled demo remains available.

## 1 Available repository materials

Available now: product specification in English and Russian, initial JSON Schema for service profiles, illustrative manifests, and [executable recovery lab tools](../../demo/README.md) for the bundled read-only PostgreSQL demo. The lab captures and restores that application only. The [initial control panel](../../control/README.md) enrolls hosts and manages this package. The 0.2 preview adds enrollment of supported ordinary Compose projects through the own-service wizard. Replication, automatic DNS changes and provider shutdown are not implemented.

## 2 Target environment

The baseline target is Linux, PostgreSQL, and containerized services with persistent files. PostgreSQL, pgBackRest, restic, Patroni, etcd, HAProxy, and optional file-storage components retain their upstream behavior and licenses. No exact version matrix is certified yet.

An application needs a consistency and recovery package. Other databases, mail services, virtual machines, and Kubernetes are separate compatibility profiles and must not be inferred from container startup alone.

## 3 Deployment-specific inputs

Required inputs are application versions, data volumes and change rate, RPO/RTO targets, failure domains, provider API rights, durable fencing capability, network latency, capacity, image availability, and recovery-key access.

No general recovery-time guarantee, compression ratio, or unlimited failure tolerance is claimed. Lab observations apply only to the tested fixture and environment. The schema validates declarations only; it does not certify these deployment properties.
