# Compatibility and current status

[Русский](../ru/compatibility.md)

## 1 Available repository materials

Available now: product specification in English and Russian, initial JSON Schema for service profiles, and illustrative manifests. No executable service, host enrollment, live backup, restore, replication, DNS change, or provider shutdown is provided.

## 2 Target environment

The baseline target is Linux, PostgreSQL, and containerized services with persistent files. PostgreSQL, pgBackRest, restic, Patroni, etcd, HAProxy, and optional file-storage components retain their upstream behavior and licenses. No exact version matrix is certified yet.

An application needs a consistency and recovery package. Other databases, mail services, virtual machines, and Kubernetes are separate compatibility profiles and must not be inferred from container startup alone.

## 3 Deployment-specific inputs

Required inputs are application versions, data volumes and change rate, RPO/RTO targets, failure domains, provider API rights, durable fencing capability, network latency, capacity, image availability, and recovery-key access.

No measured recovery time, compression ratio, or unlimited failure tolerance is claimed. The schema validates declarations only; it does not certify these deployment properties.
