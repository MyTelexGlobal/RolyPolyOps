# Example service manifests

[Русский](README.ru.md)

These manifests describe the initial configuration contract. They do not operate on servers.
All examples use reserved .invalid hosts and secret identifiers instead of secret values.
RPO/RTO values are illustrative policy targets, not measured guarantees.

- [Single server](service-single.json)
- [Assisted pair](service-pair.json)
- [Cluster](service-cluster.json)
- [Automatic pair with an external fencing policy](service-pair-automatic.json)

See the [profile reference](../docs/en/service-profiles.md) and
[schema](../schemas/service-package.schema.json).
