# 0.2 preview

[Русский](../ru/release-0.2.md)

RolyPolyOps can now protect an existing supported Docker Compose application through the panel. The bundled demo remains available.

## Available

- Select a discovered project, its source host and a separate recovery host.
- Connect an HTTPS REST or S3-compatible repository. Credentials are encrypted in the browser for the selected hosts. Download the private recovery kit for separate custody.
- Capture application data, resolved environment, file configs/secrets and exact local image identities. Project containers pause while persistent data is staged, then resume before upload.
- Restore an exact repository point into an owned isolated copy with application health checks and no published ports.
- Enable an actual per-service backup timer and view points and operation outcomes.
- Move a verified copy with explicit operator confirmation while the source is reachable. The selected snapshot defines the possible data-loss window; no final delta is transferred.

## Verification and scope

REST and S3 wizard flows completed on two Linux amd64 hosts with Docker 29. Both included repository connection on both hosts, registration, backup, isolated restore, HTTP checks and an enabled hourly schedule. Independent checks compared control records, file/environment/secret hashes, numeric owners and modes, image config/platform identities and restored network isolation.

The [service guide](compose-services.md) defines prerequisites and supported inputs. One running container per enabled service, locally available native images and one selected repository per service are required. Explicit service `platform` fields are currently refused. These tests do not certify every application, provider, architecture or operating system.

## Current boundaries

The panel is a single controller. Automatic failover, provider fencing, DNS automation, storage replication and cluster profiles are not implemented. An operator-confirmed move requires an online source and accepts changes lost after the selected snapshot.

Host state and the controller catalog need separate protection. A repository recovery kit does not contain the administrator password or catalog. Each service uses one repository; two connected hosts do not create a second independent backup location. Retention pruning and object-lock configuration are not automated. Follow the [security guide](security.md) and test recovery with your application's data before relying on it.
