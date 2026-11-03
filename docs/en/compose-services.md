# Connect your Compose service

[Русский](../ru/compose-services.md)

This guide describes the 0.2 implementation candidate. A completed browser wizard is a per-service observation, not certification of every provider, application or operating system. Live two-host acceptance and release approval must be established separately.

## 1 Prepare hosts

Enroll two different Linux Docker hosts through **Servers** using the existing one-time installation command. That is the privileged installation step. Afterwards the own-service wizard uses the panel and enrolled host services; it does not require application-specific shell commands or hand-edited configuration files.

The baseline is rootful Linux Docker 29+, Compose 2.24+ with canonical JSON, Python 3.11+, native restic 0.16+, systemd 252+, cgroup v2, cryptography 41+ and PyYAML 6+ on hosts. The controller uses the Python standard library. The installer creates the exclusive nonlogin account `rolypolyops-storage` and runs an isolation probe before consuming enrollment or replacing installed code. A missing prerequisite stops installation. Storage work has no host-network fallback; its worker uses system Python and the standard library. Read the [behavior contract](../../control/contracts/compose-v2.md) for the exact supported model.

## 2 Select the existing service

A fresh installation opens the own-service overview. The optional bundled demo does not produce a setup fault merely because it is absent. Existing selected demo installations retain their recovery and settings views.

Open **Own services**, then **Connect your service**. Select the source, its discovered Compose project and a different recovery host. Review the support reasons, image and mount summary, image size estimate and fingerprint. The estimate excludes application data; the host checks staging space against measured data before stopping the source. An offline or stale host is not ready. Compose readiness is independent of the bundled demo package.

Confirm that only this project's containers write its data. The host detects overlapping running-container mounts, but cannot reliably discover native host writers. Capture briefly stops all project containers, stages their persistent data and exact local images, resumes the previously running set, then uploads the encrypted stage. This is a cold capture, without a zero-downtime guarantee.

Ordinary named volumes, local data/configuration binds, file configs/secrets and resolved environment are included. Privileged containers, host namespaces, host control sockets, remote/external/shared resources, unsupported executable fields and unsafe archive metadata are refused. External routing and automation attached to application labels are not reproduced.

## 3 Connect storage securely

When an existing repository has fresh matching connected bindings on both selected hosts, select it to reuse that connection. The wizard shows the repository identity and continues without passwords, a new challenge or binding rotation. Missing, changed or stale binding proof returns to the normal secure connection form. The Storage view still provides explicit reconnect.

Choose a new or existing repository. Supported kinds are certificate-validated public HTTPS REST and S3-compatible storage. Supply the REST login/password or S3 access key/secret and optional session token. Enter a separate restic encryption password, or generate a random one. Attach requires the existing repository's exact endpoint, namespace and password.

Create reserves a namespace containing the storage UUID beneath the supplied REST base URL or S3 prefix. The panel displays the finalized metadata before confirmation. Check that exact destination. Creation requires positive proof that this dedicated namespace is empty. Authentication, TLS, bucket or listing errors cannot authorize initialization. No existing objects are reset, forgotten or pruned.

The browser receives a short-lived request, node public keys and binding generations. WebCrypto encrypts credentials and the repository password separately for each recipient using RSA-3072/OAEP-SHA256 and AES-256-GCM. Only sealed envelopes and public metadata are sent to the controller. The source binding completes before the recipient attaches to its verified repository identity.

Download the private recovery kit after the final namespace is displayed. It contains plaintext secrets for your local custody: store it securely and do not send it to the panel or post it publicly. Form secrets stay in memory, are cleared on completion/sign-out, and are not put in browser persistent storage. Closing or reloading the page loses the form secrets; durable jobs and service observations remain in the catalog.

## 4 Complete the first recovery

After storage connects, continue setup. The panel imports the selected project, creates a backup, restores that exact point on the other host, applies the service's actual timer and asks the controller to confirm readiness with the restore operation ID. Each job must succeed. A failed or unknown job cannot complete this sequence.

An optional HTTP health rule identifies a Compose service, internal port, relative path and expected status. Docker healthchecks are also supported. Without an application health check the service remains unverified; container startup alone does not give full readiness. These checks do not certify arbitrary database business correctness.

## 5 Daily operations and controlled move

Each card has its own repository points, restore copies, schedule and operation history. Select an exact point to retain an isolated copy, without published ports. Remove applies only to an isolated owned copy. Full repository verification reads restic data; it is distinct from application recovery checks. Scheduling applies an actual per-service timer on the current source.

**Move here** requires a successful isolated restore on the selected recovery host. Review the snapshot time and age, select every TCP port mapping, allow network egress and explicitly accept loss of changes after that snapshot. This is a historical restore with a data-loss window. There is no final delta transfer. The source must be reachable: the controller stops it and disables its timer before activating the destination. Unknown outcomes require inspection, never blind replay.

After verified activation the destination becomes the same service's backup source, and the old source becomes its selected recovery host. The destination enables its timer and attempts a first backup. A running destination whose backup failed is **active_unprotected**, requiring attention. Retry backup from the new source; do not resume the old source. The old data is retained stopped and is not deleted automatically.

Resume source is available only for a known failed activation with proven source stop and fresh proof that the target is still isolated/stopped without ports. Unknown or online target state blocks resume. The server enforces these guards even when a browser observation is stale.

Discovered port candidates are internal TCP container ports. For example, a source published as host `18190` to container `8080` still has target `8080`; choose a free destination host port separately.

Actual IP/port mappings are displayed after activation. DNS, upstream firewall, TLS termination, provider fencing, automatic failover and automatic failback are outside this operation. UDP/SCTP publication is unsupported.

## 6 Failures and evidence boundaries

Busy hosts permit an explicit retry after current work ends. Expired storage envelopes need a fresh challenge and fresh sealing; a password or TLS error must be corrected before another connection attempt. An uncertain HTTP submission retains its request identity in the current page. If a job outcome is unknown, use **Operations** to inspect its durable proof before requesting more work. Global unknown/orphan holds also block demo changes.

Source drift needs an explicit registration update. Reloading does not erase durable jobs, but the in-memory wizard and credentials are lost. The service card can repeat backup, exact restore, timer application and readiness confirmation using the persisted identities. A browser test with synthetic transport verifies interface behavior only. It cannot prove actual repository credentials, TLS routing, Docker isolation, byte preservation, timer durability or a two-host controlled move.

After a successful first backup on the moved source, the wizard automatically restores that exact point on the new recovery host and confirms readiness. After reload, use **Finish protection check**. Activation alone leaves restore_required; a missing first backup leaves active_unprotected. Ordinary include, service extends/provider and executable YAML tags are unsupported. Hosts additionally require PyYAML 6+.
