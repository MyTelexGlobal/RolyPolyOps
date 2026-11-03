# RolyPolyOps control

[Русский](README.ru.md)

**0.2 candidate:** adds the own-Compose service and REST/S3 storage wizard. See the [service guide](../docs/en/compose-services.md) for workflow, supported scope and limitations. Live two-host acceptance and release approval remain separate requirements. The demo sections below describe the preserved 0.1 mode.

## 1 Available functions

The control panel manages the bundled PostgreSQL/Compose recovery package: connect hosts, view observed health and recovery points, create an encrypted backup, verify a repository, test an exact recovery point, retain a separate preview and remove that preview, and apply a backup schedule. The setup wizard completes only after a successful backup and a matching restore check. Russian and English interfaces are included.

The own-service view discovers supported ordinary Compose projects; see the guide above. Arbitrary database correctness, automatic DNS switching and provider fencing are not implemented. Connecting an unsupported host shows that state and does not make its applications protected.

## 2 Installation

Use Python 3.11 or newer on Linux with systemd. The control process has no third-party Python dependencies. Obtain the complete trusted release repository and its full commit ID from your release supplier. Verify an archive's supplied checksum when using a downloaded archive. Keep `control/web`, `demo/compose.yaml` and `demo/ops` in the release tree: the installer copies the compatibility helpers even when the demo application is unused.

Prepare a separate root-owned release directory on the controller and on each application host. Run the following in Bash from the trusted repository, replacing `RELEASE_SHA` with the trusted full commit ID. The new destination must not already exist. `sudo` alone does not change ownership of a user-owned checkout.

```bash
set -euo pipefail
RELEASE_SHA='REPLACE_WITH_TRUSTED_FULL_COMMIT_ID'
test "$(git rev-parse --verify "$RELEASE_SHA^{commit}")" = "$RELEASE_SHA"
sudo mkdir -m 0755 "/opt/rolypolyops-release-$RELEASE_SHA"
git archive --format=tar "$RELEASE_SHA" | sudo tar -xf - --no-same-owner -C "/opt/rolypolyops-release-$RELEASE_SHA"
sudo chown -R root:root "/opt/rolypolyops-release-$RELEASE_SHA"
sudo chmod -R go-w "/opt/rolypolyops-release-$RELEASE_SHA"
cd "/opt/rolypolyops-release-$RELEASE_SHA"
```

For a reinstall, reuse the unchanged root-owned release directory instead of creating it again.

Choose the panel's HTTPS name and configure its DNS, certificate and reverse proxy. Install the controller from that release directory:

```sh
sudo python3 control/install.py controller --origin https://control.example.org
```

The installer creates a dedicated unprivileged account, persistent catalog, initial password and systemd service. It listens only on `127.0.0.1:8090`. It does not install a public HTTPS proxy or create a DNS record. For Caddy, put this handler inside the TLS site for your panel name, validate the configuration, then reload Caddy:

```caddy
handle /ops/* {
    reverse_proxy 127.0.0.1:8090 {
        header_up X-RPO-Client-IP {remote_host}
    }
}
```

Use the optional `--configure-proxy` flag only when Caddy already includes the managed `/etc/caddy/rolypolyops-routes/*.caddy` import. Without that import the flagged installation stops and preserves the existing proxy configuration.

Open `https://control.example.org/ops/` and check certificate validation from the browser and both hosts. The initial administrator password is in `/var/lib/rolypolyops-control/admin-password`, accessible through privileged server access. Change it on first login and save it separately in a password manager. The downloadable repository recovery kit does not include the administrator password or control catalog. There is no public administrator registration. Reinstalling preserves the catalog and existing credentials.

## 3 Connect hosts

Choose **Servers**, then **Add server**, name the first host and select the primary role. Run the displayed enrollment command from its root-owned release directory. Repeat for a different host with the recovery role. These roles control the bundled demo; own-Compose services select their source and recovery hosts per service. The command installs the outbound host service. A code expires in 15 minutes and is single-use. It contains temporary authority: do not post it publicly. If it expires during prerequisite installation, create a fresh code and repeat the command.

On Ubuntu/Debian the host installer can install missing Docker/Compose, native restic and Python dependencies, and download the pinned helper image. A fresh Docker installation uses the official Docker package repository. Python libraries may use a dedicated runtime. Existing Docker is not restarted or upgraded; installed versions below the required minimum cause a stop. systemd 252+, cgroup v2 and system Python 3.11+ must already be available. Other Linux systems need compatible dependencies provisioned in advance. Allow the required package/image downloads and outbound HTTPS to the controller and storage. Own-Compose enrollment does not require an initialized demo or `lab.env`.

Captured `COMPOSE_*` and `DOCKER_*` execution controls are rejected before recovery changes files or loads images. Accepted application settings are replaced with a closed environment for the bundled package.

Own-Compose storage operations require systemd 252+, cgroup v2 and system Python 3.11+ for an isolated nonroot worker. The installer creates its exclusive account, keeps a root-only identity marker, and performs a bounded probe without repository credentials before consuming enrollment or replacing code. The main agent remains privileged for Docker and outbound control traffic. If isolation is unavailable, the host is not ready for storage operations.

For the legacy demo, the host needs the initialized [supported recovery package](../demo/README.md), Docker/Compose, restic and its private repository configuration. Complete own-Compose setup using the [service guide](../docs/en/compose-services.md).

Agents use certificate-validated outgoing HTTPS. No agent port, SSH private key upload or Docker socket access from the control process is required. Tokens live in root-only host configuration; the catalog stores their digests. Reconnect rotates a token. Revocation is available after active operations have been resolved.

## 4 Daily use

Select the service and recovery point, review the proposed action and confirm it. The panel saves the operation before dispatch. Repeated submission returns the same job. Keep or reload the page while it runs; results and history remain available. Backups can briefly pause the bundled writer, which is disclosed in the confirmation.

A recovery test uses new directories, a separate project and internal isolated networks without published ports. A retained preview uses the same network restriction and never replaces the live site. Its HTTP check runs inside the container. Only the preview recorded by the host service can be removed. Checks cover actual database values, file hash, HTTP, app version, image identity, fresh mounts and runtime restrictions.

The backup interval changes through a host operation, not merely a saved preference. The wizard checks the observed timer state before marking setup complete. Unknown or old observations are shown explicitly. Losing the control process does not stop existing local systemd schedules.

## 5 Interrupted work and recovery

Controller state and the queue persist in SQLite. Hosts keep durable receipts before beginning a mutation and never blindly repeat an interrupted action. The Reconcile action asks the assigned host to inspect its receipt and matching operation proof. If the outcome still cannot be established, the job remains unknown and conflicting mutations stay blocked for investigation.

The catalog contains sensitive operational state. Keep an off-host backup of `/var/lib/rolypolyops-control` using SQLite's backup facility for the database, plus the separately protected backup encryption keys and host configurations. A restored catalog is not by itself authority to reactivate an old primary. Exclude the previous control authority and rotate host enrollment when replacing it.

The controller has one active instance and no automatic high-availability replacement. Existing host timers can continue during its outage; new wizard operations and controlled moves require the controller to be available.

Rollback removes the added Caddy route and stops only `rolypolyops-control.service` and `rolypolyops-agent.service`. Existing lab backup and recovery timers remain independent. Do not delete data directories to roll back the panel.

## 6 Checks and limits

```sh
python3 -m unittest control.test_controller control.test_agent control.test_restore_policy control.test_install
```

These checks cover authentication, request protection, job identity, queue persistence and host authority. They complement real browser and two-host recovery tests. They do not prove provider-outage recovery, split-brain prevention or support for other service packages. The public demo remains read-only.
