# RolyPolyOps control

[Русский](README.ru.md)

## 1 Available functions

The control panel manages the bundled PostgreSQL/Compose recovery package: connect hosts, view observed health and recovery points, create an encrypted backup, verify a repository, test an exact recovery point, retain a separate preview and remove that preview, and apply a backup schedule. The setup wizard completes only after a successful backup and a matching restore check. Russian and English interfaces are included.

General application discovery, arbitrary databases, automatic DNS switching and provider fencing are not implemented. Connecting an unsupported host shows that state and does not make its applications protected.

## 2 Installation

Use Python 3.11 or newer on Linux with systemd. The control process has no third-party Python dependencies. Obtain a trusted release checkout, pin its commit and verify the downloaded archive's published SHA-256 before running code as root. The commands below trust the local checkout.

```sh
sudo python3 control/install.py controller --origin https://control.example.org --configure-proxy
```

The installer creates a dedicated unprivileged account, persistent catalog, initial password and systemd service. It listens only on `127.0.0.1:8090`. `--configure-proxy` adds a route only when Caddy already has the managed `/etc/caddy/rolypolyops-routes/*.caddy` import. Otherwise existing proxy configuration is preserved and the integration must be supplied explicitly:

```caddy
handle /ops/* {
    reverse_proxy 127.0.0.1:8090 {
        header_up X-RPO-Client-IP {remote_host}
    }
}
```

Open `https://control.example.org/ops/`. The initial administrator password is in `/var/lib/rolypolyops-control/admin-password`, accessible through privileged server access. Change it on first login and keep the new password in your private recovery kit. There is no public administrator registration. Reinstalling preserves the catalog and existing credentials.

## 3 Connect hosts

Choose Add server in the wizard, name the host and select its role. The primary can create backups and change the backup interval; recovery nodes can verify and restore. Run the displayed enrollment command from the same trusted checkout on that host. It installs the outbound host service. A code expires in 15 minutes and is single-use. It contains temporary authority: do not post it publicly.

The host needs the initialized [supported recovery package](../demo/README.md), Docker/Compose, restic and its private repository configuration. This release recognizes that package; it does not configure unknown applications or silently overwrite existing deployments. On the supplied two-host lab these prerequisites are already configured.

Agents use certificate-validated outgoing HTTPS. No agent port, SSH private key upload or Docker socket access from the control process is required. Tokens live in root-only host configuration; the catalog stores their digests. Reconnect rotates a token. Revocation is available after active operations have been resolved.

## 4 Daily use

Select the service and recovery point, review the proposed action and confirm it. The panel saves the operation before dispatch. Repeated submission returns the same job. Keep or reload the page while it runs; results and history remain available. Backups can briefly pause the bundled writer, which is disclosed in the confirmation.

A recovery test uses new directories, a separate project and a loopback listener. A retained preview uses port 18082 and never replaces the live site on port 18080. Only the preview recorded by the host service can be removed. Checks cover actual database values, file hash, HTTP, app version, image identity, fresh mounts and runtime restrictions.

The backup interval changes through a host operation, not merely a saved preference. The wizard checks the observed timer state before marking setup complete. Unknown or old observations are shown explicitly. Losing the control process does not stop existing local systemd schedules.

## 5 Interrupted work and recovery

Controller state and the queue persist in SQLite. Hosts keep durable receipts before beginning a mutation and never blindly repeat an interrupted action. The Reconcile action asks the assigned host to inspect its receipt and matching operation proof. If the outcome still cannot be established, the job remains unknown and conflicting mutations stay blocked for investigation.

The catalog contains sensitive operational state. Keep an off-host backup of `/var/lib/rolypolyops-control` using SQLite's backup facility for the database, plus the separately protected backup encryption keys and host configurations. A restored catalog is not by itself authority to reactivate an old primary. Exclude the previous control authority and rotate host enrollment when replacing it.

Rollback removes the added Caddy route and stops only `rolypolyops-control.service` and `rolypolyops-agent.service`. Existing lab backup and recovery timers remain independent. Do not delete data directories to roll back the panel.

## 6 Checks and limits

```sh
python3 -m unittest control.test_controller control.test_agent
```

These checks cover authentication, request protection, job identity, queue persistence and host authority. They complement real browser and two-host recovery tests. They do not prove provider-outage recovery, split-brain prevention or support for other service packages. The public demo remains read-only.
