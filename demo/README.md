# Disposable recovery lab

[Русский](README.ru.md)

## 1 Scope

This is a small, read-only public demo backed by PostgreSQL and a proof file. It is not the general RolyPolyOps service. The page shows the serving site's label, database records, and file consistency. It does not claim a backup exists merely because the site is healthy.

Two Linux servers can run the demo. A restic REST repository on the other server holds encrypted captures from the active site. After an assisted switch, configure backups from the new active site to the other host. This has two failure domains: losing the storage host loses both its standby and the repository. Use a separate storage provider before relying on it for important data.

## 2 Start a new demo

Requirements: rootful Docker with Compose v2, Python 3, curl, openssl, util-linux, and restic. Tested lab versions are Docker 29.1.3, Compose 2.40.3, PostgreSQL 17.11, and restic 0.16.4/0.18.1 on Ubuntu x86_64. Container bases are pinned by digest; npm dependencies have a lockfile.

Copy this directory to a dedicated path such as `/opt/rolypolyops-lab`, then run from that directory:

```sh
sudo ops/init-demo A       # use B on the other host
curl --fail http://127.0.0.1:8080/healthz
```

Initialization refuses an existing database or credentials. The web listener is bound to loopback. Publish it through a reverse proxy with HTTPS. PostgreSQL has no published port. Public endpoints allow only GET and HEAD and expose only synthetic fixture data.

## 3 Prepare storage and credentials

On the storage host, create `/var/lib/rolypolyops/repository` and a bcrypt `.htpasswd` for user `lab`. Protect the plaintext authentication password separately. Start the repository with `docker compose -f storage.compose.yaml up -d`. It listens on `127.0.0.1:8000` and requires authentication. The container enables append-only mode.

Example Caddy route inside the storage host's HTTPS site:

```caddy
handle_path /backup/* {
    reverse_proxy 127.0.0.1:8000
}
```

Generate a strong random restic encryption password independently of the HTTP password. Store it as `/etc/rolypolyops/repository-password`, root-owned, mode 0600, on both hosts and in a separate protected recovery kit. Loss of this password makes recovery impossible. Keep all private configuration outside this repository.

Install `ops/labctl` as `/usr/local/sbin/rolypolyops-lab`. Create a root-owned `/etc/rolypolyops/lab.env`, mode 0600:

```sh
RPO_ROOT=/opt/rolypolyops-lab
RESTIC_REPOSITORY=rest:https://backup.example.org/backup/primary
RESTIC_PASSWORD_FILE=/etc/rolypolyops/repository-password
RESTIC_REST_USERNAME=lab
RESTIC_REST_PASSWORD=REPLACE_WITH_A_SEPARATE_RANDOM_HTTP_PASSWORD
```

For a restored active copy, also set `RPO_ROOT` to its retained service directory, `RPO_PROJECT` to its Compose project, `RPO_SOURCE_PORT` to its loopback port, and `RPO_SOURCE_LABEL` to its site label. Set `RPO_TARGET_LABEL` on the recovery host to label restored copies correctly.

On the storage host, use `RESTIC_REPOSITORY=/var/lib/rolypolyops/repository/primary` for local verification and recovery. Initialize the repository once from the source with `sudo rolypolyops-lab init`. Verify that an unauthenticated request to the storage route returns HTTP 401.

## 4 Capture and restore

```sh
# source
sudo rolypolyops-lab backup
sudo rolypolyops-lab status
# recovery host
sudo rolypolyops-lab verify
sudo rolypolyops-lab restore-check latest
sudo rolypolyops-lab restore-standby latest
```

A capture pauses the demo web process, takes a logical PostgreSQL dump and matching files, preserves the application credential and Compose definition, then resumes the web process. Image export and encrypted transfer happen afterward. Only this demo's known writer is stopped; this procedure is unsuitable for an application with other writers.

The capture includes exact web/database image IDs, saved images, checksums, and expected record values. Restore uses a fresh directory, a separate Compose project and loopback port 18081 for a drill or 18080 for a retained standby. It loads the saved images, restores the database, and checks actual record values, file SHA-256, HTTP health, version, image identity, fresh bind mounts and runtime restrictions. The original Compose recreates those restrictions. Existing source/target demo data is not overwritten.

`restore-check` removes its temporary containers, networks and directory after verification. Failed cleanup preserves the directory for investigation and returns failure. `restore-standby` retains the checked copy and records its location in `/var/lib/rolypolyops/standby.json`. It refuses to overwrite an existing standby record. A ready standby is not promoted automatically.

## 5 Schedules and supervision

Install the backup service/timer from `ops/` on the source host, and the restore-check service/timer on the recovery host under `/etc/systemd/system/`. Run `systemctl daemon-reload`, then enable the corresponding timer with `systemctl enable --now`. Backups are hourly; full repository verification and a fresh restore exercise run daily. Run each service manually once before relying on its timer.

`rolypolyops-lab status` shows snapshots, timers and the last successful operations. Inspect failures with `systemctl --failed` and `journalctl -u rolypolyops-backup -u rolypolyops-restore-check`. There is no external alert delivery yet. A successful old result does not establish that the most recent scheduled run succeeded.

Remote append-only clients cannot prune the repository. Retention cleanup must run under a separately trusted identity on the storage host after checking usable restore points. No automatic pruning is enabled in this lab; monitor disk space and stop before storage fills.

## 6 Controlled switching and limits

Before publishing a restored copy, stop the original application and disable its automatic restart. Confirm the selected snapshot and data-loss boundary, verify the target, then change routing. Preserve the original data for investigation. A DNS update does not stop old writers. Do not return to an older database after new writes without a separate reconciliation plan.

This lab provides no database replication, quorum, external fencing, Cloudflare credentials, automatic DNS failover, automatic failback, generic service enrollment, or graphical management. Its public demo is read-only. A controlled application-stop exercise does not prove recovery from a full provider outage or a network partition.

Upstream components retain their licenses: [restic](https://github.com/restic/restic), [rest-server](https://github.com/restic/rest-server), [PostgreSQL](https://www.postgresql.org/about/licence/), [Node.js](https://github.com/nodejs/node/blob/main/LICENSE), and [Caddy](https://github.com/caddyserver/caddy). No DockNest or BackupSheep code is included in these lab tools.
