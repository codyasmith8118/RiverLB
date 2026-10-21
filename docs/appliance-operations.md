# Appliance health, alerts, backups, and audit events

The **System Health**, **Alerts**, **Backups**, and **Audit Events** pages operate locally on each appliance. They save independently of traffic configuration and are not synchronized to an HA peer. Administrators manage operations settings and sensitive downloads; authenticated monitoring accounts can read system health according to their role or token scope.

## System health and support bundle

System Health reports CPU utilization between samples, memory use, free space on the application database filesystem, uptime, load averages, kernel time synchronization, interfaces and interface errors, application version, and HA/configuration synchronization state. CPU displays “Collecting…” until two samples are available. Unsupported or inaccessible metrics display as unavailable; the kernel clock query reads time discipline without changing the clock.

**Download redacted support bundle** creates a JSON report using an explicit allowlist of metrics and object counts. It omits configuration values, addresses, hostnames, administrator names, password hashes, MFA material, API tokens, certificate contents, private keys, rule text, arbitrary error text, file contents, audit text, and logs. Objects are assigned generic identifiers such as `virtual-server-1`. The diagnostic file therefore provides operational evidence without exporting private configuration or credentials. Private backups are a separate feature.

## Alerts and remote delivery

The appliance samples health every 30 seconds. **Check now** performs an immediate sample. Configure CPU and memory thresholds, minimum filesystem free space, certificate expiration warnings, unavailable pool capacity, HA errors, unsynchronized time, and unconfirmed management/network changes. Current alerts record their first observation and are removed when their conditions resolve.

Configure an optional **HTTPS webhook URL** and trust source (`system` or an absolute regular CA PEM file). URLs cannot contain embedded credentials, and redirects are not followed. Delivery verifies the remote certificate and hostname, has a five-second deadline, and reads at most 8 KiB of response headers. Each batch contains up to 20 alert/resolution transitions. Failed deliveries use persisted exponential backoff up to one hour; the queue retains the latest 100 transitions during an extended outage. Delivery can repeat after a partial failure or crash, so webhook receivers should tolerate duplicates. The page shows the delivery error and queued notifications.

The webhook payload is JSON:

```json
{
  "product": "RiverLB",
  "created": 1791420000,
  "events": [
    {
      "event": "alert",
      "alert": {
        "id": "memory",
        "severity": "warning",
        "message": "Memory utilization exceeds 90%",
        "first_seen": 1791420000,
        "last_seen": 1791420000
      }
    }
  ]
}
```

An optional numeric **Syslog destination IP:port** sends bounded RFC 5424 UDP messages. UDP delivery is best effort: sending a datagram does not prove remote receipt and provides no encryption or authentication. Use a protected management network for this transport. Enabling **Forward audit events to syslog** forwards up to 200 events per sampling cycle with a persisted ID cursor, a bounded processing window, and a two-second deadline per send. Existing retained events are forwarded when enabled for the first time. Retention can remove unsent historical events during a prolonged receiver outage.

## Encrypted backups

On Backups, set an encryption passphrase of 12–1024 bytes and store it separately from the appliance. RiverLB derives a 256-bit encryption key with Argon2id (32 MiB memory, three iterations, one lane), uses AES-256-GCM with a new random nonce for every backup, and authenticates the backup metadata and contents. The salt and derived scheduling key reside in a service-owned `0600` operations state file beside the database; the passphrase is not saved or returned by the API. Anyone possessing that local scheduling key can decrypt that schedule’s files. Root access to the appliance remains trusted.

**Download encrypted backup** creates an independent `.rlbenc` file using the supplied passphrase and a new random salt. It contains revisioned configuration, accounts and authentication settings, managed certificates and private keys, certificate signing requests, ACME data, audit events, and retained traffic samples. Login sessions, API tokens, and token activity are excluded. External certificate/key/trust files and OS settings are not embedded and need separate backups.

Backups capture confirmed configuration. Confirm or revert a pending management/network change before downloading a backup or staging a restore. Scheduled backups wait while confirmation is pending.

To schedule backups:

1. Mount operator-managed off-appliance storage, such as an NFS share, on the appliance using your OS/storage procedures.
2. Create a real directory on that separate mounted filesystem and grant the RiverLB service write access. RiverLB rejects root-filesystem destinations, temporary/system pseudo-filesystems, missing directories, and symbolic-link paths. It does not create or mount a remote share and does not implement native SFTP.
3. Enter the mounted directory, interval in hours, and number of backups to retain. Set the passphrase and enable the schedule.
4. Save the settings and use **Run backup now** to verify the destination. Review last success, next attempt, and any error.

The deployed service permits writes beneath `/mnt/riverlb-backups`. For another mount path, add it to the service's `ReadWritePaths` with a systemd drop-in and restart the service; filesystem ownership and mount permissions still apply.

An unavailable mount causes a backup failure instead of writing to the underlying root filesystem. The scheduler retries failures after five minutes. Files are created privately and synced before retention runs. Retention removes only regular files matching RiverLB’s generated `riverlb-<timestamp>-<random>.rlbenc` naming format; it leaves other operator files and symbolic links intact and always keeps the newly created backup. An interrupted backup is reported on the next startup.

## Guided restore

The portal separates verification and staging from destructive activation:

1. Select a `.rlbenc` file and provide its passphrase.
2. Select **Validate backup**. Authentication, format, checksum, configuration, account, and managed certificate validation must succeed. Review creation time and inventory counts.
3. Select **Stage restore**. This stores the validated snapshot for offline activation and leaves the running configuration in place.
4. From the console, stop RiverLB and activate the staged snapshot:

   ```bash
   sudo systemctl stop riverlb
   sudo riverlb restore --database /var/lib/riverlb/riverlb.db --staged --replace
   sudo systemctl start riverlb
   ```

   For a repository instance, stop the running process and use the corresponding local binary and database path instead:

   ```bash
   ./target/debug/riverlb restore --database /path/to/riverlb.db --staged --replace
   ```

5. Connect using the restored management address and sign in with a restored account. Current accounts are replaced, and sessions and API tokens are revoked. Local backup schedules remain unchanged. On a fresh replacement appliance, bootstrap local management and an administrator first so that the portal can validate and stage the encrypted file.

Restore does not recreate missing external TLS files, remote mounts, cluster software, or OS configuration. Check these dependencies before activation. Keep console access when restoring management/network settings.

## Audit search and retention

Audit Events supports case-insensitive text search across event/actor text, an optional exact actor filter, and bounded pagination. Each event has a stable numeric ID and timestamp. Audit retention settings on Alerts limit events by age and total records; pruning runs during operations sampling. Defaults are 365 days and 100,000 records. Search parameters use bound SQL values and are limited to 256 bytes of text, 128 bytes of actor, and 200 records per API page.

## API and verification

All endpoints are under `/api/v1/operations/` and use the normal authentication, management source restrictions, authorization, and request-forgery protection. Mutating requests require JSON and `X-RiverLB-Request: configure`.

| Method | Path | Purpose |
|---|---|---|
| GET | `health` | Current system and application health |
| GET / PUT | `settings` | Public operations settings and local immediate save |
| POST | `alerts/refresh` | Sample health and process bounded delivery |
| GET | `audit?query=&actor=&offset=0&limit=50` | Search and paginate events |
| POST | `support` | Download the redacted support JSON |
| POST | `backup/run` | Write an encrypted backup to the configured mounted destination |
| POST | `backup/download` | Download an encrypted backup using `{passphrase}` |
| POST | `backup/restore` | Authenticate/validate or stage using `{backup, passphrase, stage}` |

`settings` saves accept `{settings, backup_passphrase}`. Omitting or leaving the passphrase blank preserves the current scheduling key. The public response never contains that key or its salt. Operations writes already admitted by the API finish in independent tasks even if the requesting client disconnects.

Run `cargo test operations::tests` for encryption authentication, metadata/payload tampering, bounded paths and remote transport validation, private state ownership, owned-file retention, alert transitions, diagnostic redaction, and audit pagination tests. `python3 tests/operations.py` uses only disposable state and local fixture services to verify the actual APIs, verified HTTPS webhook failure/retry across restart, UDP syslog, confirmed-only backups, encrypted staging/offline restore, and session revocation. `node tests/operations.cjs` and `node tests/release.cjs` exercise GUI actions using JSDOM; set `UI_SNAPSHOT_DIR` to export populated pages for the optional Firefox audit in `tests/ui_layout.py`. No production network configuration or live application database is modified.
