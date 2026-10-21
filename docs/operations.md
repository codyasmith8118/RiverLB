# Day-to-day operations

Use this guide for startup, saved configuration, troubleshooting and basic API
access. For health alerts, scheduled backups and audit search, use the
[appliance operations guide](appliance-operations.md).

## Start and stop

For an installed standalone appliance that has completed console setup:

```bash
sudo systemctl start riverlb
sudo systemctl status riverlb
sudo journalctl -u riverlb -n 100 --no-pager
sudo systemctl stop riverlb
```

HA deployments use `riverlb-ha.service` and the [HA procedure](high-availability.md)
instead. Do not start standalone and HA processes against the same database.

For a repository instance:

```bash
cargo build --locked
./target/debug/riverlb validate --config examples/riverlb.toml
./target/debug/riverlb serve --config examples/riverlb.toml
```

Use Ctrl-C or SIGTERM to stop accepting traffic and drain TCP sessions for up to
ten seconds. Managed networking needs `CAP_NET_ADMIN`; root and firewalld
authorization may also be needed. Use unprivileged ports and loopback for ordinary
source development. Only use `--external-network` when you provision traffic
interfaces, addresses, routes and firewall policy separately.

For debug logs in a repository instance:

```bash
RUST_LOG=riverlb=debug ./target/debug/riverlb serve --config examples/riverlb.toml
```

For a privileged lab instance, put `env RUST_LOG=riverlb=debug` after `sudo`.
[Apply performance](performance.md) explains the timing stages in these logs.

## Configuration and database

TOML initializes an empty database. Later starts load its latest saved revision.
The default database replaces the config filename extension with `.db`; an
explicit `--database PATH` overrides it. Installed services use
`/var/lib/riverlb/riverlb.db`.

Stop the relevant process before local database commands. For a source instance:

```bash
./target/debug/riverlb export --database examples/riverlb.db > riverlb-config.json
./target/debug/riverlb validate --config examples/riverlb.toml
./target/debug/riverlb import --database examples/riverlb.db --config examples/riverlb.toml
./target/debug/riverlb admin --database examples/riverlb.db --username admin
```

Import deliberately replaces the saved configuration. Admin creates/resets a
local administrator and prompts for a password; recovery also resets its MFA and
revokes sessions/tokens. Use `/usr/bin/riverlb` and the installed database path for
an appliance. Local commands enforce an exclusive database lock; do not delete
its lock file to bypass another running owner.

JSON export is configuration only. Make an [encrypted backup](appliance-operations.md#encrypted-backups)
for accounts, managed certificate keys and recovery state. External PEM/trust
files, mounted storage and OS/cluster settings need separate backups.

## Common symptoms

| Symptom | What to check |
|---|---|
| Cannot reach the GUI | Console setup completion, management IP/port, running service and firewall. The base RPM starts from loopback HTTP; the appliance wizard configures explicit-IP HTTPS. |
| SSL protocol error | Match the URL scheme to the configured HTTP/HTTPS protocol. Port 18090 alone does not imply either protocol. |
| Address already in use | Inspect listeners with `sudo ss -lntup`; check for another RiverLB process or service before changing ports. |
| Cannot assign requested address | Confirm the IP exists with `ip -br addr`. For a managed VIP, select the correct ingress VLAN and inspect the network plan. |
| VLAN or firewall object conflict | Compare the existing object's exact attributes and ownership with the saved configuration. Preserve console access; do not delete unrelated host rules to make startup succeed. |
| Ping works but a service port fails | Check the virtual-server IP/port/protocol, enabled state, listener firewall rule and healthy pool capacity. ICMP reachability does not prove TCP/UDP service readiness. |
| HTTP monitor is down but TCP is up | Verify path, Host header, expected status/body and TLS settings against the application. TCP only checks port connectivity. |
| Changes disappear after reload | Done retains a draft; Save and apply activates it. Check revision conflicts and pending connectivity confirmation. |
| Editing TOML has no effect | The existing database is authoritative; use the GUI or an intentional stopped import. |
| Page refreshes use one backend | TCP balances per connection. Check browser keepalive, persistence, member eligibility and weights; use HTTP processing for per-request balancing. |
| Apply takes several seconds | Enable debug logging and compare apply phase timings. Backend probes should not block apply. See [performance diagnostics](performance.md). |

For tagged networking and asymmetric return paths, use [networking](networking.md)
and [two-arm setup](two-arm-networking.md). For management/network rollback, use
[configuration recovery](configuration-recovery.md). Keep a separate console path
when changing the management address or interface.

## API essentials

Use the bound management IP and port in the URL. Host protection currently accepts
that IP/port or `localhost:port`; a DNS alias is not automatically accepted.
Browser Origin must match. Authentication is required except for login assets and
`/healthz`, subject to management source restrictions. Roles and bearer-token
scopes limit which operations are available.

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Management process liveness; not backend capacity |
| `GET /api/v1/status` | Virtual-server/member health and traffic counters |
| `GET /api/v1/config` | Current revision, configuration and network mode |
| `POST /api/v1/config/validate` | Validate a JSON configuration without activation |
| `PUT /api/v1/config` | Apply `{revision, config}` and return the new revision/management URL |
| `GET /api/v1/config/history` | Browse saved configuration revisions |
| `GET /api/v1/config/history/{revision}` | Read a saved revision for review or draft import |
| `GET /metrics` | Authenticated Prometheus metrics |

Mutations require JSON and `X-RiverLB-Request: configure`. Use a login cookie or
scoped bearer token; do not put credentials in URLs. Most JSON requests have a
2 MiB limit, with separate limits for login and large artifact endpoints. See
[authentication and API security](security-and-database.md#authentication-and-api).

The status CLI supports HTTP loopback management only:

```bash
./target/debug/riverlb status --address 127.0.0.1:18090 --session-stdin
```

Provide a signed-in session token on stdin. For HTTPS or remote management, use
the authenticated portal/API with certificate verification.

## Further operations

- [Statistics and latency](traffic-statistics.md) explains persistent totals, live gauges and reset behavior.
- [Monitors](health-monitors.md) explains readiness and diagnostic failures.
- [Persistence](persistence.md) covers inspection and audited clearing.
- [Certificate management](certificates.md) covers device/traffic stores, rotation and CSR workflows.
- [Signed updates](offline-updates.md) covers application activation and recovery.
- [Release readiness](release-readiness.md) lists remaining VM and platform qualification.
