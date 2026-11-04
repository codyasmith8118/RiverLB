# Installed privilege separation

Task #16 moves the installed standalone and HA daemons to the dedicated
`riverlb` account. Both use `serve --privileged` and retain only
`CAP_NET_BIND_SERVICE`. The application requires an authenticated helper at
startup and fails closed if it cannot verify its identity or protocol. Explicit
repository CLI instances retain their existing execution mode for fixtures and
console recovery; the packaged services never fall back to it.

This implementation remains under qualification. Source checks and a container
exercise do not establish enforcing-SELinux, live HA, update/recovery, or paired
EVE delivery. Keep #16 open until those requirements have evidence.

## Trust boundary

The web daemon owns `/etc/riverlb`, `/var/lib/riverlb`, and `/run/riverlb`.
Its accounts, database, device TLS keys, and application state remain private to
that account. Publisher trust, application executables, updater checkpoints,
helper policy, ownership records, and HA SSH identities remain root-owned and
outside its writable paths. The helper's socket parent is root-owned 0755;
the socket is root:`riverlb` 0660. Another UID in that group still fails kernel
peer authentication.

`riverlb-privileged.service` runs the fixed Python entrypoint with isolated
imports, a cleared subprocess environment, no shell, fixed executable paths,
and its own filesystem and capability restrictions. It retains network and
HA provisioning privileges. Moving those privileges does not make the helper
unprivileged: its code, root policy, installed dependencies, and kernel remain
trusted. Its source and policy must be reviewed as security-sensitive code.

The helper authenticates the application UID, not a human administrator. HTTP
role checks and audit remain in the web application. A compromised daemon can
exercise the intentionally delegated operations and can deny its own service;
it must not gain arbitrary root execution or overwrite publisher trust or root
credentials. Fresh password/MFA proof is separate work under #18.

The HA service signals systemd readiness after startup withdrawal, management
initialization and HA control-socket binding. Pacemaker is ordered after that
signal. Probing an HA socket before it exists can otherwise turn an ordinary
reboot into an uncertain stop and power fencing. The OCF agent still refuses
to treat an unreachable daemon as a successful stop.

## Protocol 1

Each request uses a new Unix stream and a root-generated 256-bit challenge.
Messages are length-prefixed JSON with a 64 KiB request limit and 2 MiB response
limit. The envelope has exactly `version`, `nonce`, `action`, and `parameters`.
Boolean versions, unknown fields, reused challenges, oversized frames, and
ancillary data are rejected. Received descriptors are closed even when their
control message is truncated. No descriptor or raw socket is returned.

The server checks `SO_PEERCRED` before allocating a worker, permits at most
32 workers, and bounds reads and fixed subprocess timeouts. The Rust client
checks the endpoint's root ownership and the server's kernel UID. Root console
tools are also permitted peers. Protocol errors omit arguments, output, and
credential material. Accepted changes and rejected requests are recorded through
authpriv syslog with UID, PID, fixed action, and outcome.

The action vocabulary is closed:

| Action | Delegated operations |
| --- | --- |
| `network` | Generated address, VLAN, route and source-rule commands; traffic adapters only; private table range and protocol/priority markers |
| `firewall` | Zone queries and exact local destination/port TCP/UDP rules; no direct rules, services, reload, or broad accept |
| `ping` | One bounded echo to a canonical IP, with an optional assigned source and approved device |
| `network_manager` | Approved independent Ethernet profiles and one-device, peer-bound checkpoints; no secrets, imports, plugins, or global checkpoint destruction |
| `ha` | Fixed authority, group, sync, deployment and announcement operations using protected settings and stored membership |
| `lifecycle` | Start/status for the fixed signed updater or HA deployment unit |
| `status`, `update_status` | Helper identity/protocol and selected root-owned updater status fields |

The HA helper reads outgoing synchronization data from one fixed private
service-owned file, copies bounded bytes into memory, and sends them as data
through fixed SSH with protected identity and strict known-host verification.
Callers cannot choose a local executable, credential path, remote command, or
raw Ethernet payload. Announcements require current quorum, fencing, local HA
authority, and an assigned helper-owned address; the helper constructs three
fixed gratuitous ARP or IPv6 NA packets on a send-only raw socket.

NetworkManager trials use a 90-second checkpoint and delete-new-connections
rollback semantics. The helper retains peer ownership and independently checks
NetworkManager's active checkpoints. It destroys only its own completed trial.
See the upstream [NetworkManager D-Bus API](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/gdbus-org.freedesktop.NetworkManager.html)
and [checkpoint flags](https://www.networkmanager.dev/docs/api/latest/nm-dbus-types.html).

## Installation and console policy

The RPM creates a non-login system account. The root preparation unit runs before
either daemon's appliance readiness condition. It initializes policy once from
the root-owned saved configuration and physical NIC inventory, then transfers
application files using directory descriptors. Symlinks, hardlinks, special
files, foreign owners, and writable directories are rejected. It never follows
application-controlled links while changing ownership.

Existing configured traffic parents and otherwise unaddressed physical NICs
become traffic candidates. Other addressed NICs remain management adapters.
A parent shared with the configured management address requires console policy
review. Hotplug and later GUI configuration cannot expand the root policy.
Inspect `/etc/riverlb-privileged/policy.json` from the console before changing
approved adapters. Preserve all existing management and recovery interfaces.
Policy must remain root-owned 0600 in its root-owned 0700 directory. Stop and
restart the helper when applying a reviewed console policy change.

The root migration marker is durable before application ownership changes, so
an interrupted migration cannot later treat application-written configuration
as trusted bootstrap policy. Preparation repeats on service starts to repair
ownership after root console restore. It preserves file contents and device
identity. The development deployment procedure backs up and restores the new
protected directories separately on each appliance.

Legacy HA requires a stopped console migration before preparation. Inventory
all existing HA identities, known-host files, and fencing credential files;
move them into `/etc/riverlb-privileged`, retaining root-only ownership. Move
`ha.json`, `ha.group.json`, and HA deployment identity there, normalize settings
to the fixed installed paths, and leave no HA credentials under the application
directory. The fixed sync key and known-host paths are
`/etc/riverlb-privileged/ha-sync-ed25519` and
`/etc/riverlb-privileged/ha-known-hosts`. Unsupported custom executable or socket
paths must be resolved explicitly from the console. Automatic preparation
refuses legacy `ha.*`/`ha-*` files rather than exposing them to the service UID.
Do not provision or enable a new HA group as part of migrating an existing one.

An active offline version selection must be recovered to the packaged base
before the initial RPM migration. Subsequent signed updates are independently
verified from a root-private copy and must report helper protocol `1` before
the updater stops traffic. Readiness authenticates the service UID; restored
databases and sidecars return to that UID. Root updater state and monotonic
sequence records keep their root-only ownership.

Database backup and restore tools run as the service UID in temporary private
workspaces below the root-owned `/var/lib/riverlb-updater-work` traversal parent.
The root updater copies bounded checkpoint bytes without parsing their private
contents, and keeps its durable checkpoint outside those workspaces. Preflight
removes interrupted owned workspaces under the updater lock. The application
cannot create or rename workspace entries in the root-owned parent.
The updater and recovery units explicitly retain only their fixed file-operation
and UID/GID-switch capabilities. Their database children clear supplementary
groups and run without effective or ambient capabilities.

## Ownership and interrupted-operation recovery

The helper journals intent before each network or firewall mutation and owns
only resources it actually creates. Borrowed OS addresses, routes, VLANs, and
firewall rules are preserved. VLAN removals verify the recorded kernel index.
Resource counts and state sizes are bounded. Same-boot helper restarts retain
ownership; a new boot discards volatile ownership so OS-rendered resources are
borrowed. Permanent helper-created firewall rules retain their ownership.

An uncleared intent prevents helper startup. Stop the daemon and helper, inspect
the root-owned ownership journal and current kernel/firewall state from the
console, and resolve any partially applied resource. The console-only command
`/usr/libexec/riverlb/privileged/riverlb-privileged reconcile-forget-intent`
clears only the interrupted resource's ownership and intent under the service
lock. It leaves the uncertain OS object intact as borrowed. It cannot be invoked
through RPC and does not delete an uncertain resource. Remove an unwanted
leftover explicitly from the console after inspection, then restart the helper
and daemon. Do not delete the entire journal or copy another node's policy.

## Evidence required before delivery

Run Rust regressions, helper transport/grammar/ownership tests, descriptor-based
preparation tests, updater recovery tests, source service audits, and installed
RPM smoke tests. `scripts/test-privileged.sh` exercises real operations through
a non-root peer in a disposable rootless network namespace. The installed RPM
fixture must prove login, forwarding, service UID, protected root writes,
unknown-UID rejection, signed staging, and root-only readiness IPC.

Before closing #16, also qualify managed networking and NetworkManager rollback,
actual fenced HA and announcements, protected SSH synchronization, signed
activation/rollback and console restore under enforcing SELinux. Review AVCs.
Require every exact-commit GitHub workflow, then deploy the accepted artifact
to both EVE review appliances and retain installed-check receipts as described
in [the lab procedure](development-lab.md). Containers do not replace these
installed and platform checks.
