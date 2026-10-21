# Architecture

RiverLB is a Rust process with an embedded web interface, a local database and a
full-proxy data plane. Linux owns routing and the TCP/IP stack. RiverLB accepts
client traffic, selects a backend and forwards application bytes or UDP datagrams.
It is not a transparent packet-forwarding appliance.

## Module ownership

| Area | Main files | Responsibility |
|---|---|---|
| Startup and CLI | `src/main.rs` | Commands, database selection, startup and signals |
| Configuration | `src/config.rs` | Serialized settings, validation, named-object resolution and generated domain HTTPS listeners |
| Apply transactions | `src/control.rs`, `src/confirmation.rs` | Runtime generations, listener reuse, rollback and connectivity confirmation |
| TCP and scheduling | `src/runtime.rs`, `src/admission.rs` | Member selection, health state, reservations, session limits and draining |
| UDP | `src/runtime/udp.rs` | Bounded client-endpoint flows, backend sockets and idle expiry |
| HTTP | `src/http_proxy.rs` | HTTP/1 framing, streaming, WebSockets, RiverRules and cookie persistence |
| Health checks | `src/monitor.rs` | Protocol-specific probes and verified TLS checks |
| TLS and certificates | `src/tls.rs`, `src/server_tls.rs`, `src/certificates.rs`, `src/acme.rs` | Client/backend TLS, certificate stores, CSR and renewal |
| Linux integration | `src/network.rs`, `src/nat.rs`, `src/firewall.rs` | Network plans, source selection, return routing and firewalld rules |
| HA | `src/ha.rs`, `src/ha_network.rs`, `deploy/ha/` | Cluster authority, ownership, synchronization and address announcements |
| Management security | `src/management.rs`, `src/management/`, `src/auth.rs`, `src/local_control.rs` | HTTP API, source/Host/Origin checks, roles, tokens and private readiness IPC |
| Durable state | `src/storage.rs`, `src/backup.rs` | Turso connection, revisions, accounts, audit, snapshots and restore |
| Operations | `src/traffic.rs`, `src/operations.rs`, `src/updates.rs` | Traffic checkpoints, system health, alerts, backups and signed update staging |
| Portal | `web/` | Embedded HTML, CSS and JavaScript; no frontend runtime or build dependency |

## Configuration and apply lifecycle

TOML seeds a database that has no saved configuration. After that, the database's
latest committed revision is authoritative. `Config::resolve` expands reusable
pools and profiles into effective runtime settings while preserving named
references in stored/exported configuration. Domain routes can derive HTTPS
listeners before validation.

An apply follows this sequence:

1. Validate the proposed configuration and check its expected revision.
2. Acquire the generation lock and verify HA authority when relevant.
3. Apply managed Linux network changes before binding newly needed addresses.
4. Resolve certificates/trust and construct the next runtime without waiting for
   network health probes.
5. Reuse compatible listener sockets and prepare new ones. Transfer verified
   member health only when backend and monitoring inputs are unchanged.
6. Prepare firewalld/HA changes, then commit configuration and its audit event.
7. Cancel and await the old generation's accept/probe/UDP tasks, then activate
   the prepared generation.

Configuration reads that need the generation lock can wait behind an apply.
[Apply timing logs](performance.md) distinguish that wait from certificate,
network, firewall and database work. The API runs admitted applies in a separate
task so a disconnected browser cannot abandon a transaction midway.

A validation, preparation or commit failure retains the prior revision and runs
compensating network commands. Linux changes are not atomic: an edit or rollback
can interrupt traffic. A rollback failure stops normal daemon operation and
requires recovery. Management/network confirmation retains a rollback journal;
HA has its own durable ownership journal. These are distinct recovery mechanisms,
not a general transactional Linux network manager. See
[networking](networking.md) and [configuration recovery](configuration-recovery.md).

Management can bind loopback or an explicit unicast IP. Address changes prepare a
new socket before releasing the previous one; conflicting address swaps require
an intermediate free address. Protocol/certificate changes can reuse the same
port and drain old management connections after their current response.

## Traffic and resource invariants

- Validate before binding. Prepare all required listeners before activating a
  new generation. TCP and UDP can share an IP/port because they use separate sockets.
- New members start unhealthy. Background probes establish readiness; startup
  and apply do not wait for every backend. A runtime-wide semaphore limits probe
  concurrency to 16. Rise/fall thresholds count consecutive observations.
- Reserve capacity before forwarding. RAII releases global, virtual-server and
  member slots on completion, failure or cancellation. Decreased limits preserve
  existing occupancy and reject excess new work.
- Never hold a synchronous mutex across an await. Keep queues, body sizes,
  affinity tables and diagnostic snapshots bounded.
- Do not replay application bytes after backend failure. Clients decide whether
  retrying an operation is safe.

Named pools share configuration, not one global scheduler or capacity counter
across all referring virtual servers. Each virtual server has its own runtime
pool context. Backend source selection applies to traffic and probes; source NAT
uses outgoing socket binding and kernel-allocated ephemeral ports.

TCP sessions use a separate tracker and retain the runtime they started with
across ordinary applies. Half-close propagation uses bidirectional copying.
HTTP processing reserves members per backend exchange, with separate framing,
streaming and tunnel limits described in [RiverRules](river-rules.md).

UDP flows are keyed by the client IP/port within a virtual server. Each flow owns
a connected backend socket, a member reservation, an idle timer and an eight-packet
queue. A process-wide 8 MiB budget bounds queued payloads across generations and
virtual servers. Oversized aggregate queue use drops new packets; capacity limits
bound admitted flows. Apply and HA withdrawal cancel UDP flows. No UDP flow socket
or live TCP/TLS session is replicated. See [UDP limits](udp-load-balancing.md).

Shutdown cancels accept/probe loops and allows TCP sessions up to ten seconds to
finish. This drain window does not provide live session migration.

## Statistics, persistence and storage

`traffic.rs` counts successfully forwarded application bytes while sessions are
active. Shared registries retain traffic totals and capacity occupancy across
runtime replacement. A five-second sampler checkpoints counters and bounded
latency aggregates; no SQL runs on the forwarding path. Restart restores saved
totals while live gauges return to zero. A crash can lose increments since the
last checkpoint. See [statistics semantics](traffic-statistics.md).

Source/cookie affinity tables live in memory. Applying configuration creates new
tables for new traffic; draining TCP sessions retain their old runtime. HA can
replicate asynchronous source/cookie checkpoints with expiry checks, which is
separate from live transport state. Stateless source hashing uses no affinity
record. See [persistence](persistence.md) and [HA](high-availability.md).

Storage serializes access to the local Rust-native Turso connection and takes an
exclusive companion-file lock. Revisions and their audit events commit together.
Managed certificates use separate device and virtual-server stores; normal
configuration and inventory responses omit private keys. Explicit private backups
and HA traffic certificate synchronization carry secrets and require trusted
administrative access. External PEM/trust files need separate backup and deployment.

## Security and deployment boundaries

Management validates the actual connecting source, Host and browser Origin before
serving protected routes. Sessions and bearer tokens are checked against account
roles and scopes; mutation headers remain required. Password hashing runs on
blocking workers. Public login assets and `/healthz` disclose no configuration.
Management currently accepts its bound IP/port or `localhost:port` as Host; a
certificate containing another hostname does not itself authorize that Host.

Installed managed-network services run as root with systemd capability, filesystem
and syscall restrictions. This remains a trusted privileged process. Publisher
trust is provisioned separately from application update uploads; updates are
signed offline standalone application bundles. See [security](security-and-database.md),
[service hardening](service-hardening.md) and [offline updates](offline-updates.md).

HA delegates authority to Pacemaker/Corosync and requires working fencing.
Management stays available on both nodes; only the authorized active owns floating
traffic addresses. Source/cookie checkpoint replication and traffic configuration
sync do not include device certificates, local accounts or statistics. Real
platform fencing, installation, capacity and upgrade qualification remain release
gates in the [appliance test plan](appliance-test-plan.md).
