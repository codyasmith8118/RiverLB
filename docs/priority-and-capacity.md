# Pool priorities and connection limits

Edit a named pool under Local Traffic → Pools, or an inline virtual server:

- **Member priorities:** `IP:port=priority` lines; values 0–65535, higher first.
  Unspecified members have priority zero.
- **Priority group minimum eligible members:** zero disables priority activation
  and allows all members. A positive value must not exceed the pool's member count.
- **Member connection limits:** `IP:port=limit` lines; 1–1000000. Omit a member
  to leave it unlimited.

Virtual Servers additionally provides **Virtual server connection limit**,
0–1000000. Zero is unlimited, subject to the existing global connection limit.
Named pools own member settings; the virtual-server editor hides those inline
fields when a pool is assigned. Save and apply commits all changes together.

```toml
[[pools]]
name = "primary-backup"
algorithm = "round_robin"
members = ["192.0.2.10:443", "192.0.2.11:443"]
member_priorities = { "192.0.2.10:443" = 100, "192.0.2.11:443" = 10 }
priority_group_min_active = 1
member_connection_limits = { "192.0.2.10:443" = 200, "192.0.2.11:443" = 100 }

[[virtual_servers]]
name = "app"
listen = "127.0.0.1:8443"
default_pool = "primary-backup"
connection_limit = 250
```

## Selection and backup activation

Eligible members are healthy, non-draining and below their member limit. Start
with the highest eligible priority group; include complete lower groups until
the cumulative eligible count reaches the configured minimum, or no groups
remain. Use the configured balancing algorithm within that combined set. A
failed, drained or full primary can open a lower-priority backup. Recovery closes
lower groups for new unpersisted connections when the minimum is satisfied again.
The minimum is an activation threshold, not a requirement to reject traffic when
the total eligible count is below it.

A usable source-affinity record takes precedence over priority grouping. A client
can remain on a healthy backup after a primary recovers, until expiry or clearing.
A full/down/draining persistent target is not reused; normal selection finds a
new target and updates affinity. Stateless source hash uses the current eligible
priority set and can change mappings as capacity/health changes.

These policies require regression coverage of capacity, persistence and priority activation interactions.

## Admission across reloads

A reservation consumes virtual-server and member slots before TLS/backend
connection work starts, and releases both on every completion/failure/drop path.
Admission uses atomic counters and never queues excess connections. When the
virtual/global limit is full, or all eligible members are full/down, the accepted
client socket closes and the virtual rejected counter increments. Probes do not
consume traffic slots.

Counters follow **virtual-server name** and **(virtual-server name, member
IP:port)** across runtime generations. Old sessions remain counted after apply,
including removal/re-add of those identities while sessions are alive. Lowering
a limit preserves existing sessions and blocks new admissions until occupancy
falls below the limit. Renaming a virtual server creates a new admission identity.
Changing a member address creates a new member identity. These counts are not
stored in the database; restart has no surviving sessions.

Named pools share configuration, not aggregate capacity: member limits are per
virtual server even when it references a shared pool. These are session limits,
not request-rate limits, backend-wide/node limits or SYN-backlog limits. Scheduler state belongs to each runtime generation. Traffic totals and peaks
use shared persistent counters, and capacity occupancy includes all live
generations. UDP uses these limits for flows, which restart on apply.

## Visibility and verification

Overview and `/api/v1/status` expose virtual `connection_limit`,
`admission_active` and `priority_group_min_active`. Member records add `priority`,
`connection_limit` and `admission_active`. An occupancy may exceed a newly lowered
limit until old sessions finish; this is expected.

Prometheus adds virtual/member `admission_active` and `connection_limit` gauges,
and member `priority`. Zero limit means unlimited, not no capacity.

`tests/priority_capacity.py` covers real primary failure/recovery, saturation,
draining, virtual limits, hot reload, removal/re-add, lowering limits, preserved
connections and durable configuration. Rust tests cover priority expansion,
atomic concurrent reservations, reference validation and slot release; portal
tests cover field ownership, editing and reload.
