# Persistence profiles

Local Traffic → Profiles → Source Persistence creates reusable settings. Assign a profile
name to a virtual server, or use its inline persistence fields. Named profiles
and inline settings are mutually exclusive. Profile settings persist in the
configuration database; each virtual server keeps its own runtime table.

## Source address affinity

Connections reuse the selected healthy, non-draining member for their source key.
The balancing algorithm selects a member when no usable record exists. IPv4 and
IPv6 prefix lengths mask the key: defaults `/32` and `/128` keep individual
addresses; `/24` or `/64` group clients by subnet. `/0` groups an entire address
family. Client ports are ignored. Clients behind the same NAT share affinity.

Sliding expiry refreshes a record on each new connection. Fixed expiry leaves its
original deadline unchanged when reused. Established sessions alone do not
refresh records. Timeouts use monotonic time and range from 1 to 86400 seconds;
zero disables affinity. Capacity is 1–1000000 when enabled. At capacity, expired
records are reclaimed; when still full, new sources are balanced without creating
records. Valid records are not evicted by new clients. Down/draining members
cannot receive new persistent connections. Actual backend-connect failures mark
the member down; failed connections are not retried automatically.

```toml
[[persistence_profiles]]
name = "home-affinity"
[persistence_profiles.settings]
timeout_secs = 180
max_entries = 10000
ipv4_prefix = 32
ipv6_prefix = 128
refresh_on_use = true

# In an existing [[virtual_servers]]:
# persistence_profile = "home-affinity"
```

Legacy inline TOML remains valid:
`persistence = { timeout_secs = 120, max_entries = 10000 }`.
Optional fields `ipv4_prefix`, `ipv6_prefix`, `refresh_on_use` and `kind` are also
available inline. Names in the portal have suggestions from the current draft.

## Stateless source hash

Select Source hash as the profile method (`kind = "source_hash"`). It hashes the
masked source key using stable FNV-1a over its address bytes and selects among
eligible members. This overrides the virtual server/pool's balancing algorithm.
It has no persistence records; timeout and capacity must both be zero. Member
availability/order changes can change mappings. The legacy `source_hash`
balancing algorithm remains available independently.

## Live records

Refresh records on the Persistence Profiles page to inspect masked source keys,
member addresses and remaining deadlines. The response includes a total count
and up to 1000 sampled records per virtual server, sorted within that sample.
Expired records are pruned during inspection. Clear records removes that virtual
server's table immediately and writes an audit entry. Future connections can
select a new member; established sessions continue. This action is independent
of draft Save and apply.

- `GET /api/v1/persistence`: authenticated snapshots with profile/effective settings.
- `POST /api/v1/persistence/{virtual_server}/clear`: authenticated, mutation-header
  protected, audited clearing.

Ordinary apply creates new affinity tables for new traffic, including named
profiles. Standalone restart loses in-memory records. HA can replicate asynchronous
source/cookie checkpoints with expiry validation; this does not replicate live
connections. See [HA](high-availability.md). Profiles do not share tables across
virtual servers. HTTP cookie persistence is documented separately under
[cookie profiles](cookie-profiles.md). SSL-session/universal persistence,
destination affinity, cross-service matching and fallback profile chains remain
unsupported.

Tests cover source masks (IPv4/IPv6 including `/0`), fixed/sliding expiry, failover,
draining, bounds, stateless hashing, profile references and actual TLS traffic
creating/clearing records. See `tests/persistence.py`, `tests/certificates.py` and
the Rust runtime/configuration tests.
