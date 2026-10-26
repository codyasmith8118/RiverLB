# Live connection and UDP flow inspection

`GET /api/v1/connections` exposes read-only metadata for RiverLB's own live
traffic. It requires an administrator or operator session, or a Read/Configure
token belonging to one of those roles. Read-only accounts and Monitoring tokens
are denied. Existing HTTPS/source/Host/authentication restrictions still apply.
There is no connection termination API or diagnostic action that changes traffic.
No additional destructive action or associated audit policy is introduced.

Use the [HTTPS CLI](management-cli.md), for example:

```sh
riverlb manage --url https://192.0.2.10:18090 --ca appliance-ca.pem \
  --token-file "$HOME/.riverlb-token" connections --protocol tcp --limit 100
```

## Metadata and filtering

The response has `schema: 1`, `snapshot`, `captured_at_ms`,
`configuration_revision`, `snapshot_ttl_ms`, `capacity`, `total`, `rows`,
`next_cursor`, `admission_and_coverage` and `termination_supported: false`.
`total` is the number of matching **observed** rows, not a traffic accounting
counter. Management sessions, health probes and unrelated host sockets are not
indexed. Source addresses are privileged diagnostic data.

Each row contains an ID scoped to this process, virtual-server name, client
IP/port (`source`), protocol (`tcp`, `http`, `udp`), selected backend, state,
age at capture in milliseconds, generation and `previous_generation`.
Generation is a diagnostic runtime identity, not a saved configuration revision.
The snapshot records the saved revision at capture. Old TCP/HTTP sessions can
remain visible after apply until their normal drain/disconnect/timeout ends;
UDP flows follow the existing apply/idle cancellation behavior.

States describe application forwarding, not the kernel TCP state machine:

- `connecting`: accepted flow establishing frontend/backend transport.
- `forwarding`: TCP backend transport or UDP socket is ready. UDP connect is not
  proof of backend readiness; use the existing monitor status for that.
- `http`: an HTTP/1 connection, including idle keepalive or an upgraded tunnel.

TCP/UDP backend observation is `selected_backend`. An HTTP keepalive connection
can select different backends for different requests. Its backend is explicitly
`sampled_last_http_selection`, sampled at most once per second, including the
first selection. It is not a claim that a backend socket is currently open.
`backend_observed_age_ms` identifies sample age; a missing backend can mean no
selection yet. `backend_available: false` means its metadata was busy during the
capture. No request URLs, HTTP Host values, headers, cookies, credentials, packet bytes
or response bodies are collected.

Optional API query filters are exact `virtual_server`, `protocol`, client IP
`source`, backend IP/port `backend`, and `state`. The CLI uses the same names with
hyphens for `--virtual-server`. IPv4 and IPv6 addresses use standard socket/IP
notation. Invalid/unknown filters or page sizes return 400.

## Pagination, limits and retention

- At most 4,096 observations are indexed per appliance, shared across virtual
  servers and configuration generations. Forwarding remains available beyond
  that diagnostic cap. Names longer than 128 bytes are not indexed.
- An observation is created once per admitted flow. TCP/UDP forwarding adds no
  inspection work per packet or copied byte. Registration uses a nonblocking
  lock attempt; full/busy diagnostics skip observation instead of waiting or
  rejecting traffic. HTTP selection samples use an atomic rate gate.
- Snapshots are immutable and created at most once per second globally. Up to
  six snapshots are allocated; each expires five seconds after capture using a
  monotonic clock. New first-page requests can reuse a snapshot younger than one
  second. Consequently even a first-page response may be briefly stale.
- Page size defaults to 100 and is limited to 1..200. A shared fixed window allows
  20 page requests per second across privileged callers. Excess requests return
  429; retry after one second. Diagnostic contention returns 503; back off and
  retry. Configuration/status endpoints retain their existing independent rules.
- Repeat the same filters with the opaque `next_cursor`. Page size may change.
  A changed filter is rejected with 400; expired or previous-process cursors
  return 410. Restart pagination rather than combining different snapshots.
  Numeric flow IDs are not durable identities across restart.
- Ages, states, counts and admission/coverage counters are frozen in a snapshot,
  so churn and apply cannot duplicate or skip rows within that cursor chain.
  An old snapshot may still show a flow that has since closed.
- New captures omit observations marked closed. Capture is concurrent with
  traffic; a flow can disconnect during or after capture. The live
  index is reclaimed once per second; expired snapshots are reclaimed on that
  same maintenance interval. Previously captured metadata can therefore remain
  in server memory for at most the five-second TTL plus one cleanup interval.
  No connection history is written to the database, backup, HA synchronization,
  audit log or disk. Shutdown disables new inspection and clears its caches.

For API pagination, send the returned cursor as the next request's `cursor`
query parameter, URL-encoded, along with the same filters. CLI pagination uses
`connections --cursor VALUE` with the same filter flags. A cursor binds filters
and the process namespace; it is not an authentication credential.

`admission_and_coverage` records fixed-cardinality counters since process start:
global connection-limit rejections, HTTP virtual-server capacity rejections,
no eligible backend/virtual/member capacity, UDP queue/memory rejection, and
observations skipped because of capacity, contention or long names. It never
retains a rejected client's source or packet. These counters survive apply but
reset on restart; they are distinct from persistent traffic accounting counters.
Coverage losses mean this table is a best-effort diagnostic sample. Use existing
[statistics and admission counters](monitoring.md) for complete aggregate totals.

## Verification

`python3 tests/flow_inspection.py` uses disposable real HTTPS/TCP/HTTP/UDP sockets
and thousands of concurrent flows. It checks cardinality/coverage, forwarding
beyond the observation cap, immutable pagination during churn, filters, expiry,
restart, role/scope denial, payload and credential redaction, rate limits,
admission reasons and apply/drain/disconnect/UDP idle cleanup. It requires a
16,384 descriptor limit and never changes host networking.

Rust regressions cover full/busy registration, bounded churn, immutable cursors,
filter binding, process namespaces, limits and HTTP sample rates. The manual
`tests/flow_inspection_perf.py` benchmark compares a retained baseline and the
candidate on the same host with 3,000 idle connections, both without polling and
with approximately 20 inspection calls/second. Results are local diagnostic
measurements, not appliance capacity or a production performance guarantee. The
benchmark uses authenticated loopback HTTP for diagnostic polling to isolate
inspection overhead; the correctness fixture uses verified HTTPS.
