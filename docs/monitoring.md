# Statistics and Prometheus

Use **System → Statistics** for live traffic, failure and latency tables, plus
stored history. Refreshing statistics does not discard traffic configuration drafts.
See [traffic statistics](traffic-statistics.md) for counter and reset semantics.

## Connect a collector

`GET /metrics` serves the
[Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/)
on the configured management listener. It uses the same source restrictions,
Host checks and authentication as the API.

Create an expiring **Monitoring** API token under Management Security and configure
your collector to send it as `Authorization: Bearer …`. Protect the collector's
credential file and replace the token before expiry. A signed-in session cookie
also works, but its absolute and idle expiry make it less suitable for unattended
collection. Unauthenticated scrapes return 401. Use certificate verification for
HTTPS; the request Host must match an accepted management IP/port or localhost.
See [token scopes](security-and-database.md#management-security).

## Metric families

| Metric | Type | Meaning |
|---|---|---|
| `riverlb_config_revision` | Gauge | Saved configuration revision |
| `riverlb_member_healthy` | Gauge | Current monitor health: 1 up, 0 down |
| `riverlb_member_active_connections` | Gauge | Active member sessions |
| `riverlb_member_completed_sessions_total` | Counter | Normally completed sessions |
| `riverlb_member_failures_total` | Counter | Backend/session failures |
| `riverlb_member_bytes_to_backend_total` | Counter | Forwarded application bytes toward backends |
| `riverlb_member_bytes_to_client_total` | Counter | Forwarded application bytes toward clients |

Member series have `virtual_server` and `member` labels. Virtual-server series
include `riverlb_virtual_connections_total`, `riverlb_virtual_connections_current`,
`riverlb_virtual_connections_peak`, `riverlb_virtual_connections_rejected_total`,
`riverlb_virtual_bytes_in_total` and `riverlb_virtual_bytes_out_total`.

Counters survive apply and restart through database checkpoints. Earlier-generation
TCP sessions contribute to the same logical object counters. Explicit statistics
reset decreases cumulative counters and changes the rate epoch. Bytes exclude
wire headers, encryption overhead and retransmissions. UDP session counters describe
client IP/port flows; see [UDP statistics](udp-load-balancing.md).

Capacity series include `riverlb_virtual_admission_active`,
`riverlb_virtual_connection_limit`, `riverlb_member_admission_active`,
`riverlb_member_connection_limit` and `riverlb_member_priority`. Occupancy includes
still-live reservations from older generations. Zero configured limit means unlimited.

## Latency and other health information

`riverlb_virtual_{connect,response_headers,probe}_latency_seconds_{sum,count}` and
matching `riverlb_member_…` series provide latency sums and sample counts. Divide
the rate of sum by the rate of count for a windowed average in seconds. Backend
connect includes TLS. HTTP response timing ends at response headers; UDP uses the
first response in a flow under the existing response metric name. Probe duration
includes failed checks. Histograms and percentiles are not measured.

System Health and Alerts provide local CPU, memory, filesystem, interface and
application health views; see [appliance operations](appliance-operations.md).
Those views are distinct from the traffic Prometheus families. SNMP and packet-level
instrumentation are not implemented.
