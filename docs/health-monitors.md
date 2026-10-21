# Health monitors and application readiness

Local Traffic → Health Monitors creates reusable TCP, HTTP, HTTPS, ICMP, UDP, DNS and TLS monitors.
Assign a monitor in a node, pool, or virtual server with inline members.
A node monitor overrides the pool or inline monitor for that endpoint. Leave
the node monitor blank to inherit the pool check. Enabled nodes with an explicit
monitor are also checked when no enabled virtual server references them; these
checks use the operating system routing table. The node health icon reflects
the result, including for an unassigned node.
Named pools own their monitor; all referencing servers inherit it. Blank names
retain the default TCP check and global timing/threshold settings.

HTTP checks send GET to the configured path (including query string), with the
configured Host header, to each member's IP and port. Exact expected status is
required. Optional response text must occur within the first 64 KiB of the decoded
body. Chunked transfer encoding is supported; compression and redirects are not
followed. Use a readiness endpoint such as `/health` that checks the application's
dependencies, rather than a page that always returns 200.

HTTPS adds verified TLS: the host must be a TLS server name without a port and the
CA certificate path must contain trusted PEM certificates. For a home lab's
private CA, enter its CA certificate path. There is no skip-verification option.
These probes do not enable backend TLS for application traffic; assign a [Server TLS profile](server-tls.md) separately. TCP health checks on a virtual server with a Server TLS profile also verify its backend TLS handshake.

Use **Clone** on a monitor to copy its settings into an independently editable
monitor with a unique name. **Done** returns to the list and keeps edits in the
browser. The yellow **Not yet applied** indicator in the appliance header stays on
until **Save and apply** succeeds, or **Discard and reload** restores the active
configuration; the indicator then turns green and reads **Configuration applied**.
Done does not write or activate configuration. These browser
edits are separate from the saved configuration's HA synchronization state.

| Type | Successful check | Additional settings |
| --- | --- | --- |
| TCP | TCP connection opens (and verifies assigned backend TLS, when configured) | None |
| HTTP | Exact status and optional response text match | Path, Host, status, text |
| HTTPS | Verified TLS plus the HTTP check | HTTP settings, server name, CA PEM |
| TLS | Verified TLS handshake, without sending HTTP | Server name, CA PEM |
| ICMP | One echo reply from the member IP; member port is ignored | None |
| UDP | A datagram response from the member contains the required text | Send text, receive text |
| DNS | A complete successful UDP DNS response contains the requested record type | Query name, record type |

UDP send/receive fields contain literal UTF-8 text, not escape sequences or binary
hex. Both are required and bounded to 4096 bytes. DNS supports A, AAAA, CNAME,
MX, NS, TXT, SOA and SRV. It queries the member's configured IP and port directly;
use port 53 for an ordinary DNS server. It validates the transaction ID, echoed
question, response code, answer bounds and requested record type. Truncated
responses fail; automatic TCP fallback and matching a particular record value
are not supported. The DNS wire format follows
[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html).

ICMP requires `/usr/bin/ping` from `iputils` and permission to send echo requests.
The RPM includes that dependency. The probe uses the same configured source IP
and backend interface as other checks and kills the subprocess on deadline or
cancellation. Linux permission failures appear as probe errors; ICMP monitoring
does not require any TCP service on the member. See the
[ping manual](https://man7.org/linux/man-pages/man8/ping.8.html) for Linux permissions.
TLS and HTTPS require a trusted CA PEM file and verify the configured server name;
TLS certificate errors never count as successful checks.

```toml
[[health_monitors]]
name = "app-ready"
kind = "http"
interval_secs = 5
timeout_ms = 2000
rise = 2
fall = 3
path = "/health"
host = "app.home.example"
expected_status = 200
body_contains = "ready"

# In an existing [[pools]] or inline [[virtual_servers]]:
# monitor = "app-ready"
```

For HTTPS, set `kind = "https"` and `ca_certificate = "/path/to/ca.pem"`.
TCP profiles use the common name, interval, timeout, rise and fall fields only.

The deadline covers routing/source selection, connect, TLS, request and response.
Each enabled virtual server has a probe task. Up to 16 connections are checked
concurrently across the runtime; excess checks queue. A large pool's sweep can
still take longer than its interval. Missed ticks are
skipped. Startup schedules an immediate background sweep without delaying listener activation. Apply commits without waiting for
health responses; background checks begin immediately after activation. Members start down and rise after consecutive successes; consecutive
failures meet the fall threshold. A real backend connection failure still marks
the member down immediately. Checks use the same source NAT/self IP policy as
traffic and do not increment traffic counters. Unused named pools and disabled virtual servers have no traffic probe task;
explicit node monitors continue to check enabled nodes independently.

Overview and `/api/v1/status` expose `last_probe` (Unix seconds),
`probe_latency_ms` and `probe_error` for each member. A last successful probe can
coexist with down health while the rise threshold is still pending; a failed probe
can coexist with up health while the fall threshold is pending. Applying preserves health and streaks for retained members whose backend and
monitoring inputs are unchanged. Changed inputs and newly enabled listeners start
unhealthy until their configured rise threshold is met. Restarting resets health
and streaks. Response bodies are not stored or logged.

Limits: intervals 1–3600 seconds, deadlines 1–60000 ms, thresholds 1–1000,
request paths up to 2048 ASCII bytes, required text up to 4096 bytes, response
headers bounded to 16 KiB. Monitor combinations, passive monitoring, database/mail/directory protocols,
SNMP, SIP and external scripts remain unimplemented.
