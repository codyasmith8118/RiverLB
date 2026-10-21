# Traffic statistics

Use **System → Statistics → Refresh traffic**. Summary cards show virtual-server totals. Select virtual servers, pools, members or nodes, then choose **Connections**, **Traffic**, **Failures** or **Latency** to see a focused table. Filter names without losing the selected view during automatic refreshes every three seconds. Aligned numeric columns use compact byte/rate units; latency cells show the average, minimum–maximum range and sample count. A dash means unavailable or no samples. Select a virtual server for its stored throughput history chart. Green is inbound; blue is outbound. The first refresh has no rate until a second snapshot is available. Prometheus output is under an expandable section.

## Counter meanings

**Virtual-server total** counts accepted client TCP sockets, including those later rejected. **Rejected** means the global connection limit was full or no healthy, undrained member was available. **Current** counts reserved sessions through handshake, connect and transfer; **Peak** is the greatest concurrent reserved-session count. **Member total** counts reservations, including failed TLS/backend connects. Monitor probes are not counted as client traffic. Completed means the copy finished normally; failures include TLS, backend connection, transfer errors and session timeouts.

For TCP and UDP, bytes count application data accepted by backend/client socket writes while sessions are live, including bytes from sessions that later fail. Inbound means client → backend; outbound means backend → client. They exclude TLS framing, TCP/IP headers, retransmissions and queued data not yet written. Packet counts are deliberately absent: a TCP stream read/write is not a network packet. Client-side and server-side wire-level counters require a separate kernel instrumentation implementation.

For HTTP proxying, byte counters meter the plaintext backend connection: request
bytes written toward the backend and response bytes read from it. They include
HTTP start lines, headers, body/chunk framing, and upgraded WebSocket data, with
each byte counted once. GET requests therefore produce an inbound rate even
without a request body. These are backend-leg application counters; headers
rewritten toward the client and locally generated RiverRule responses are not
client-interface wire totals. TLS handshake/record overhead and health probes
are excluded. Earlier builds counted only HTTP bodies, so GET-only tests showed
zero inbound bytes. Existing totals/history are retained across the fix; older
samples cannot reconstruct omitted headers. Reset statistics explicitly if you
need a clean comparison using the corrected definition.

Named-pool totals sum counters from referring virtual servers. Shared runtime pool state is still per virtual server; member rows retain that context. A sum of independently observed peaks is not a concurrent pool peak, so pool peak is displayed as unavailable. Member rejection is also unavailable because rejection precedes member selection.

Counters follow virtual-server names and member endpoints across apply and restart, including sessions still using an older runtime generation. New or renamed objects start new totals. Current connections are live gauges and start at zero after restart; historical peaks remain. Snapshots are approximate concurrent readings, not an atomic packet accounting ledger. Rates and history charts never bridge configuration revisions or runtime epochs and do not turn reset counters into negative rates. HTTP request counts, packet counters and connection tables remain unsupported. System Health provides a separate interface inventory/error view; it is not packet-level traffic accounting.

## History and API

The Rust database stores virtual-server aggregate samples every five seconds, independently of traffic I/O. Retention is at most seven days and 20,000 global samples, whichever is smaller; the API returns the latest 300 in chronological order. History survives restarts, with epoch boundaries separating rate calculations. The latest checkpoint also stores member counters and latency measurements for restart recovery. Checkpoints are written every five seconds and after shutdown draining; an abrupt crash or power loss may lose the last five seconds. Older samples without member counters cannot reconstruct those counters. Sampling errors are logged without stopping traffic. History timestamps use Unix seconds and display in the browser's local time. Database migrations retain compatible traffic samples and certificate assets; see [storage and upgrade behavior](security-and-database.md).

Authenticated endpoints:

- `GET /api/v1/statistics`: revision, runtime epoch, virtual-server/member snapshots and named-pool aggregates.
- `POST /api/v1/statistics/reset`: reset all traffic counters, latency measurements and history; authentication and the management request header are required. Active connections continue and live gauges remain accurate. The reset is committed to the database and audited.
- `GET /api/v1/statistics/history`: timestamped virtual-server aggregate samples.
- `GET /metrics`: existing member metrics plus virtual connection total/current/peak/rejected and live bytes-in/out counters.

History is included in a full stopped-database backup, but not in configuration JSON export. There is no per-packet SQL access, automatic archive export or packet capture. See [database backup/security](security-and-database.md) and [Prometheus](monitoring.md).

## Latency and reset

Virtual servers, named pools, members and nodes show average, minimum, maximum and sample count for backend connect, backend response and health checks. Backend response means HTTP response headers or the first UDP response in a flow. Object lists/detail pages and the overview also show average and maximum latency. Health monitor pages aggregate probe latency from their attached virtual servers. Backend connect includes TLS when enabled; HTTP response-header time runs from backend exchange start through connection, upload and the first response headers. Successful connects/responses contribute traffic latency samples; health-check duration includes both successful and failed probes. Streaming and WebSocket response-header latency measures the handshake, not the duration of the stream. Pure TCP has connect latency and no HTTP response-header measurement. Unused objects show no samples rather than zero latency. Pool/node averages are weighted by sample counts across referring member instances.

Use **System → Statistics → Reset statistics** to clear counters, latency samples and history globally. The button confirms the scope before resetting. Connections and configuration remain in place. Fresh health checks and traffic create new samples immediately. Prometheus exports per-virtual-server and per-member latency sums (seconds) and sample counts for computing windowed averages; explicit reset decreases counters and changes the statistics rate epoch. Histograms/percentiles are not measured.

After reset, sessions accepted earlier can complete later, so completed totals may temporarily exceed accepted totals in the new statistics period.

## UDP flow counters

UDP virtual servers reuse session counters for client IP/port flows. Normal idle
expiry increments completed; queue/capacity drops increment rejected. Byte counts
measure forwarded payloads. Connect latency is UDP socket setup, and response
latency is the first response in a flow. Neither is a UDP handshake or a DNS
transaction histogram. See [UDP flow behavior](udp-load-balancing.md).
