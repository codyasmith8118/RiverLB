# Task #27 bounded flow inspection evidence

Tested implementation source: `b21fa728c684f24c684dde2d54f34c17f5b8bf8d`,
based on `release-2.0`. [Local identity and redacted results](local.json) retain
the exact development binary SHA-256, compiler, host platform and resource bounds.
This evidence record is documentation only and does not change that runtime.

## Correctness, privacy and resource checks

| Command | Expected | Actual |
|---|---|---|
| `cargo build --locked --offline` | Build retained dependencies | Passed; binary identity in local.json |
| `cargo test --locked --offline` | No Rust regressions | 105 passed, 0 failed |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | No warnings | Passed |
| `rustfmt --check --edition 2024` on changed Rust files | Formatted source | Passed |
| `python3 tests/flow_inspection.py` | Real concurrent flows, privacy and bounds | Passed; exact output in local.json |
| `python3 tests/udp.py` | Existing UDP behavior, including IPv6 | Passed |
| `python3 tests/http_traffic.py` | Exact HTTP/TLS/streaming/WebSocket accounting | Passed |
| `python3 tests/management_cli.py` | Existing HTTPS CLI lifecycle/security behavior | Passed |
| `python3 scripts/check-docs.py`, `python3 tests/check_docs.py`, `git diff --check` | No documentation/whitespace failures | Passed |

The socket fixture opened 3,500 TCP connections, 1,200 UDP flows and an HTTP
keepalive connection against real disposable backends. The diagnostic cap stayed
at 4,096 and exposed coverage loss while additional traffic still forwarded.
Immutable cursor pages retained the original row set and ages while connections
closed. Filters, changed-filter rejection, cursor expiry/restart, new/old
configuration generations, explicit rejection counters, UDP idle expiration and
normal disconnect/apply cleanup passed. The verified HTTPS CLI read filtered
metadata from the same protected endpoint.

Unauthenticated requests, read-only accounts and Monitoring tokens were denied;
administrator/operator sessions and eligible Read/Configure tokens worked.
DELETE was unsupported. Exact row-field checks and payloads containing password,
Authorization/Cookie and URL markers demonstrated that snapshots contain no
payload/header/credential values. Six Rust regressions additionally cover cap
exhaustion/churn, nonblocking registration under contention, immutable filter-bound
cursors, page/rate/label bounds, HTTP sampling and process-namespace reuse.

## Local overhead comparison

The [raw benchmark](performance.json) retains every sample, exact baseline and
candidate binary hashes, source commits, poll status/latency and resident/high-water
memory. Command:

```sh
python3 tests/flow_inspection_perf.py \
  --baseline /tmp/riverlb-task27/baseline \
  --candidate /tmp/riverlb-task27/candidate \
  --output /tmp/riverlb-task27/performance.json
```

Both binaries ran on the same host/profile with 3,000 idle TCP connections,
five samples of 1,000 new echoed TCP connections each, and identical backends.
The polling case targeted 20 authenticated diagnostic requests/second and
received 37 successful responses during the measured connection workload.
Polling used loopback HTTP to isolate inspection cost; correctness above used
verified HTTPS. No Rust dependencies or build flags changed.

| Mode | Median new connections/second | Relative to baseline |
|---|---|---|
| Baseline | 2,414.8 | 1.000 |
| Inspection, no polling | 2,372.3 | 0.982 |
| Inspection with polling | 2,246.7 | 0.930 |

Maximum observed poll duration was 13.9 ms. Post-workload resident memory was
161,431,552 bytes baseline, 161,443,840 bytes without polling and 166,998,016
bytes with polling. The approximately 5.3 MiB polled difference is a same-host
observation, not an allocator/RSS guarantee. Fixed cardinality, snapshot/page
limits and nonblocking registration are independently exercised by the tests.

This short debug/Python-backed comparison measures local admission and polling
overhead, not calibrated appliance throughput, statistical performance budgets,
provider/guest qualification or a production capacity guarantee. Extended load
and release qualification remain separate work. See the
[operator contract](../../flow-inspection.md) and
[design decision](../../decisions/004-bounded-flow-inspection.md) for retention,
HTTP sample semantics, coverage loss and the read-only termination policy.
No guest state, captured packets, real client metadata, credentials or keys are
retained here.
