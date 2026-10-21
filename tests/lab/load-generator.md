# Load generator at 192.168.1.24

The configured generator is named `riverlb-loadgen`. Sign in over SSH as `admin`:

```bash
ssh admin@192.168.1.24
riverlb-load check
```

No sudo is needed to generate traffic. The machine uses its existing eth0 and
gateway 192.168.1.1 to reach the traffic VLAN. Its network configuration and
firewall do not need extra inbound ports for these client tests.

## Ready-to-run profiles

| Command | Traffic |
| --- | --- |
| `riverlb-load check` | HTTP then verified HTTPS; 10 requests/s for 10 seconds each |
| `riverlb-load http` | HTTP; 50 requests/s for 30 seconds |
| `riverlb-load https` | Verified HTTPS; 50 requests/s for 30 seconds |
| `riverlb-load ramp` | HTTP; 10, 25, 50, 100, then 200 requests/s; 15 seconds per step |
| `riverlb-load soak` | HTTP; 10 requests/s for 10 minutes |
| `riverlb-load payload` | HTTP; 16 KiB responses; 50 requests/s for 30 seconds |
| `riverlb-load failover` | HTTP; 10 requests/s for 2 minutes while you separately trigger a GUI switchover |

For a custom run:

```bash
riverlb-load http --rate 100 --duration 60 --workers 32
riverlb-load https --rate 100 --duration 60 --workers 32
```

Overrides apply to each phase, including every ramp step. Press Ctrl+C to stop a
run. One profile at a time can run in the default results directory. A failed
phase stops a ramp rather than increasing the offered load. Each phase is capped
at 1,000 requests/s, 64 workers, and 200,000 scheduled requests. These limits and
the modest defaults suit the generator's approximately 1 GiB of RAM. The existing
Python generator is a functional and low-rate test tool, not a wire-rate capacity
benchmark.

The failover profile **does not** change HA state or power off a VM. It records
what clients see while you use the appliance GUI. A failed request or a full
worker queue makes the run report fail; deliberate failover errors remain visible
for analysis.

Convenience scripts also live in `~/riverlb-loadgen/`: `run-check.sh`,
`run-http.sh`, `run-https.sh`, `run-ramp.sh`, `run-soak.sh`, `run-payload.sh`,
and `watch-failover.sh`. They accept the same overrides as `riverlb-load`.

## Targets and HTTPS trust

The root-owned configuration is `/opt/riverlb-loadgen/config.json`:

- HTTP: `http://10.10.10.100:8080/`
- HTTPS: `https://10.10.10.100/`
- Expected responses: `server-test-1`, `server-test-2`, or `server-test-3`
- HTTPS trust file: `/opt/riverlb-loadgen/certs/lab-vip.pem`

The trust file contains only the public certificate assigned to `lab-https-vip`.
Hostname/IP verification remains enabled. No appliance password, management
session, or private key is installed on the generator. If you rotate the VIP's
self-signed certificate, export its new public PEM from the appliance and replace
this trust file after checking its identity. Generating a new certificate does
not automatically update client trust.

The runner opens a fresh connection per request, without retries, cookies, or
redirect following. Backend identity comes from `X-Backend-Node`. HTTP 503,
transport errors, TLS errors, unexpected backend names, incorrect payload size,
and scheduler drops are all reported. Under concurrent traffic, compare backend
totals rather than strict response ordering.

## Results and monitoring

Each invocation creates a new directory under `~/riverlb-loadgen/results/` with
a UTC timestamp, profile name, and unique suffix. It contains:

- `run.json`: profile settings, generator information, phase reports, and outcome.
- A summary JSON per phase: offered and achieved rate, failures, status codes,
  backend counts, latency p50/p95/p99, and scheduler drops.
- A `.requests.jsonl` file per phase: individual request outcomes and timestamps.
- A `.console.log` file per phase: the underlying generator's output.

The terminal prints the results directory and a compact summary. For example:

```bash
jq . ~/riverlb-loadgen/results/<run-directory>/run.json
```

These files contain test URLs and response metadata. Check disk usage before a
long series; results are kept until you remove them.

In a second SSH session, watch the generator rather than assuming all measured
latency or throughput limits come from RiverLB:

```bash
pidstat -rud -C python3 1
sar -n DEV 1
free -m
```

Python, curl, OpenSSL, ApacheBench (`ab`), sysstat, jq, and IP diagnostic tools are
installed. ApacheBench can provide a separate HTTP concurrency sample, for
example `ab -n 10000 -c 32 http://10.10.10.100:8080/`; it sends requests as fast as
responses permit, unlike the profile runner's offered-rate schedule.

The application scripts are installed read-only under `/opt/riverlb-loadgen`.
The [TRex tools](README.md) remain a separate workflow requiring a dedicated
generator/NIC layout described in the [qualification plan](../../docs/appliance-test-plan.md).

## Setup verification

On October 13, 2026, the installed profiles were run as the ordinary `admin`
account from this machine:

| Test | Offered traffic | Outcome | p95 request latency |
| --- | --- | --- | --- |
| HTTP | 20 requests/s for 15 seconds | 300/300; 100 per backend | 13.09 ms |
| Verified HTTPS | 20 requests/s for 15 seconds | 300/300; 100 per backend | 9.66 ms |
| 16 KiB payload | 10 requests/s for 5 seconds | 50/50; exact response size verified | 16.91 ms |

There were no request failures or scheduler drops. These are low-rate functional
samples over the routed client path, not measurements of maximum appliance
capacity. The original JSON summaries and request logs are in the generator's
results directory.
