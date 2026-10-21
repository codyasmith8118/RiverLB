# RiverLB lab tools

Start with the [full qualification plan](../../docs/appliance-test-plan.md).
These tools target disposable isolated labs, not production workloads.

For the configured 10.10.x lab, see the [deployed HA lab record](deployed-ha-lab.md)
for its actual addresses, traffic objects, test commands, and firewall verification.
The [configured load generator](load-generator.md) has ready-to-run HTTP/HTTPS
profiles, saved results, and monitoring commands.

| File | Purpose |
| --- | --- |
| `backend.py` | Python HTTP/optional HTTPS backend with identity and fault endpoints |
| `deploy-backend.sh` | Explicit systemd deployment on an individual AlmaLinux backend VM |
| `http_load.py` | Bounded offered-rate GET traffic, verified HTTPS, per-request JSONL and summary |
| `loadgen.py` | Named check, HTTP, HTTPS, ramp, soak, payload and failover-observation runs |
| `loadgen.example.json` | Example VIPs, node names and explicit HTTPS trust file for the profile runner |
| `riverlb-functional.toml` | Standalone three-node HTTP object example; validate before adapting |
| `trex_tcp_profile.py` | ASTF raw TCP request/response profile through a full proxy |
| `trex_run.py` | Dedicated-generator API runner; fixed duration/drain and raw counters |
| `trex.example.yaml` | Two physical/four logical port generator configuration template |
| `riverlb-trex.toml` | Separate routed synthetic-backend TCP lab example |

All Python scripts except the TRex files use only the standard library. TRex
requires the matching distribution's bundled `trex.astf.api` and a separately
configured generator. Use `--help` for options. Summary/output files must be new;
use one filename per run. Do not disable TLS verification to make a test pass.
The HTTP client does not retry, retain cookies, reuse connections or follow
redirects. Backend identity is read from `X-Backend-Node`.

The qualification plan describes addresses, firewall rules, warmup/health-probe
handling, results interpretation and cleanup. Neither starter TOML should
replace an installed appliance's management/database configuration.

Run isolated tool integration tests with:

```bash
python3 tests/lab_tools.py
```

TRex profile serialization can optionally be checked with the official client:

```bash
PYTHONPATH=/path/to/trex/scripts/automation/trex_control_plane/interactive \
  python3 tests/lab_tools.py --trex
```

Serialization is an API check, not proof of real NIC connectivity or capacity.
