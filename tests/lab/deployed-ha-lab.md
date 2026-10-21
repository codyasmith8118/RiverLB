# Deployed three-server HA lab

This is the lab configured and checked on October 13, 2026. It is a deployment
record, not an appliance release qualification or a capacity benchmark. The
generic [qualification plan](../../docs/appliance-test-plan.md) uses different
example addresses; use the addresses below for this deployment.

## Addresses and traffic objects

| System | Management | Internal VLAN 3020 | External VLAN 3010 |
| --- | --- | --- | --- |
| riverlb-test-a | 10.10.2.11 | 10.10.20.10 | 10.10.10.10 |
| riverlb-test-b | 10.10.2.12 | 10.10.20.20 | 10.10.10.20 |
| server-test-1 | SSH through backend address | 10.10.20.11:8080 | — |
| server-test-2 | SSH through backend address | 10.10.20.12:8080 | — |
| server-test-3 | SSH through backend address | 10.10.20.13:8080 | — |
| riverlb-loadgen | 192.168.1.24 | — | Routed client through 192.168.1.1 |
| Floating backend source | — | 10.10.20.100 | — |
| Floating HTTP VIP | — | — | 10.10.10.100:8080 |

Both appliances use eth0 for management, eth1 for internal traffic, and eth2
for external traffic. The backend servers each use a single eth0 with a static
/24 address and gateway 10.10.20.1. No backend address changes were necessary.

The final state is **A active, B standby**, with automatic configuration sync
enabled and synchronized. Each appliance keeps its own local self IPs. The
active appliance alone owns the VIP and floating backend source.

| Object | Configuration |
| --- | --- |
| Nodes | server-test-1, server-test-2, server-test-3; addresses above |
| Monitor | lab-http-health; HTTP GET /healthz; Host lab.example.test; status 200 and body containing OK |
| Monitor timing | Every 2 seconds; 1-second timeout; 2 successful probes to recover, 2 failed probes to go down |
| Pool | lab-web-pool; all three nodes; equal weights; round robin |
| Virtual server | lab-http-vip; HTTP; 10.10.10.100:8080 |
| VLAN selection | Ingress external3010; backend internal3020 |
| Backend source | Named self IP internal-floating, 10.10.20.100 |
| Persistence | Disabled |

Manage the pair at https://10.10.2.11:18090 and https://10.10.2.12:18090.
Traffic configuration changes should be made on the active appliance.
The [load-generator guide](load-generator.md) describes the installed profiles
and results on 192.168.1.24.

## Try the virtual server

Open **http://10.10.10.100:8080/** from a client that can route to the external
traffic network. This endpoint uses HTTP. Each response contains the backend
name, source address seen by that backend, and received request headers. It also
includes an `X-Backend-Node` response header.

HTTPS is also available at **https://10.10.10.100/** through `lab-https-vip`.
Its managed self-signed certificate is `ss-lb-ha-vs-ssl`, with the VIP in its IP
subject alternative names. The certificate assignment is applied and synchronized
to standby. Thirty verified TLS 1.3 requests returned ten responses from each
backend with no errors. Browsers require the self-signed certificate to be trusted
or its certificate warning accepted. Generating a certificate only adds it to
the store: select it under the virtual server's **Client TLS → Managed
certificate** setting and apply the configuration to enable TLS on that listener.

On Windows, use separate curl requests to see the rotation:

```powershell
1..12 | ForEach-Object {
    curl.exe --fail --silent --show-error --max-time 5 http://10.10.10.100:8080/
    Write-Host ""
}
```

From the repository, run a bounded traffic test with the existing generator:

```bash
python3 tests/lab/http_load.py http://10.10.10.100:8080/ \
  --duration 30 --rate 10 --workers 4 --timeout 3 \
  --expect-nodes server-test-1,server-test-2,server-test-3 \
  --output /tmp/riverlb-lab-load-01.json
```

Use a new output filename for each run. The generator opens a new connection
per request. Browser behavior and concurrent requests are not a reliable way
to check strict round-robin ordering.

## Backend services and health tests

Each server runs the repository's [backend.py](backend.py), installed using
[deploy-backend.sh](deploy-backend.sh), as an unprivileged systemd service:

```bash
sudo systemctl status riverlb-lab-backend --no-pager
```

The service is enabled at boot and listens only on that server's backend IPv4
address, TCP 8080. Runtime and permanent firewalld rich rules allow that port
from 10.10.20.10, 10.10.20.20, and 10.10.20.100. Direct HTTP access from other
clients is intentionally not allowed by these rules; use the VIP.

On one backend, deliberately fail just the health endpoint:

```bash
sudo touch /run/riverlb-lab/unhealthy
```

After two failed probes, its node should show down and new VIP requests should
reach only the other two servers. Recover it afterward:

```bash
sudo rm /run/riverlb-lab/unhealthy
```

After two successful probes it should rejoin the pool. The marker lives in
/run and does not survive a reboot.

Other endpoints are `/payload?bytes=4096`, `/?delay_ms=100`, and `/fail`.
The last endpoint deliberately returns HTTP 503; it does not change `/healthz`.

## Automatic firewall provisioning

An initial test found that the HA service's restricted capabilities prevented
it from reading `/proc/1/ns/net`, causing automatic firewalld provisioning to be
skipped. That integration issue is now fixed in both the source and the installed
pair, now running RPM release **1.1.9-20261013223000.el10**.

Both packaged services use systemd's `OpenFile=` to pass a read-only reference
to the host network namespace. RiverLB checks its device and inode against its
own namespace before contacting firewalld. Capability bounds and SELinux
enforcement remain unchanged. Native tests confirmed the guard works in both
service sandboxes and rejects a separate network namespace.

The active appliance automatically maintains this destination-scoped rule in
both the runtime and permanent public-zone configuration:

```text
rule family="ipv4" priority="18600" destination address="10.10.10.100" port port="8080" protocol="tcp" accept
```

The temporary priority-18599 operator rule has been removed from both appliances.
Controlled failover was retested in both directions using only automatic VIP
rules. The standby retains its management allowance and removes its VIP rule
when it relinquishes traffic ownership. Creating and deleting traffic objects
through the active GUI manages their rules; no manual port opening is needed.

## Checks completed

- All three backend services active and enabled at boot; health endpoint 200.
- All three RiverLB nodes, the pool, and the virtual server healthy.
- 300 sequential fresh VIP connections: exactly 100 per backend, no errors;
  every backend saw the floating source 10.10.20.100.
- Backend 2 deliberately unhealthy: marked down; 100 fresh requests split
  50/50 between backends 1 and 3, no errors; all three healthy after recovery.
- Controlled switchover A to B and back to A: exclusive ownership of both
  floating addresses and synchronized configuration verified on each move.
  Five settled-state traffic checks of 60 requests each returned 20 responses
  per backend with no errors, including while B was active.
- Temporary switchover placement constraints cleared; final owner A.
- Firewall fix deployed to both appliances; native standalone/HA sandbox checks
  passed in both host and private network namespaces, with read-only descriptors
  marked close-on-exec and unchanged service capability bounds.
- Automatic VIP rules verified on ports 8080 and 443. A temporary port-8081
  virtual server added runtime/permanent rules only on the active appliance,
  served 60 requests evenly, then removed both rules when deleted.
- After removing the manual firewall workaround, another 300 fresh HTTP VIP
  requests split 100/100/100 with zero errors. Both live security audits passed.
- HTTP byte accounting now includes backend HTTP headers and framing. After
  deployment to both appliances, 100 bodyless HTTP GETs added 11,600 inbound
  bytes and 100 verified HTTPS GETs added 11,100 inbound bytes, with zero
  failures. At 10 requests/s, sampled inbound rates were approximately 9 kbit/s.
  Existing statistics were retained; node-rate display was corrected as well.

The switchover checks verify traffic after each transition settles; they do not
measure outage duration or preservation of existing connections. No new power
fencing, reboot-persistence, soak, or capacity tests were performed in this run.
