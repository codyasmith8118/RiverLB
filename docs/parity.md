# Feature coverage and remaining work

This page describes RiverLB's implemented behavior and its practical limits.
Implemented does not mean production-qualified. Use the
[release checklist](release-readiness.md) and [test plan](appliance-test-plan.md)
to assess a deployment. The filename is retained for existing links.

## Traffic features

| Area | Available | Main limits or remaining work |
|---|---|---|
| TCP | Opaque forwarding, half-close, incoming TLS, verified backend TLS | Live socket/TLS replication; transparent forwarding |
| UDP | IPv4/IPv6 flows, idle expiry, source binding, datagram monitors, TCP/UDP sharing a port | Flow sockets restart on apply/failover; no DNS-aware profile, DTLS termination or QUIC connection-ID routing |
| HTTP | HTTP/1 request balancing, streaming, WebSockets, bounded header/body processing | HTTP/2 processing, other upgrades, backend connection reuse, compression and caching engine |
| Balancing | Round robin, weighted round robin, least connections, weighted least connections, source hash | Dynamic/predictive methods and sustained scheduling benchmarks |
| Nodes and pools | Reusable service endpoints, node monitors, disable/drain, member priorities and limits | Address-only nodes, aggregate node limits and shared scheduler/capacity across virtual servers |
| Health checks | TCP, HTTP, HTTPS, TLS, ICMP, UDP and DNS; deadlines, rise/fall thresholds and diagnostics | Mail/database/directory/SNMP/SIP/external checks, monitor combinations and dependencies |
| Persistence | No persistence, source address/hash and HTTP cookie profiles; source/cookie HA checkpoints | Live table inheritance on ordinary apply, transport session replication and cross-service affinity |
| Domain routing | Exact Host matches, selected node, default-pool fallback or route-only 404; route HTTPS certificates | Wildcard/path routing and per-route backend/access policies |
| RiverRules | Built-in and custom ordered HTTP match/action rules, copying and validation | General-purpose scripting or arbitrary host code execution |
| Certificates | Device/traffic stores, import, self-signed, CSR, SNI, ACME HTTP-01 renewal | Client/backend mTLS, HSMs, DNS-01/EAB and public-CA qualification |

See [the documentation index](README.md#configure-traffic) for individual feature guides.

## Appliance and management features

| Area | Available | Main limits or remaining work |
|---|---|---|
| Linux networking | VLAN/interface mapping, IPv4/IPv6 self IPs and VIPs, static routes, VLAN return routing, ingress/backend binding, full-proxy source translation | Multi-port bridges/trunks, VRFs, dynamic routing, arbitrary packet NAT and comprehensive self-IP lockdown |
| Firewall | Destination-specific firewalld listener rules for TCP/UDP in managed mode | Other firewall implementations; externally managed/wildcard listener policy |
| HA | Two-node active/standby, Pacemaker/quorum/fencing gates, floating addresses, manual/automatic traffic sync and source/cookie checkpoints | Real platform fencing qualification, synchronous commit, active/active, live connection mirroring and HA rolling software updates |
| Configuration | Revisioned GUI/API, drafts, validation, hot apply, history, import/export and connectivity rollback | Complete management CLI CRUD and online restore activation |
| Accounts | Local roles, MFA/recovery, idle sessions, source restrictions and scoped API tokens | Remote identity providers |
| Visibility | Persistent traffic counters/history, latency aggregates, Prometheus, system health, alerts, UDP syslog and audit search/retention | Latency histograms, packet/connection tables, SNMP and encrypted/reliable syslog |
| Recovery | Private logical backups, encrypted downloads/schedules, staging and offline restore | OS/cluster/external-file backup automation; online restore activation |
| Software delivery | AlmaLinux RPMs, ISO/disk recipes, graphical install, console setup and signed offline standalone updates | Immutable OS repository inputs, protected production promotion, OS rollback and full platform/upgrade qualification |

## Next implementation priorities

Prioritize release qualification and recovery evidence before expanding the
protocol catalog. The current release gates include:

1. Run full CI against the exact source revision used for each artifact.
2. Install and boot BIOS/UEFI candidates on intended platforms; test existing-disk
   confirmation, management recovery, NIC/VLAN behavior, firewalld and SELinux.
3. Exercise real two-appliance fencing, partitions, failover and rejoin.
4. Interrupt application updates and verify rollback/recovery with durable state.
5. Measure capacity, tail latency, resource bounds and extended-load behavior.
6. Complete dependency/license review, SBOM/provenance and controlled signing/promotion.

## Delivery gates

Keep each artifact's source identity, checksums, package inventory and test reports
together. A converted disk format, successful unit run or container smoke test
is insufficient to claim a supported appliance platform. Unsigned development
candidates must stay identifiable as such.

Historical feature test runs are recorded in [verification](verification.md).
Current implementation and pending appliance checks are summarized in
[release readiness](release-readiness.md).
