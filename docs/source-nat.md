# Automap and source NAT

Open **Local Traffic → Virtual Servers**, click the virtual server, and set **Source address translation**. Save and apply stores the policy in the configuration database. Translation belongs to a virtual server, independently of its named or inline backend pool.

- **Default proxy source / legacy self IP:** ordinary Linux-selected proxy source, or the existing named source-self-IP binding. This does not preserve the original client IP at the backend.
- **Automap:** resolve the Linux route for each backend connection, find the egress interface, and bind a configured self IP on that interface. Prefer the route's preferred source if it is one of those self IPs; otherwise choose the first matching configured self IP. Tagged VLANs match their device name; untagged VLANs match their mapped interface. No matching egress self IP means failure, not silent fallback to another address.
- **SNAT address pool:** enter one or more translation IPs separated by commas. New connections rotate through matching-family addresses, independently for IPv4 and IPv6. Each address must already be assigned to the Linux host. Configure them as self IPs in managed mode or provision them externally. Probes use the first matching address and do not advance traffic rotation.

```toml
# Inside a [[virtual_servers]] declaration, choose one:
source_nat = { mode = "automap" }
# Or:
source_nat = { mode = "snat", addresses = ["192.0.2.10", "192.0.2.11"] }
```

Automap requires configured self IPs for every backend address family. Explicit SNAT requires 1–256 unique unicast addresses and coverage of each backend family. An explicit source-NAT policy cannot coexist with `source_self_ip`. The portal clears that legacy selection when saving another mode. Ports are allocated by Linux using source port zero; source-port preservation and custom port ranges are not implemented.

This changes the source of **full-proxy TCP and UDP sockets**, including monitor connections, rather than installing nftables rules or translating arbitrary packets. RiverLB always creates a separate server-side connection. Client-IP preservation, outbound-origin SNAT objects, transparent forwarding, SNAT port-exhaustion accounting and live HA translation mirroring remain unsupported. Established TCP sessions retain their original source after a policy edit; UDP flows restart.

Automap selects configured self IPs on the selected egress network. HA floating address ownership is described in [high availability](high-availability.md).

Automap currently runs bounded `ip -j route get` lookups within the backend connect deadline. This follows Linux routing changes but incurs a subprocess per connection/probe; a netlink route cache and high-rate benchmarks remain future work. Failure to bind a translation address or reach a backend counts as a connection failure and affects reachability monitoring. Multiple translation addresses are not all individually health-tested; verify assignment of every configured address before applying.

`tests/traffic.py` checks actual translated socket sources without host network changes. The guarded root `tests/nat_namespace.sh` creates a disposable backend namespace and veth pair and verifies real routed automap, explicit source rotation and managed address cleanup. Never run the Python namespace fixture against host networking.
