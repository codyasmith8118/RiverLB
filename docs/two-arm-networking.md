# External and internal networks

RiverLB supports a full-proxy deployment with separate client-facing and
backend-facing Linux adapters. VLANs carry an optional `role` of `external`,
`internal`, or `unspecified`; a role describes their purpose. Traffic direction
is controlled by each virtual server's `ingress_vlan` and `backend_vlan`.

## Hyper-V setup

Use the ordinary Hyper-V Network Adapter for each connection. A practical layout
has an independent management adapter, an external/client adapter, and an
internal/backend adapter. An existing management adapter can remain unchanged.

Connect the external adapter to an External virtual switch bound to the host's
LAN adapter. Connect the internal adapter to the network where backends live.
For backend VMs on the same Hyper-V host, use an Internal switch if Windows also
needs to reach them, or a Private switch for VM-only access. Backends on another
physical network need an External switch bound to that network's physical
adapter. Attach backend VMs to the same internal/backend switch. The Linux
adapter's external/internal role is independent of the Hyper-V switch type.
See [Microsoft's virtual-switch setup](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-switch-for-hyper-v-virtual-machines).

Identify adapters using `ip -brief link` and `ip -brief address`, matching MAC
addresses to Hyper-V's VM settings. Linux names vary; do not assume `eth1` and
`eth2`. Untagged networks work without configuring an 802.1Q trunk. If using tags,
configure matching VLAN connectivity on Hyper-V and the physical switch.

## Configure RiverLB

1. Under **Network → Interfaces**, inspect adapters, link state, MTU, MAC
   addresses, assigned addresses, and draft VLAN roles. Select **Configure** to
   edit OS addressing and DHCP. Keep default routing disabled on traffic adapters.
   See [interface management](interface-management.md) for apply/confirmation.
2. Under **Network → VLANs**, create `external` and `internal`, map each to its
   adapter, and choose its role. Leave the tag blank for an untagged adapter.
3. Under **Network → Self IPs**, add a static CIDR address on each VLAN. Use
   non-overlapping subnets for a conventional two-arm deployment. Exclude these
   addresses from DHCP allocation or reserve them appropriately.
4. Add **Static Routes** for off-subnet backends when needed. Connected subnets
   already have Linux routes when their addresses are provisioned.
5. Set the virtual server's destination IP and port. A distinct VIP is provisioned automatically on its ingress VLAN in managed mode. Choose
   `external` as its **Ingress VLAN** and `internal` as its **Backend VLAN**.
   Use **Automap**, explicit SNAT addresses on the internal VLAN, or the default
   proxy source. The default uses the first configured internal self IP matching
   the backend's address family. An explicit source self IP must belong to the
   backend VLAN.
6. Preview the network plan, then **Save and apply**. Existing database
   configurations remain authoritative; editing TOML alone does not replace them.

The complete example is [two-arm.toml](../examples/two-arm.toml). Its addresses
are documentation-only placeholders. Provision the addresses with your OS
tooling, or use RiverLB's default automatic provisioning after adjusting the example:

```bash
cargo build --locked
sudo ./target/debug/riverlb serve --config examples/two-arm.toml
```

Automatic provisioning requires Linux `CAP_NET_ADMIN`. Normal `serve` enables it; `--external-network` opts out when the OS manages the addresses and routes. The daemon only creates tagged VLAN
devices, self IPs, and configured routes. Existing untagged adapters must already
be up. The separate Interfaces editor manages Ethernet profiles through
NetworkManager; traffic configuration does not change DHCP or hypervisor switches.
Managed VIP listeners also provision their firewall rules.
On clean shutdown it removes the objects it created. Keep your management path
independent of those objects. IPv6 setup waits for duplicate-address detection
and rolls back if the address is duplicated or does not become ready.

No new Rust dependencies are required. The implementation uses the existing
Tokio and libc dependencies. AlmaLinux needs `iproute` for `/usr/sbin/ip`:

```bash
sudo dnf install iproute ca-certificates
```

The built-in Server TLS profile uses `system` trust, recognizing Ubuntu/Debian and AlmaLinux/RHEL CA bundle locations. Custom profiles accept `system` or an explicit CA PEM path.

Kernel device binding uses `SO_BINDTODEVICE`. If your kernel/security policy
returns a permission error for this option, the process needs `CAP_NET_RAW` in
addition to any managed-network capability. Ports below 1024 also require
`CAP_NET_BIND_SERVICE`. Apply capabilities to the deployed binary/service, not
to Cargo. Configure management HTTPS and host firewall access for your network.

## Behavior and limitations

An ingress VLAN pins the listening socket to one Linux device. Packets arriving
on other devices cannot reach that listener, even when Linux accepts traffic
for a local address on a different adapter. A backend VLAN pins application
connections and TCP/HTTP/HTTPS health probes to its device and source self IP.
There is no fallback through another adapter if that route fails. Automap's
route lookup includes the selected output device. TCP, HTTP, WebSocket and TLS
backend connections use the shared connection path.

Leaving either selection blank preserves the existing unrestricted ingress or
system-routing behavior. External/internal roles alone do not isolate traffic.
A virtual server can deliberately select an internal VLAN for ingress; the
role is not a security policy. Management binding remains separate from the
virtual-server VLAN selections, and host firewall rules still govern other
services and ports on self IPs.

Changing an active listener's ingress device or tagged-VLAN topology at the same
listen address requires disabling that virtual server and applying first, then
changing it and re-enabling. Alternatively, choose a different listen address.
Role-only edits do not recreate links, addresses, routes, or listening sockets.
Failed listener/device preparation or network changes preserve the saved revision
and run compensating rollback. Network rollback can interrupt active sessions.

This implementation supports one ingress VLAN per virtual server and one Linux
device per VLAN. Multi-port bridges/trunks, VLAN exclusion lists, floating
self IPs/HA, route domains/VRFs, transparent forwarding and self-IP port lockdown
remain unsupported. Static self IPs are not automatically changed when DHCP
changes a management address. Enabled VIP addresses are provisioned as host addresses on the selected ingress VLAN in managed mode. Without an explicit selection, a unique matching self-IP subnet determines the VLAN. External mode requires VIP addresses to be assigned separately.

## Verification

`tests/two_arm.py` creates separate client and backend network namespaces and
veth adapters. It checks IPv4/IPv6 forwarding, internal source addresses for
probes and application traffic, wrong-interface ingress rejection, Automap/SNAT,
hot-apply protection, role-only updates, rollback, duplicate IPv6 rejection, and shutdown cleanup. Run both untagged and tagged traffic fixtures:

```bash
sudo unshare --net -- python3 tests/two_arm.py
sudo unshare --net -- python3 tests/two_arm.py --tagged
```

For a host that enables unprivileged user namespaces:

```bash
RIVERLB_TEST_PARENT_NETNS=$(readlink /proc/self/ns/net) \
  unshare --user --map-root-user --net -- python3 tests/two_arm.py
```

These tests also require `util-linux` for `unshare`/`nsenter`. They refuse to run
in the host network namespace or an already configured namespace.

For routed clients, configure the external VLAN's IPv4/IPv6 return gateway. Managed source-routing rules keep self-IP and VIP replies on that VLAN even when a main-table route selects the internal or management interface. Clients on the external connected subnet do not require a return gateway. Missing routes in the VLAN table are rejected rather than using another interface.
