# Linux networking

RiverLB can provision traffic networking when you apply configuration. Management
networking still needs a working OS-assigned address. Keep console access while
changing interfaces, routes or management settings.

For a complete external/client and internal/backend example, see
[two-arm networking](two-arm-networking.md).

## Network objects

| Object | Purpose | Important details |
|---|---|---|
| Interface | Existing Linux NIC | Read-only inventory in the portal; use actual Linux names |
| VLAN | Logical traffic network on an interface | Untagged maps to the parent; tagged creates an 802.1Q subinterface |
| Self IP | Appliance address on a VLAN | Static IPv4/IPv6 CIDR; supplies subnet and optional backend source |
| VIP | Virtual server's client-facing address | Derived from enabled listeners; normally `/32` or `/128` |
| Route | Next hop for a destination | Static main-table route with VLAN, gateway and metric |

VLAN/device names are 1–15 letters, digits, underscores, periods or hyphens. Tags
range from 1 to 4094. Nested VLANs and multi-port bridging are unsupported. An
external/internal role describes purpose; ingress/backend VLAN selections enforce
socket device binding.

Self IPs reject loopback, multicast and unspecified addresses. They do not provide
general service lockdown: other Linux services bound to wildcard addresses may
also listen there. HA can mark self IPs as floating; see [HA ownership](high-availability.md).

## Automatic managed mode (default)

`serve` provisions networking by default. On a dedicated lab host, for example:

```bash
cargo build --locked
sudo ./target/debug/riverlb serve --config examples/networking.toml
```

First adjust the example's `uplink` parent to the intended interface. The process
needs `CAP_NET_ADMIN`, plus authorization for firewalld changes. Missing privileges
reject the change; RiverLB does not silently save unapplied network objects.
`--manage-network` remains a compatibility flag.

Startup creates network objects before binding listeners. Save and apply prepares
the network delta before committing the database. Preview network changes shows
the planned `ip` operations; execution passes argument arrays rather than shell
commands. A failure runs compensating commands in reverse order. Kernel changes
are not atomic and may interrupt traffic. Rollback failure stops normal operation
and requires console recovery.

Do not edit managed objects with another tool while RiverLB runs. Clean shutdown
removes its managed addresses, routes and tagged devices; parent interfaces and
saved database configuration remain. An unclean exit can leave objects behind.

Startup reuses a tagged device only when name, parent, VLAN ID and protocol match.
Exact configured addresses and protocol-186 routes/rules can also be reused.
Failed startup preserves reused objects; successful startup owns their subsequent
updates and cleanup. Conflicting objects are rejected rather than overwritten.
Standalone mode has no general durable ownership journal for unrelated stale
objects. HA ownership and connectivity confirmation have separate recovery journals;
see [configuration recovery](configuration-recovery.md).

## OS-provisioned mode (explicit opt-out; API name `external`)

```bash
./target/debug/riverlb serve --config /path/to/config.toml --external-network
```

RiverLB saves objects and generates plans but does not change Linux networking
or manage listener firewall rules. Your OS tooling must supply interfaces,
addresses, routes and firewall access before listeners bind. An unavailable address
still rejects startup/apply. This mode suits development or hosts managed by
another provisioning system; it is independent of VLAN external/internal roles.

## Managed virtual IP addresses

Choose the virtual server's **Ingress VLAN** to place its VIP on the right device.
With no selection, RiverLB infers a VLAN only if exactly one configured self-IP
subnet contains the VIP. Ambiguous matches require an explicit selection. With
no selection or match, the address must already exist on Linux.

VIPs use `/32` for IPv4 and `/128` for IPv6; self IPs keep their subnet prefix.
Multiple listeners can share a VIP on different ports or transports. A self IP
also used as a VIP is provisioned once. Removing the last enabled listener removes
its derived VIP. IPv6 provisioning waits for duplicate-address detection.

An `os error 99` bind failure means the requested address is unavailable. Check
the ingress VLAN, provisioning privileges and `ip -br addr`. Provisioning enables
local binding and ARP/NDP; switches and VM adapters must still carry the VLAN.
A packet captured on a VLAN subinterface is already decapsulated, so that capture
need not display an 802.1Q tag.

## Client return routing

Managed mode installs per-VLAN source-routing tables for self IPs and VIPs. Replies
sourced from those addresses use their configured VLAN. Connected subnet routes
and that VLAN's static routes are included. For routed clients, set **IPv4 return
gateway** or **IPv6 return gateway**, or add a suitable route on that VLAN.
An explicit return gateway overrides static defaults in its private table.

A missing route fails instead of falling through to another interface. RiverLB
does not guess a gateway or learn each connection's last-hop MAC. This is routing
by the source address's configured VLAN, not arbitrary ingress-path reflection.
Management's main-table default route remains separate.

Rules use priority 18600 and protocol 186, after local-address lookup. Private
table IDs are stable VLAN-name hashes in the range 1000000–17777215; collisions
are rejected. Earlier administrator policy rules can take precedence. Default
metric 4294967295 is reserved for the unreachable guard. External mode requires
equivalent return routing configured by your OS tooling.

## Managed listener firewall permissions

When managed mode starts with firewalld running, RiverLB creates destination-specific
rich rules for explicit non-loopback management and enabled traffic listeners.
Management uses TCP; traffic rules use each listener's TCP or UDP transport.
Rules use the owning interface's zone, or the default zone if unassigned.
Runtime and permanent rules are updated together.

Changing, disabling or removing a listener removes its owned rules; clean shutdown
also cleans them up. Startup can reuse exact configured priority-18600 rules after
an unclean exit, independently in runtime and permanent scope. Failed startup
preserves reused rules. Other administrator rules remain untouched, and earlier
deny rules can still block traffic.

Wildcard listeners, external mode and other firewall implementations need separate
policy. Assigning a self IP does not grant blanket access to all services.

## API

| Method and path | Result |
|---|---|
| `GET /api/v1/network/interfaces` | Linux interface/address inventory |
| `POST /api/v1/network/plan` | Plan and undo operations for a configuration; no execution |
| `GET /api/v1/config` | Saved config, revision and provisioning mode |
| `PUT /api/v1/config` | Revisioned configuration transaction including network changes |

Dynamic routing, VRFs, multi-port VLANs and arbitrary packet NAT are unsupported.
[Source NAT](source-nat.md) explains full-proxy source selection.
