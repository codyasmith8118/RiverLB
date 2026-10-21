# RiverLB documentation

Start with the guide for the task you are doing. The feature reference pages
explain individual settings; they are not additional installation steps.

## Install or try RiverLB

- [Source quick start](../README.md#run-from-source): run a local instance on Linux or WSL.
- [Install an appliance](installer-experience.md): select a disk, complete console setup and sign in.
- [Application RPMs](../packaging/README.md): install the application separately from an appliance image.
- [Accounts, HTTPS and database](security-and-database.md): first admin, password recovery and management security.

## Configure traffic

Start with [your first pool and virtual server](web-configuration.md). Use the
[portal reference](portal.md) to find pages and understand which changes apply immediately.

| Topic | Guides |
|---|---|
| Backend selection | [Nodes and domain routes](domain-routing.md), [weighted round robin](weighted-balancing.md), [weighted least connections](weighted-least-connections.md) |
| Backend readiness | [Health monitors](health-monitors.md), [draining members](member-draining.md), [priorities and capacity](priority-and-capacity.md) |
| Protocols and application settings | [UDP and virtual-server types](udp-load-balancing.md), [profiles](profiles.md), [RiverRules](river-rules.md), [WebSockets and streaming](home-features.md#websockets-and-streaming) |
| Persistence | [Source persistence](persistence.md), [cookie persistence](cookie-profiles.md) |
| TLS | [Certificate management](certificates.md), [backend TLS](server-tls.md) |
| Networks | [Interface addressing and DHCP](interface-management.md), [VLANs, self IPs, VIPs and firewall](networking.md), [two-arm networking](two-arm-networking.md), [source NAT](source-nat.md) |
| Small hosting deployments | [Home hosting](home-hosting.md) |

## Operate and recover

- [Day-to-day operations and API](operations.md).
- [Statistics and latency](traffic-statistics.md), [Prometheus](monitoring.md).
- [System health, alerts, encrypted backups and audit](appliance-operations.md).
- [Configuration confirmation and recovery](configuration-recovery.md).
- [High availability and configuration sync](high-availability.md).
- [Signed offline application updates](offline-updates.md).
- [Service security and retained privileges](service-hardening.md).

## Develop, build and qualify

- Simple steps: [software updates](../SOFTWARE-UPDATES-README.md) and [installer ISO with update keys](../ISO-BUILD-README.md).

- [Development environment and tests](development.md), [architecture](architecture.md), [contributing](../CONTRIBUTING.md).
- [Configuration apply performance](performance.md), [UI conventions and layout review](ui-review.md).
- [Build and release pipeline](build-and-release.md), [appliance build commands](../appliance/README.md).
- [Appliance test plan](appliance-test-plan.md), [runnable lab tools](../tests/lab/README.md).
- [Release readiness](release-readiness.md), [feature coverage and remaining work](parity.md).
- [Branding](branding.md), [latest repository review](repository-review-2026-10-14.md).

[Verification records](verification.md) describe earlier test runs. They are
historical evidence, not a statement that the current working tree or a downloaded
ISO passed those tests. Architectural decisions are recorded under
[decisions](decisions/).

## Terms used in the guides

| Term | Meaning |
|---|---|
| Node | A reusable backend IP/service endpoint. Nodes can also have their own monitor. |
| Pool | A group of backend members with a balancing algorithm and health settings. |
| Pool member | A backend endpoint participating in a pool, with its own weight, priority and limits. |
| Virtual server | The client-facing IP, port and protocol, plus the pool and processing settings used for that service. |
| VIP | The client-facing virtual IP address. Several virtual servers can share it on different ports or transports. |
| VLAN | A logical mapping to a Linux interface, optionally with an 802.1Q tag. |
| Self IP | An appliance data-plane address on a VLAN, used for local communication or backend source selection. |
| Persistence | A policy that keeps a client associated with a backend across new requests or connections. |
| Draft | Unsaved GUI configuration. Done returns to a list; Save and apply activates the draft. |
| Active / standby | The HA node that owns traffic addresses, and the peer waiting to take ownership. Management remains available on both. |
