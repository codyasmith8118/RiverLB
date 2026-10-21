# RiverLB

The existing experimental release **1.0.0** includes the publisher public update trust key in its appliance
RPM and installer ISO. The private signing key is retained separately.
The current source includes later security changes; existing release assets do
not automatically incorporate them.

[![CI](https://github.com/codyasmith8118/RiverLB/actions/workflows/ci.yml/badge.svg)](https://github.com/codyasmith8118/RiverLB/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

RiverLB is an open-source traffic manager written in Rust. It balances TCP, UDP
and HTTP/1 traffic and provides a web interface for configuration, health checks,
certificates, statistics and active/standby operation. The virtual appliance is
based on AlmaLinux. RiverLB source is licensed under MIT; bundled third-party
components retain their own licenses and notices.

**RiverLB is experimental.** Features have automated regression tests, but
production qualification is incomplete. Start with the
[release checklist](docs/release-readiness.md) before planning a deployment.

## Choose your starting point

| I want to… | Read this |
|---|---|
| Install an appliance | [Installation and first boot](docs/installer-experience.md) |
| Run a local development instance | [Quick start below](#run-from-source) |
| Create a pool and virtual server | [Web configuration guide](docs/web-configuration.md) |
| Configure interfaces, VLANs and VIPs | [Linux networking](docs/networking.md) |
| Set up two appliances | [High availability](docs/high-availability.md) |
| Build an installer ISO | [Appliance build instructions](appliance/README.md#build-iso-candidates) |
| Test a deployment | [Appliance test plan](docs/appliance-test-plan.md) and [lab tools](tests/lab/README.md) |
| Find a specific feature | [Documentation index](docs/README.md) |

## Simple build and update instructions

- [Build, share and install a software update](SOFTWARE-UPDATES-README.md).
- [Build an installer ISO and prepare update signing keys](ISO-BUILD-README.md).

## Run from source

Use Linux or WSL with Rust, a C compiler and Python 3 installed. See
[development setup](docs/development.md) for dependencies and tests. Native Windows
binaries are unsupported.

From the repository root:

```bash
cargo build --locked
cargo run -- validate --config examples/riverlb.toml
cargo run -- admin --database examples/riverlb.db --username admin
cargo run -- serve --config examples/riverlb.toml
```

The admin command prompts for a password; there is no default account. Open
<http://localhost:18090> and sign in. The example listens on TCP port 8080 and
expects your backends on `127.0.0.1:8001` and `127.0.0.1:8002`. To run a separate,
self-contained traffic check, use `python3 tests/smoke.py` after building.

**The database becomes the source of configuration after first startup.** Editing
TOML and restarting does not replace saved settings. Use the GUI or the stopped
[import command](docs/operations.md#configuration-and-database) to change them.

This example uses loopback HTTP for local development. Installed appliances use
the console setup wizard to select a management IP, create an administrator and
configure HTTPS. Keep that address stable with a DHCP reservation or static IP;
RiverLB does not automatically follow a changed DHCP address.

## What RiverLB supports

- TCP, UDP and HTTP/1 virtual servers with reusable nodes, pools and health monitors.
- Round robin, weighted round robin, least connections, weighted least connections
  and source hashing, with member draining, priorities and connection limits.
- TLS termination and verified backend TLS, separate device and virtual-server
  certificate stores, CSR/self-signed workflows, SNI and ACME HTTP-01 renewal.
- Source and cookie persistence; built-in, editable-copy RiverRules for HTTP policies.
- Managed Linux VLANs, self IPs, VIPs, return routing and firewalld listener rules.
- Revisioned configuration, account roles, MFA, scoped API tokens, backups,
  persistent statistics, audit events and signed offline standalone updates.
- Two-appliance active/standby operation, traffic configuration sync and floating
  addresses, with operator-provided fencing.

Applying configuration preserves established TCP sessions; UDP conversations
restart. Failover requires clients to reconnect: live TCP/TLS sessions and UDP
flow sockets are not replicated. HTTP/2 processing, QUIC-aware routing, HA rolling
updates and OS rollback remain unsupported. See [feature coverage](docs/parity.md)
for the full scope and [architecture](docs/architecture.md) for implementation details.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Rust daemon, CLI, traffic processing and management API |
| `web/` | Web interface embedded in the daemon |
| `tests/` | Integration fixtures, appliance checks and lab tools |
| `docs/` | Operator guides, architecture and design decisions |
| `examples/` | Sample configurations for local development |
| `packaging/`, `appliance/` | RPM, container and installation media tooling |
| `deploy/ha/` | Cluster services, fencing and deployment helpers |
| `scripts/` | Build, release and repository checks |

## Contributing

Start with [development and tests](docs/development.md) and
[contributing guidelines](CONTRIBUTING.md). Build outputs belong in `target/` and
`dist/`; local databases, private keys and appliance state must stay out of Git
and release packages.

For sensitive reports, follow the [security policy](SECURITY.md).
