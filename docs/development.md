# Development and tests

RiverLB builds on Linux and WSL. Use a native Linux Rust toolchain; the application
uses Unix signals and Linux networking interfaces. Work from the repository root.

## Set up a development machine

Install Rust with rustup, including `rustfmt` and `clippy`. The RPM builder uses
Rust 1.92.0; CI currently follows stable Rust. On Ubuntu or Ubuntu WSL, install
the other development dependencies with:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libclang-dev python3 openssl iputils-ping nodejs node-jsdom
```

Keep the checkout and Cargo output on the Linux filesystem in WSL for faster
builds. You may set `CARGO_TARGET_DIR` to another build directory. Python socket
fixtures use the debug binary there, so rebuild before running them.

For local startup and account creation, follow the [source quick start](../README.md#run-from-source).
The GUI is embedded in the binary; there is no frontend build step. Rebuild and
restart the daemon after editing `web/` files.

## Check a change

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 scripts/check-docs.py
python3 tests/smoke.py
python3 tests/configuration.py
node --check web/app.js
node tests/portal.cjs
```

These checks cover formatting, lints, Rust behavior, local documentation links,
real TCP forwarding, configuration transactions and DOM behavior. DOM tests do
not verify actual browser layout. See the [UI review](ui-review.md) for layout checks.

`Cargo.lock` is committed. Change dependencies deliberately and review their
licenses and advisories before releases. Use `cargo doc --locked --no-deps` for
Rust API documentation.

## Choose the relevant integration tests

The [CI workflow](../.github/workflows/ci.yml) is the authoritative list of automated
checks. Start with the tests for the behavior you changed:

| Area | Test commands |
|---|---|
| Apply and recovery | `python3 tests/configuration.py`, `python3 tests/confirmation.py` |
| TCP, admission and balancing | `python3 tests/smoke.py`, `python3 tests/priority_capacity.py`, `python3 tests/draining.py` |
| UDP data plane | `python3 tests/udp.py` |
| Health monitors | `python3 tests/monitors.py`, `python3 tests/datagram_monitors.py` |
| HTTP and policies | `python3 tests/http_rules.py`, `python3 tests/rule_catalog.py`, `python3 tests/home_features.py`, `python3 tests/domain_routing.py` |
| Persistence | `python3 tests/persistence.py` |
| TLS and renewal | `python3 tests/certificates.py`, `python3 tests/device_certificates.py`, `python3 tests/server_tls.py`, `python3 tests/acme.py` |
| Accounts and authorization | `python3 tests/security.py`, `python3 tests/admin_accounts.py`, `python3 tests/auth_release.py` |
| Statistics and operations | `python3 tests/traffic.py`, `python3 tests/operations.py`, `node tests/statistics.cjs`, `node tests/operations.cjs` |
| GUI appearance and lifecycle | `node tests/appearance.cjs`, `node tests/release.cjs` |
| Packaging workflow | `python3 tests/appliance/build_workflow.py`, `python3 tests/build_release.py` |
| Lab tools | `python3 tests/lab_tools.py` |

Python fixtures use the standard library, temporary configurations and isolated
loopback sockets. Authentication tests create real temporary administrators; there
is no authentication bypass. TLS fixtures require OpenSSL. ICMP fixtures require
`ping`. ACME tests use a private local fixture and do not contact a public CA.

## Test Linux network changes

Managed network tests require root or the relevant capabilities, `unshare` and
iproute2. Run them in disposable namespaces, as CI does:

```bash
sudo unshare --net -- bash tests/network_namespace.sh
sudo unshare --net -- bash tests/nat_namespace.sh
sudo unshare --net -- python3 tests/two_arm.py
sudo unshare --net -- python3 tests/two_arm.py --tagged
sudo unshare --net -- python3 tests/confirmation_network.py
sudo unshare --net -- python3 tests/ha_failover.py
```

The namespace harnesses isolate interface/address changes. They do not qualify
real switch connectivity, host firewalld, SELinux or platform fencing. HA fixtures
exercise traffic failover with controlled cluster inputs; a real two-appliance
cluster still needs the [deployment test plan](appliance-test-plan.md).

## Before submitting or releasing

Document changed behavior, configuration and failure modes. Add regression tests
that exercise observable behavior, including rollback where relevant. Keep the
[feature matrix](parity.md) accurate and record major design decisions under
[decisions](decisions/). Avoid claiming interoperability from matching feature names.

For slower packaging and VM qualification, use the [build guide](../appliance/README.md)
and [release checklist](release-readiness.md). A successful unit or container run
does not qualify an appliance image.
