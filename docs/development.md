# Development and tests

RiverLB builds on Linux and WSL. Use a native Linux Rust toolchain; the application
uses Unix signals and Linux networking interfaces. Work from the repository root.

## Release 2.0 development

Create feature branches from `release-2.0` and target that branch in child-issue
PRs. The complete approved release will later be proposed for `main`. Follow the
[2.0 scope and readiness plan](releases/2.0-scope.md) for dependencies, proposed
support claims, evidence and decisions; a merged planning document is not release
approval. Keep the parent tracker #8 open until the release gates are met.

## Set up a development machine

Install Rust with rustup, including `rustfmt` and `clippy`. The RPM builder uses
Rust 1.92.0; CI uses the same version. On Ubuntu or Ubuntu WSL, install
the other development dependencies with:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libclang-dev python3 openssl iputils-ping
```

Install Node.js 22 for the browser fixtures. Their jsdom dependencies are pinned
in `tests/package-lock.json` and installed with npm, rather than distribution packages.

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
npm ci --prefix tests --ignore-scripts
npm test --prefix tests
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

## GitHub Actions

CI runs on branch pushes, pull requests and manual dispatch. Separate jobs check
Rust and repository policy, Linux integration and network behavior, browser
fixtures, and both Windows PowerShell receivers. Linux jobs use Ubuntu 24.04;
Windows checks use Windows Server 2025. Rust dependencies are cached per job.

The application release workflow runs full CI before building unsigned archives
and qualified AlmaLinux RPMs. Tag names must match the Cargo package version.
RPM qualification is a reusable workflow shared by release, ISO and disk builds.

ISO and disk workflows are manual. ISO builds offer installer, image or both
media types and verify the pinned base ISO checksum. Disk builds additionally
require the protected `appliance-build` environment and a disposable self-hosted
runner labeled `riverlb-kvm`, with writable KVM, Podman and Packer. BIOS and UEFI
qualification run sequentially. Uploads contain unconfigured disks and reports;
VM test overlays and private runtime state are excluded.

Artifacts expire after 7–14 days. These workflows produce candidates; publishing
or signing a production release is a separate operation. Existing release tags
and published assets are unaffected by workflow changes.

Security scans run on pushes, pull requests, manual dispatch and daily schedules.
Run `python3 scripts/check-dependencies.py` and `bash scripts/check-secrets.sh`
from the repository root with network access, plus `npm audit --prefix tests`
after installing browser fixture dependencies. The secret scan helper requires
Linux x86_64, curl and sha256sum. The release workflow requires these security
checks in addition to full CI. See the [source publication gate](release-readiness.md#source-publication-gate).

See [retained inputs and reproducible builds](reproducible-builds.md) for appliance dependency snapshots and clean-build comparisons.
