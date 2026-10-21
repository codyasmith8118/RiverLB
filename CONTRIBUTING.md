# Contributing

RiverLB is experimental. Start with the [architecture](docs/architecture.md) and
[development guide](docs/development.md), which covers dependencies, local startup
and the relevant test commands.

## Report a problem or propose a change

For bugs, include the RiverLB version or commit, installation method, expected
behavior, actual behavior and reproducible steps. Redact logs and configuration:
databases, backups and HA bundles can include private keys and password hashes.
Use the [security policy](SECURITY.md) for sensitive reports.

For larger changes, open an issue describing the problem, proposed behavior and
compatibility impact before implementation. Search existing issues first.

## Prepare a pull request

Keep changes focused and document behavior, configuration and failure modes.
Explain incompatible configuration changes and recovery steps. Run formatting,
Clippy, unit tests and the integration tests relevant to your change; the
[development guide](docs/development.md#check-a-change) lists the baseline checks.
Include commands and results in the pull request, and identify anything untested.
Add behavioral regression coverage for traffic and lifecycle changes.

Prefer small modules with clear ownership, bounded resources and no synchronous
locks held across awaits. Keep endpoint groups beneath the shared management
authentication middleware. Record major architecture changes as numbered decision
documents under [docs/decisions](docs/decisions/).

Document feature support and interoperability only when backed by versioned tests.
Keep the [feature matrix](docs/parity.md) accurate. Generated output belongs in
`target/` and `dist/`; do not commit appliance state or credentials.

This project accepts contributions under the MIT license. Do not include
proprietary code, confidential configurations, credentials or copyrighted manuals.
