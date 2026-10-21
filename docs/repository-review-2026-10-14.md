# Repository review — October 14, 2026

This pass reviewed source organization, the management security boundary,
certificate endpoints, admission counters, storage/backup limits, network source
selection, build tooling, CI and GitHub presentation. It supplements the
[October 11 review](repository-review.md). Targeted code reading and automated
checks do not constitute a line-by-line security audit or appliance qualification.

## Changes made

- Extracted certificate inventory and CSR handlers into
  [management/certificates.rs](../src/management/certificates.rs), removing about
  280 lines from the main management module. Only its router is exposed to the
  parent; the shared source/Host/Origin, authentication, role, standby and pending
  configuration protections still wrap every route. Endpoint behavior is unchanged.
- Added a README status badge and source map, expanded contribution guidance,
  added bug/feature and pull request templates, and documented sensitive reporting
  in the [security policy](../SECURITY.md).
- Expanded the documentation checker to cover source Markdown throughout the
  repository, including deployment guides, root policies and GitHub templates.
  Build output, local hidden state and symlinks are excluded. A regression fixture
  verifies those boundaries.
- Added explicit read-only CI token permissions, a Linux job timeout and
  cancellation of superseded CI runs on the same ref.
- Consolidated the loose root notes into the [offline update guide](offline-updates.md#extract-the-packaged-application).
  The maintained procedure selects an explicit RPM and reads the source version;
  obsolete version examples, machine-specific links and command typos were removed.

## Remaining maintenance and release risks

| Priority | Evidence | Next action |
|---|---|---|
| High | [Logical backups](../src/backup.rs) cap snapshots at 32 MiB and 100,000 rows per table, while [configuration revisions](../src/storage.rs) accumulate without retention. Audit retention can also exceed the snapshot row limit. | Qualify long-lived databases and design explicit archive/retention and pre-limit diagnostics; do not silently remove history. |
| High | The packaged daemon remains privileged; namespace and fixture checks do not qualify actual NICs, SELinux, storage failures or fencing. | Complete the [appliance test plan](appliance-test-plan.md) on final artifacts and intended platforms. |
| High | CI action references use mutable version tags and release candidates are not a production signing/provenance chain. | Establish reviewed action commit pins, dependency/license review, artifact provenance and protected signing/promotion. |
| Medium | Storage, operations, runtime, configuration and the main GUI script still concentrate substantial responsibilities. | Continue cohesive extractions with behavioral tests, prioritizing account transactions, migrations and GUI editors. Avoid a broad rewrite alongside functional changes. |
| Medium | [Automap selection](../src/nat.rs) performs an OS route lookup for each selection. | Benchmark connection/probe load before designing bounded route caching with correct invalidation. |

The [earlier review](repository-review.md#important-remaining-work) records
additional deployment limits. None of these items is represented as fixed by
GitHub presentation changes.

## Verification

- `cargo build --locked`: passed.
- `cargo test --locked`: 96 passed with local socket access. The initial sandboxed
  run passed 89 and failed seven because socket creation was prohibited; the
  rerun resolved those environment failures.
- Certificate/CSR and device-certificate integration fixtures, management security,
  three forwarding algorithms, and configuration transaction fixtures: passed.
- Documentation checker fixtures: three passed; repository local links passed.
- Release packaging, ISO workflow, service hardening and installer branding
  fixtures: passed. Update-helper recovery suite: 25 passed.
- Syntax checks: 66 Python files and 16 shell scripts passed.
- Tracked-file scan found no private-key PEM headers or AWS access-key patterns
  and no files over 1 MiB. This is a narrow hygiene check, not a complete secret scan
  or review of Git history.

Rustfmt, Clippy and Node are unavailable in this environment, so formatting,
strict lints and JavaScript/DOM tests remain for CI. The full integration matrix,
dependency advisory scanning, browser visual checks, RPM/ISO builds, VM installs,
real fencing and capacity qualification were not run. Existing local build
artifacts and appliance state were preserved. No changes were committed or pushed.
