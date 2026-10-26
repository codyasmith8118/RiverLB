# Task #20 HTTPS management CLI evidence

Implementation source: `20c83b8c1f3c3ae168cc4568961cacf3e64e5d1a` on
`release-2/issue-20-management-cli`, based on `release-2.0`.
[Local source/artifact/platform identities and redacted results](local.json)
identify the exact tested development binary. This record adds documentation;
it does not change that binary's source identity or claim a production release.

## Commands and actual results

| Command | Expected | Actual |
|---|---|---|
| `cargo build --locked --offline` | Build existing locked dependencies | Passed; binary SHA-256 in local.json |
| `cargo test --locked --offline` | No Rust regression failures | 99 passed, 0 failed |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | No warnings | Passed with Clippy 0.1.92 |
| `rustfmt --check --edition 2024 src/main.rs src/management_cli.rs` | Formatted source | Passed with Rustfmt 1.8.0 |
| `python3 tests/management_cli.py` | All CLI lifecycle/security/recovery assertions | Passed; exact result in local.json |
| `python3 tests/configuration.py` | Existing API transaction/traffic behavior preserved | Passed |
| `npm ci --ignore-scripts --no-audit --no-fund` and `npm test` in tests | All six existing portal fixture groups | Passed with current lock, jsdom 30.1.3, Node 22 container |
| `python3 scripts/check-docs.py` and `python3 tests/check_docs.py` | No link/checker failures | Passed |
| `git diff --check` | No whitespace errors | Passed |

Formatting/Clippy used existing extracted development tools; the browser test
used an isolated temporary npm installation and read-only repository mount. The
Node image and exact package-lock digest are retained in local.json. No new Rust
or runtime dependencies were introduced. CI uses the repository's pinned tool
setup and runs the new integration fixture alongside existing API/browser suites.
[Implementation CI](https://github.com/codyasmith8118/RiverLB/actions/runs/40335554855)
records the source-level checks; the associated PR supplies final review/CI.

The CLI fixture starts a real, disposable HTTPS daemon and tests all 13 shared
configuration collections through create/get/list/update/delete. Updates alter
and verify a field; stale local and server revisions fail. CLI status, full
configuration, diff and history match the authenticated API. Validate does not
activate, and rollback creates a new revision. Both private CA trust and SAN
verification are required; HTTP, unknown CA, wrong SAN, URL credentials and
unsafe credential files fail.

Configure, read and monitoring tokens retain their server scopes. A read-only
session cannot mutate configuration. MFA enablement revokes old authentication;
login requires a valid code, recovery codes are single use, and expired session
activity remains expired after restart. Login, session logout, explicit
confirmation/revert and an interrupted-confirmation restart are exercised.
The expiry fixture edits only its own stopped database and closes its SQLite
connection before restarting; no production timeout or lock is bypassed.

Captured stdout/stderr under `RUST_LOG=trace`, help and both shell completion
formats contain no fixture password, session, token, MFA secret or recovery
code. The API client omits dependency trace initialization and emits fixed error
categories without reflecting server error bodies. A malformed-response Rust
regression checks protocol failure instead of panicking.

These are local HTTPS, API and DOM parity checks, not provider/guest appliance
qualification or a real-browser accessibility claim. No host networking,
existing accounts or installed appliance state were modified. See the
[CLI contract](../../management-cli.md) and
[design decision](../../decisions/003-online-management-cli.md) for command scope,
output/exit schemas and handling of uncertain or unconfirmed mutations.
