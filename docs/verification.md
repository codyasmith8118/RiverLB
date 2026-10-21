# Verification record

This is a historical log of individual feature test runs. Test counts, limitations
and environment details describe the recorded run, not the current working tree.
Use the [current CI workflow](../.github/workflows/ci.yml),
[release checklist](release-readiness.md) and [appliance test plan](appliance-test-plan.md)
for current validation requirements.

## Home hosting priorities — 2026-10-05

WSL Ubuntu: formatting, Clippy with warnings denied, 29 Rust unit tests, build and
portal DOM tests passed. New socket fixtures passed WebSocket frames across reload,
incoming TLS, live admission/counters, invalid backend handshake rejection, disabled
upgrades, early streaming response/upload forwarding, known/chunked body limits,
SNI selection/default fallback and protected private backup/staging/offline restore
into a fresh database. Restore's injected SQL failure rolled back database changes;
successful restore revoked sessions. Schema versions 1/2 migrate to 4 in tests.

The private HTTPS ACME fixture passed real HTTP-01 callbacks, multi-domain CSR
signing/issuance, durable account reuse, assigned SNI certificate renewal, management
HTTPS certificate rotation on its existing port, failure/backoff/restart recovery,
backup of ACME credentials and schedule validation. Tests never contact a public CA.

Existing configuration, persistence, priority/capacity, monitor, certificate,
security, backend-TLS, smoke forwarding, drain and traffic-statistics regressions
passed. Isolated managed-network and routed-NAT namespace tests passed. CI includes
the new fixtures. Native-browser visual QA, public-CA deployment qualification,
streaming load/memory benchmarks and broader behavior qualification remain unverified.

## Profiles hub and reusable HTTP profiles — 2026-10-05

WSL Ubuntu validation: 27 Rust unit tests, formatting, Clippy with warnings denied,
build, portal DOM tests and HTTP/server-TLS socket suites passed. Regression suites
for configuration, source persistence, priority/capacity, monitors, certificates,
security, smoke forwarding, draining and traffic statistics passed, as did isolated
managed-network and routed-NAT namespace tests. The NAT backend helper cannot run
standalone: it requires the interfaces prepared by the routed-NAT harness.

New checks cover default/read-only profile lists, create/detail routing and saved
detail URLs, named HTTP reference resolution and validation, hot-applied body
limits, disabled client keepalive, database restart, member-IP certificate matching
and rejection of a private certificate by the built-in system trust bundle.
Native browser visual QA and broader behavior qualification remain unverified.

Date: 2026-10-02. Environment: Ubuntu WSL2, Rust stable 1.99.0, Linux x86_64.

Passed locally:

- `cargo fmt --check`
- `cargo test`: three unit tests for configuration safety and scheduling reservations.
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --locked`
- `python3 tests/smoke.py`: real TCP tests for all three algorithms, forwarding, half-close, concurrent sessions, successful byte counters, health failure/recovery, status CLI, dashboard HTTP response and SIGTERM shutdown.
- `cargo doc --locked --no-deps`

Not yet verified: broader behavior qualification, production throughput, long-duration load, browser visual rendering/accessibility, connection saturation, drain deadline with long-lived sessions, IPv6 integration, security audit and native Linux packaging. No external products test appliance was used; these checks do not establish traffic feature coverage.

## Web configuration update

Added passing `tests/configuration.py` checks for configuration validation, disallowed Host/Origin and missing mutation header, socket-bind rollback, persistence staging failure, stale revisions, live pool replacement with an established session, virtual server add/delete, management address move and persistence across daemon restart. The configuration test also passed with temporary configuration files on `/mnt/d/Git_Repos/RiverLB`, verifying saves on the Windows-mounted project drive. Formatting, unit tests, strict Clippy, build and all existing forwarding smoke tests passed after the update. Portal JavaScript syntax validation passed. Browser automation was unavailable in this session, so visual rendering and interactive browser behavior still require manual verification.

## Virtual-server and networking update

Passed `cargo fmt`, strict Clippy, five Rust unit tests, build, all forwarding smoke tests, configuration integration tests and validation of `examples/networking.toml`. Extended integration coverage includes description edits, disabling/re-enabling listeners, network model persistence, invalid VLAN references, external-mode plan behavior and the embedded JavaScript serving path.

`node --check web/app.js` and `node tests/portal.cjs` passed. DOM tests exercise the Edit action on an existing server, rename/disable/member/algorithm/source edits, networking forms and preview, Save and apply and reload. These tests use jsdom with a mocked API; they do not verify visual rendering in Chrome/Edge.

`tests/network_namespace.sh` passed as root inside a disposable WSL Linux network namespace with a dummy `uplink`. It verified real tagged VLAN creation, self-IP assignment, static routing, proxy/probe source address binding, rollback after a failed listener preparation, live address/route updates and managed object cleanup on shutdown. The host eth0 was not modified. Physical switch trunk ingress/egress, IPv6 kernel integration, host drift, crash recovery, rollback-failure fault injection and broader behavior qualification remain unverified.

## Portal navigation, named pools and monitor thresholds

Added sidebar pages for Overview, Virtual Servers, Pools, Interfaces, VLANs, Self IPs, Routes, Settings & Monitors and Import / Export, with a global draft/apply bar. Seven Rust tests pass, including named-pool reference validation and consecutive probe thresholds. DOM tests pass for navigation visibility, retaining drafts, named-pool assignment and hidden-page validation. API/socket tests verify named-pool updates change backend routing and reject deleting referenced pools. Formatting, strict Clippy and build pass. Actual browser visual rendering remains unverified because the browser automation runtime could not connect in this session. Named pools share definitions, while scheduler/monitor/counter state remains per virtual server.

## Source-address persistence

WSL checks passed: formatting, strict Clippy, ten Rust unit tests, build, TCP forwarding smoke tests, configuration integration tests, JavaScript syntax and portal DOM tests. The new `tests/persistence.py` verifies real TCP affinity reuse, expiry, backend-failure selection and configuration settings after restart. Portal tests verify persistence fields survive Save and apply. Deterministic runtime tests cover sliding expiry, health exclusion and bounded capacity. CI includes the new TCP test. Actual browser visual rendering and broader behavior qualification remain unverified. See [persistence semantics](persistence.md).

## Administrative member drain

WSL formatting, strict Clippy, twelve Rust unit tests, build, forwarding smoke tests, configuration and persistence integration tests, JavaScript syntax and portal DOM checks pass. `tests/draining.py` verifies a named-pool drain applied while a TCP session is established: subsequent sessions select another backend, the old session completes on its original backend, the drain list persists to disk, and removing drain restores eligibility. Runtime tests cover affinity exclusion, all-members-drained rejection and reservation release. Config tests reject duplicate or unknown drain addresses. Portal tests verify named-pool drain settings are saved. CI runs the new integration test. Browser visual rendering and broader behavior qualification remain unverified.

## Weighted round robin

WSL formatting, strict Clippy, fourteen Rust tests and build passed. Unit tests verify 3:1 weighted distribution over 400 selections, health exclusion/recovery and invalid ratio references/ranges. The CI member-drain integration fixture now also verifies a 30:10 distribution over 40 actual TCP sessions through a weighted named pool before checking live drain and restoration. Existing configuration, source-persistence and forwarding regressions pass. JavaScript syntax and portal DOM tests pass, including weighted algorithm selection and saved ratios. Actual browser visual rendering and broader behavior qualification remain unverified. See [weighted balancing](weighted-balancing.md).

## Object details, Rust database, login and HTTPS

This update supersedes earlier TOML staging-file and unauthenticated-management descriptions in this historical verification log. The database is now authoritative after initial TOML import, and all status/configuration/metrics APIs require administrator sessions.

Passed in Ubuntu WSL: formatting, strict Clippy, fifteen Rust tests and build; configuration, source-persistence, weighted/drain and all forwarding integration tests; login JavaScript/app syntax and portal DOM tests. The added database test verifies rollback after a duplicate revision, successful subsequent commit, password reset revocation and session expiry. The security integration test verifies missing-session rejection, public login/favicon, wrong credentials and origin, mutation CSRF checks, invalid TLS preparation rollback, HTTP-to-HTTPS management migration, Secure/HttpOnly/SameSite cookies, trusted TLS virtual-server HTTP traffic, plaintext rejection, database ownership enforcement, password/logout revocation, rate limiting, persistent configuration/revisions/sessions and audit access. It reads the stopped Turso database using Python SQLite and verifies hashed passwords/tokens, then exports configuration through the CLI. Portal DOM tests cover object list/detail URLs, Back to list, retained drafts and TLS paths saved in configuration. CI includes the security test and login-script syntax check.

The root managed-network fixture also passed inside a disposable WSL network namespace: VLAN/address/route creation, source binding, kernel rollback, authenticated web edits and clean shutdown. Host interfaces were not modified.

Chrome/Edge rendering and broader appliance behavior qualification remain open. Backend TLS, ACME scheduling, local roles/MFA and consistent online backup now have repository fixtures; see the linked feature documents for their limits. Setup and constraints are documented in security-and-database.md.

## Live traffic statistics, favicon, automap and SNAT

Passed in Ubuntu WSL: formatting, strict Clippy, seventeen Rust tests and build; new real-socket traffic test; all forwarding, configuration, source-persistence, weighted/drain and HTTPS/authentication integration tests; statistics/app syntax and portal DOM tests. Byte counts are now live application-write counters rather than completed-session-only totals. The traffic fixture confirms bytes while a session remains open, current/peak/total connection accounting, named-pool aggregation, member totals, explicit source-address rotation, Prometheus values and history retained after restart. Runtime epochs bound rate calculations. Storage tests also cover schema-1-to-2 migration while preserving accounts and configuration.

Both guarded root namespace suites passed with disposable interfaces. Existing managed networking verifies kernel rollback and cleanup. The new routed NAT fixture links the RiverLB namespace to a separate backend namespace over a veth pair and verifies the actual observed egress self IP for automap, alternating explicit SNAT sources and clean managed-address removal. Host networking was not changed.

Portal tests exercise source-NAT configuration save, traffic tables, history object selection and SVG chart generation. The generated favicon is an embedded SVG load-balancing symbol served to both the portal and login page. Actual Chrome/Edge visual rendering remains unverified. Packet/HTTP-request counters, floating-IP preference, arbitrary packet NAT, SNAT port accounting and broader behavior qualification remain pending. See traffic-statistics.md and source-nat.md for precise semantics and operational requirements.
# Health monitor and home hosting verification — 2026-10-05

Verified in Ubuntu WSL: formatting, Clippy with warnings denied, 18 Rust unit
tests, locked build, smoke/configuration/persistence/draining/security/traffic
integration tests, and isolated managed-network/NAT namespace tests. New
`tests/monitors.py` passed real HTTP status/body/chunked response matching,
deadline and recovery, bounded body matching, verified HTTPS and hostname
rejection, unsafe configuration rejection, and persisted configuration history
across restart. `node --check web/app.js` and `tests/portal.cjs` passed monitor
editing/assignment, app links and loading a revision into a draft without apply.
Portal verification used DOM automation, not visual browser inspection.

## Managed certificates and persistence profiles — 2026-10-05

Ubuntu WSL verification passed: formatting, strict Clippy, 20 Rust unit tests,
locked build, certificate/security/persistence/monitor/configuration/smoke/drain/
traffic integration tests, portal JavaScript syntax/DOM tests and isolated managed
network/NAT tests. Certificate tests verify schema-2 migration, matching keys,
immutable names, assignment/deletion protection, public export secrecy, real TLS
rotation, managed management HTTPS and restart without original PEM files.
Profile tests verify reference safety, IPv4/IPv6 masks, fixed/sliding expiry,
stateless hashing, record inspection and audited clearing. Certificate/persistence
portal controls were verified with DOM automation; actual browser rendering and
broader behavior qualification remain unverified.

## Server TLS profiles and weighted least connections — 2026-10-05

Ubuntu WSL checks passed: strict Clippy, formatting, 21 Rust unit tests, locked
build, all existing socket/security/certificate/monitor/persistence/draining/
traffic integration tests, JavaScript syntax and portal DOM tests, and isolated
managed-network/NAT tests. New backend TLS fixtures verify trusted TLS traffic,
SNI, untrusted certificate and hostname rejection, complete handshake deadlines,
TLS-to-TLS bridging with source NAT, profile validation, hot apply and restart.
Weighted least-connections tests cover normalized load comparison, rotating
reservations and draining exclusion. Portal tests cover profile CRUD/assignment/
reload and weighted algorithm selection. Actual browser visual rendering,
performance qualification and broader behavior qualification remain unverified.

## Priority groups and reload-safe capacity — 2026-10-05

Ubuntu WSL checks passed: formatting, strict Clippy, 24 Rust unit tests, locked
build, all socket/security/certificate/monitor/TLS/persistence/draining/traffic
integration tests, portal JavaScript syntax/DOM tests and isolated managed-network/
NAT tests. Priority/capacity fixtures verify primary failure/recovery, saturation
opening a backup, drain, virtual/member limits, held sessions across apply and
removal/re-add, decreased limits, durable configuration and cross-generation
Prometheus occupancy. Concurrent admission tests verify the hard bound and slot
release. Portal tests verify named-pool ownership, field editing and reload.
Actual browser visual rendering and broader behavior qualification remain
unverified; policy interactions are documented in priority-and-capacity.md.

## RiverRules and cookie persistence — 2026-10-05

Verified in Ubuntu WSL: formatting, Clippy with warnings denied, 25 Rust unit
tests, locked build, `tests/http_rules.py`, JavaScript syntax/portal DOM tests,
all existing integration suites (smoke, configuration, source persistence,
draining, security, traffic, monitors, certificates, server TLS and priority/
capacity), plus isolated managed-network and routed-NAT namespaces.

HTTP fixtures cover client keepalive, chunked request/response decoding,
conflicting Content-Length rejection, local deny/redirect, conditional rewrite,
header changes, forced member selection, live healthy/full member fallback,
opaque cookie stripping/collision handling, TTL/capacity/clear, HTTPS Secure
attributes, body limits, invalid rules, runtime reload and database restart.
Held HTTP keepalive retains its admission slot across reload. Portal fixtures
verify rule/cookie collection and reload and source-persistence exclusion.
Visual browser QA, broader behavior qualification, streaming, HTTP/2 and backend
connection reuse remain unverified/unsupported as documented in river-rules.md.

## Reusable rules and cookie profiles — 2026-10-05

Verified in Ubuntu WSL: formatting, Clippy with warnings denied, 26 Rust unit
tests, locked build, HTTP/rules integration and portal DOM/syntax tests, all
existing smoke/configuration/persistence/drain/security/traffic/monitor/
certificate/server-TLS/priority-capacity suites, and isolated network/NAT tests.

New fixtures verify built-in/custom cookie profiles, independent cloned
settings, named rule resolution/order/update, cookie-only and rules-only
assignments, rewrite placeholder behavior, learned passive affinity, hash
byte ranges, session/browser/server expiry settings, fixed record expiry,
always-send suppression, explicit member-limit override, unsafe/ambiguous/
dangling-reference rejection and durable restart. Portal fixtures cover
separate pages, default read-only controls, cloning, dropdown assignment,
ordered assignment movement, save/reload and legacy inline migration.

external products encryption formats, live parent inheritance, cross-scope state and HA
mirroring remain pending; native method semantics and the feature inventory
are documented in cookie-profiles.md. Native browser visual QA and broader behavior qualification remain unverified.

The additional release fixtures and qualification gates are listed in [release preparation](release-readiness.md).
