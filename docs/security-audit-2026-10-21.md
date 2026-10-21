# RiverLB security audit — 2026-10-21

The highest priority is updating the TLS certificate verifier. The locked Linux dependency graph contains a newly disclosed certificate trust vulnerability. Management availability and enforcement of encrypted management also need attention before broader network exposure.

## Remediation follow-up

The findings below describe the original audit snapshot. Subsequent working-tree
changes address SEC-01, SEC-03 and SEC-04: `rustls-webpki` is locked to `0.103.16`,
sign-in throttling is isolated by source, concurrent password checks are bounded,
and management has connection, upload admission and read deadlines. The OSV query
for `rustls-webpki 0.103.16` returned no advisory matches on 2026-10-21. See
[management resource limits](../SECURITY.md#management-resource-limits) for the
limits and client-visible behavior. The source publication follow-up also addresses SEC-02 by rejecting non-loopback
management without TLS. rustls is updated to 0.23.46 and webpki-root-certs to
1.0.10. Recurring dependency/history scans and pinned actions are now configured.
The original findings below are historical; remaining architecture and appliance
qualification work is described in the release checklist.

Remediation validation: all 98 Rust tests passed, along with the security,
authorization/MFA, backend TLS and signed-update integration suites. New coverage
checks independent source allowances, forwarding-header spoof resistance, limiter
expiry and bounded storage, connection-cap enforcement and recovery, large-upload
admission with health access preserved, and stalled-body expiry. Rust formatting,
diff whitespace and documentation link checks passed.

This is a repository security assessment, not a certification or a completed appliance penetration test. It covers the current working tree, including existing uncommitted changes, based on commit `1bc5ca3a12e9f5d76225d20ddfc27d4a0b6cf018`. Application and deployment files were inspected with particular attention to authentication, authorization, HTTP handling, TLS, secrets, backups, signed updates, privileged operations, HA, packaging and CI. No application fixes were made during this audit.

## Findings

### SEC-01 — High: vulnerable TLS certificate verifier in the Linux build

Evidence: `Cargo.lock:2300` locks `rustls-webpki` to `0.103.15`; `src/server_tls.rs:24` builds backend TLS verification using configured CA roots. The RustSec advisory states that affected verifiers can accept chains through distrusted emSign intermediates whose private keys are publicly known, when the configured trust anchors allow those chains. An attacker able to intercept an affected outbound TLS connection could impersonate its destination. Exposure depends on the actual configured roots; a private CA deployment that cannot chain through these intermediates has a different risk.

Update `rustls-webpki` to at least `0.103.16`, regenerate the lockfile, rebuild, and rerun backend TLS and ACME tests. Validate the appliance CA store as well. Source: [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html). This finding is based on the resolved dependency and advisory; a forged-certificate exploit was not executed.

The scan also matched `webpki-root-certs 1.0.9` against [RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383.html), fixed in `1.0.10`. It is absent from the active host dependency tree and appears under the platform verifier's wasm32 dependency. Treat this as a lockfile/other-target issue rather than a second confirmed Linux exposure.

### SEC-02 — Medium: network management can operate over plaintext HTTP

Evidence: `src/config.rs:822` only checks consistency between the selected protocol and certificate assignment; `src/config.rs:939` accepts a specific non-loopback unicast management address without requiring TLS. `src/control.rs:268` serves plaintext when no management certificate exists. `src/management.rs:122` then issues a session cookie without the Secure attribute.

An administrator can configure network-accessible HTTP management, exposing passwords, MFA codes, session tokens, and private backup responses to a network observer or intermediary. The appliance firstboot path provisions HTTPS, so this is a configuration-policy weakness rather than an assertion that default installed appliances use HTTP.

Require TLS for every non-loopback management address. Retain local development HTTP only on loopback, or require an explicit console-only override. Add validation and integration coverage for rejection of remote HTTP configuration and preservation of HTTPS during configuration changes.

### SEC-03 — Medium: shared login budget allows unauthenticated denial of sign-in

Evidence: `src/management.rs:94` uses one `control.login_budget` for every source and username, allowing ten attempts per minute. Every admitted attempt consumes the same budget, including successful attempts. The existing security integration test confirms that exhausting it returns HTTP 429.

Any client permitted to reach management can repeatedly spend the ten attempts and deny new sessions to all administrators. This does not invalidate existing sessions, and the management source allowlist can reduce exposure.

Use bounded per-source and per-account throttling, together with an aggregate resource budget that preserves availability for other sources. Avoid replacing this with an attacker-triggered permanent account lockout. Test two independent sources to confirm that one cannot exhaust the other's sign-in allowance.

### SEC-04 — Medium: management connections and request bodies lack aggregate admission limits

Evidence: `src/control.rs:247` accepts each management connection and `src/control.rs:268` spawns a task without a semaphore or connection limit. `src/control.rs:1203` sets a ten-second header timeout, but no request-body or total request deadline. The data-plane connection limits do not cover this accept loop. The allowlist and authentication checks run inside the HTTP request handler, after connection acceptance and, for HTTPS, the TLS handshake.

A reachable client can hold many connections or send complete headers followed by a stalled body, tying up descriptors and connection tasks. Header and TLS handshake timeouts reduce some attacks but do not bound overall resource use. Exhaustion shares a process with traffic handling. This was verified by code inspection; destructive load testing was not performed.

Add a separate management connection semaphore, bounded concurrent requests/body buffering, and body-read deadlines. Apply source admission as early as practical. Validate with stalled-body connections and a capped disposable load test, confirming that valid management and traffic requests remain available.

## Dependency scan details

The OSV batch API was queried on 2026-10-21 for all 376 registry package/version pairs in `Cargo.lock`. It returned seven advisory matches across four packages. A lockfile match alone is not proof that the affected feature is used.

| Package | Locked version | Matches | Assessment |
| --- | --- | --- | --- |
| rustls-webpki | 0.103.15 | RUSTSEC-2026-0382 | Active Linux verifier; SEC-01 |
| webpki-root-certs | 1.0.9 | RUSTSEC-2026-0383 | Not in active host graph; update to 1.0.10+ for affected targets |
| rustls | 0.23.45 | RUSTSEC-2026-0346, -0347, -0348, -0349 | Update to 0.23.46+; affected paths not established in this build |
| rustls-pemfile | 2.2.0 | RUSTSEC-2025-0134 | Unmaintained dependency notice; plan migration |

For rustls, the active feature tree enables ring/std/tls12, without Brotli. Inspection found no ECH configuration or custom client session store logging. The ring provider does not offer the hybrid post-quantum key exchange implicated by the downgrade advisory. Consequently these four rustls matches are maintenance items here, rather than four demonstrated exploitable findings. Sources: [session debug output](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [ECH rejection](https://rustsec.org/advisories/RUSTSEC-2026-0347.html), [Brotli allocation](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [key exchange prediction](https://rustsec.org/advisories/RUSTSEC-2026-0349.html), [pemfile maintenance](https://rustsec.org/advisories/RUSTSEC-2025-0134.html).

## Further hardening

- Separate the public traffic process and management handlers from privileged network/HA helpers. Both packaged daemons run as root; HA retains DAC override, ownership and identity capabilities. Existing systemd restrictions reduce impact, but a daemon compromise still exposes substantial authority. This is an architectural consequence, not a discovered remote code execution vulnerability.
- Add a recurring dependency advisory check to CI. Current workflows build and test with a lockfile but contain no advisory scan; a successful test run cannot detect a newly published trust advisory.
- Pin GitHub Actions to reviewed commit hashes and update them automatically. Current actions use mutable version references, including a `stable` toolchain action reference.
- Consider recent password/MFA proof before downloading a raw private backup. The endpoint is administrator-only and audited, but the snapshot contains certificate private keys, MFA seeds and password hashes. A stolen administrator session can currently export it. Encrypted operational backups already exist.
- Add a restrictive Content Security Policy after checking the UI's script/style requirements. Current management responses set no-store, frame denial and MIME sniffing protection, but no CSP.

## Controls observed

The review found Argon2 password hashing, random session/API tokens stored as hashes, role and token scope enforcement, idle and absolute session expiry, MFA replay and recovery-code controls, session invalidation after credential changes, and parameterized database queries in the inspected authentication paths. Management validates Host, Origin and browser fetch context and requires a custom header for mutations.

Updates verify Ed25519 signatures, payload digests, platform, expiry and monotonic sequences. Publisher trust is outside daemon-writable paths. The updater copies the bundle into its protected directory and checks rollback/readiness state. Backups use a defined table inventory and validated restore transaction; encrypted operational snapshots use authenticated encryption. Packaged service policy limits capabilities, writes, syscall groups and socket families. These observations do not establish the absence of other defects.

## Validation and limits

- `cargo build --locked`: passed.
- `cargo test --locked --all-targets`: 96 passed with local sockets enabled. The initial sandbox run had seven permission-related socket/ICMP failures; those all passed in the rerun.
- `python3 scripts/audit-appliance-security.py`: source policy checks passed, with expected root/HA privilege warnings.
- `python3 tests/appliance/service_hardening.py`: passed.
- `python3 tests/updates_helper.py`: 25 passed.
- `python3 tests/ha_hyperv_fencing.py`: 8 passed using local fixtures; no real hypervisor operations.
- `python3 tests/security.py`: passed authentication, browser request protection, logout/password revocation, rate limiting, HTTPS and durable configuration checks.
- `python3 tests/auth_release.py`: passed role, token scope/revocation, source allowlist, TOTP/recovery and idle expiry checks.
- `python3 tests/admin_accounts.py`: passed administrator lifecycle, proof, revocation and audit checks.
- `python3 tests/signed_updates.py`: passed signature interoperability, tampering, sequence and trust/file permission checks.
- `python3 tests/server_tls.py`: passed verified backend TLS/SNI, bridging, timeout, reload and persistence checks.
- `cargo audit` and `cargo clippy` are unavailable in this environment. OSV supplied dependency advisory coverage; no claim is made that Clippy passed.
- A cross-target dependency tree request could not fetch uncached target crates because of restricted DNS. Host feature analysis and local platform-verifier manifest inspection were available.
- A limited source pattern scan found no embedded private key blocks or matching AWS/GitHub token patterns. This was not a full Git history, ignored artifact, database, or binary secret scan.
- No live appliance was supplied. Actual firewall exposure, OS RPM vulnerabilities, effective SELinux enforcement/AVCs, SSH configuration, HA failover/fencing, installed service sandbox behavior, boot media and update recovery on a VM remain unverified. No fuzzing, destructive resource exhaustion, or exhaustive review of every code path was performed.

Prioritize SEC-01, then enforce remote HTTPS and bound management resources. Qualify the resulting build in a disposable AlmaLinux appliance, including HA if used, before treating it as ready for deployment.
