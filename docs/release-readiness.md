# Release preparation

For the proposed 2.0 scope, support matrix, dependency order, decisions and final
sign-off gates, see the [2.0 scope and readiness plan](releases/2.0-scope.md).

The nine requested release areas have implementation and regression coverage in the repository. This table distinguishes those changes from the appliance qualification required before a production release.

| Area | Implemented behavior | Verification |
|---|---|---|
| 1. Configuration recovery | Review differences; management/network confirmation; automatic/manual rollback; startup recovery | Confirmation API and real deadline tests; transaction regression fixtures |
| 2. Application updates | Signed offline staging; fixed standalone activation; compatible database rollback; monotonic sequence and recovery history | OpenSSL/Rust signature tests and isolated updater failure fixtures |
| 3. Administration | Administrator/operator/read-only roles; TOTP/recovery codes; idle expiry; source allowlists; scoped expiring API tokens | Auth unit and actual API tests; security GUI fixtures |
| 4. Operations | CPU, memory, disk, interfaces, time, certificate, pool and HA health; alert transitions; HTTPS webhook retries; UDP syslog; redacted support export | Health/transport/restart/redaction API tests |
| 5. Backups | Authenticated encrypted downloads and scheduled backups to an operator-mounted separate filesystem; retention; validate/stage/offline restore | Encryption/tampering, owned retention, staging and restore tests |
| 6. Audit | Search, actor filter, pagination, age/count retention and syslog forwarding; stable monotonic IDs | Database and operations API fixtures |
| 7. Service hardening | Bounded capabilities; restricted filesystems, sockets and syscalls; separate read-only publisher trust; inspectable policy audit | Service policy fixtures and systemd directive verification |
| 8. Installer | Graphical RiverLB installer, native disk choice/confirmation, explicit text fallback; reviewed console setup with retry/back/cancel | Branding/runtime/media structure and first-boot fixtures |
| 9. Branding | RiverLB product identity across portal, login, installer/media labels and console; AlmaLinux platform attribution | Branding fixtures and repository review |

See [configuration recovery](configuration-recovery.md), [offline updates](offline-updates.md), [administration](security-and-database.md), [operations and backups](appliance-operations.md), [service hardening](service-hardening.md), [installer experience](installer-experience.md) and [branding](branding.md).

These changes do not by themselves qualify a production image. The management daemon still runs as root for the current networking/HA integration; the restrictions are concrete limits, not a completed privilege-separated network helper. Backup scheduling requires a real mounted destination and its systemd write permission. UDP syslog is best effort. Live TCP/TLS failover replication, HA rolling software updates and OS rollback remain unsupported.

A release must rebuild the RPM and ISO from the final commit and pass full CI, supported BIOS/UEFI VM boots, graphical installation and recovery, network/firewall/SELinux tests, application update interruption/rollback, and HA fencing/failover tests on the intended platforms. Retained OS/build inputs and clean offline rebuild comparisons are implemented on the 2.0 development branch under #9; see [reproducible builds](reproducible-builds.md). Capacity and extended load testing, dependency/license inventory, protected signing/promotion and signing-key ownership remain release qualification work. Keep the evidence with the artifact manifest; do not label a converted image or unsigned candidate a qualified release.

Isolated KVM qualification under issue #10 passed both BIOS and UEFI build,
boot and interactive installer suites in run
[39880100867](https://github.com/codyasmith8118/RiverLB/actions/runs/39880100867)
for source `7215510e3b44dfb4d2f858f56dcc42b7adbeed25`. The
[retained evidence](evidence/issue-10/README.md) records the exact checks and limits.
This completes the runner/workflow evidence for that source; final release
artifacts still require the broader qualification and signing gates above.

## Source publication gate

Issue #11 adds [software inventories and signed provenance](software-supply-chain.md)
to the protected qualification workflow. Its fixture checks and source inventories
do not close the release gate: both firmware jobs must pass the new aggregate
inventory stage and verify their signed bundles for the intended source. Keep
the issue open until that evidence is retained and published.

Source publication is experimental and separate from appliance qualification.
Before changing repository visibility:

- Pass CI and the Security scans workflow on the intended publication commit.
- Scan all reachable history for secrets; keep signing keys and private state outside Git.
- Publish the private contact in SECURITY.md and verify ownership of that mailbox.
- Once public, enable GitHub private vulnerability reporting in repository security settings.
- Keep the experimental warning and prerelease label; do not claim production qualification.
- Preserve bundled third-party licenses and source provenance. RiverLB source is MIT;
  the appliance also redistributes GPL and other separately licensed components.

Recurring OSV checks scan the complete Cargo lockfile, including other targets.
The sole maintenance exception is RUSTSEC-2025-0134 for rustls-pemfile: plan and
validate its migration; other advisory matches fail the check. npm audit checks
browser fixture dependencies. Gitleaks scans reachable history with a narrow
exception for the public RFC 6455 sample nonce. Dependabot proposes weekly Rust,
npm and GitHub Actions updates; each update still requires review and tests.

Existing remote HTTP management must be migrated to HTTPS before installing the
new source build. Published v1.0.0 assets predate this hardening; do not assume
that their signatures mean they contain these later changes. Rebuild, qualify
and sign a new version before distributing these changes as appliance binaries.
