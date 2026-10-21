# Repository review — October 11, 2026

This review covered repository organization, operator/developer documentation,
build and CI scripts, and targeted reading of configuration transactions, traffic
lifecycle, health checks, authentication, backups, HA and signed updates. Automated
checks supplemented the reading. It was not a line-by-line security audit or a
new appliance platform qualification.

## Fixes made

| Finding | Change |
|---|---|
| Documentation had accumulated feature announcements rather than a clear starting point | Rewrote the root README and added a [task-based documentation index](README.md) and glossary |
| Core guides contradicted current behavior | Rewrote architecture, operations, portal, first-service, networking, development, monitoring and build/release guides |
| Several feature pages described implemented features as missing | Corrected node monitors, monitoring tokens, cookie/source HA checkpoints, UDP behavior, persistent counters and certificate/schema descriptions |
| Historical results looked like current qualification | Labeled the verification log as historical and separated implemented tooling from pending release gates |
| Release packaging ignored `CARGO_TARGET_DIR` | Package the binary from the directory used by Cargo; test both relative and absolute paths, including spaces |
| Application archive identity omitted dirty state and payload identity | Record dirty state, binary SHA-256 and Cargo.lock SHA-256 in its manifest |
| Application archives reused a repository README with unavailable relative links | Supply archive-specific startup, dependency and artifact-limit instructions |
| Failed compression could truncate an existing application archive | Complete archive/checksum preparation in a temporary directory before replacing the candidate; inject compression failure in a regression test |
| Two test harnesses could use a stale default-directory binary | Make lab-tool and signed-update tests honor `CARGO_TARGET_DIR` |
| Local operations/update sidecars were not ignored | Add specific ignore patterns without deleting local appliance state |
| Documentation had no automated local-link check | Add a dependency-free checker, fixtures and CI coverage; ignore links inside code examples |

Existing documentation filenames remain available so bookmarks and references
continue to work. The main exception is content organization: use the index rather
than reading guides in filename order. Private runtime data and existing release
artifacts were preserved.

## Important remaining work

These are deployment or design issues identified during review, not features
silently enabled by this cleanup.

| Priority | Finding and evidence | Recommended follow-up |
|---|---|---|
| High | Appliance/platform qualification remains incomplete. Namespace HA tests use controlled authority/transport fixtures. | Run [the deployment test plan](appliance-test-plan.md) on intended BIOS/UEFI, NIC/storage, firewalld/SELinux and real fencing configurations; retain reports per artifact. |
| High | Backup size and retained database growth need joint qualification. `src/backup.rs` limits logical snapshots to 32 MiB and 100,000 rows per table; configuration revisions have no retention policy. | Test realistic long-lived databases. Design explicit history retention/archive and size diagnostics before promising recovery at scale. Do not silently discard revisions. |
| High | The managed-network service is still a privileged process. `packaging/rpm/riverlb.service` runs as root with bounded capabilities. | Complete a focused privilege-boundary/security review; qualify the current restrictions and consider a narrow network helper separately. |
| High | Production artifact trust and supply-chain gates are unfinished. CI actions follow version tags, OS repositories move, and candidate archives/RPMs/ISOs are unsigned. | Establish signing-key ownership, protected promotion, dependency/license scanning, SBOM/provenance, reviewed action commits and immutable OS inputs. |
| Medium | Automap performs a route subprocess per connection/probe (`src/nat.rs`). | Benchmark under offered load and evaluate bounded route caching or netlink integration without weakening route-change correctness. |
| Medium | Large modules concentrate unrelated responsibilities: storage, operations, management, runtime and `web/app.js`. | Extract cohesive modules in behavior-preserving changes with existing regressions; prioritize database migrations, account/security endpoints and GUI object editors. |
| Medium | Standalone networking reuses exact configured objects but is not a general durable ownership reconciler. HA and confirmation journals have narrower purposes. | Exercise crash/drift recovery on disposable VMs and specify ownership before broadening reconciliation. |
| Medium | Explicit management addressing and Host protection constrain access. DHCP changes are not followed, and arbitrary DNS aliases are not accepted. | Document reservations/static management addressing; design any hostname allowlist or address-following feature explicitly. |

Live TCP/TLS session replication, UDP flow replication, HA rolling software
activation and OS rollback remain unsupported. Those limits are now stated
consistently in the main guides.

## Validation performed

- Rust regression suite: **85 tests passed**.
- Strict Clippy for all targets: **passed**.
- Release packaging fixtures: custom target paths, fresh binary selection, dirty
  identity, archive/member checksums, private-file exclusion and failed-build preservation.
- Documentation checker fixtures: local files/headings, encoded paths, reference
  links, repeated headings, code examples and repository-escape rejection.
- Lab-tool integration: **5 tests passed**, including actual RiverLB distribution,
  health changes, overload reporting, refused connections and TLS trust/name checks.
- Signed offline bundles: OpenSSL/Rust signature interoperability and rejection
  of tampering, stale sequence, symlinks and unsafe trust permissions.
- All six public top-level example TOMLs validated, including UDP.
- Local documentation links: **231 checked across 49 Markdown files; no errors**.
- Formatting and syntax: Rustfmt passed; 57 Python files, 15 shell scripts and
  13 JavaScript files passed syntax checks.
- ISO orchestration fixtures: stage ordering, archival, failure restoration,
  mode validation and build locking passed.

External websites are not fetched by the documentation checker. Dependency
vulnerability scanning, the entire
CI integration matrix, new browser visual qualification, real TRex capacity tests,
VM installation and real cluster fencing were not performed in this review.

No RPM, disk image or ISO was rebuilt as part of this cleanup. Rebuild from the
intended final source revision and rerun artifact qualification before distributing
new media.
