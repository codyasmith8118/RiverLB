# Restricted diagnostic packet capture

Status: implementation in progress; capture remains disabled pending prerequisite
delivery and installed qualification.
Updated November 4, 2026 for [task #55](https://github.com/codyasmith8118/RiverLB/issues/55).
The initial selector/header policy and synthetic tests open no sockets and write
no capture files. They do not enable a capture endpoint or lab collection.

## Prerequisites and observed baseline

Task #55 explicitly depends on
[#16](https://github.com/codyasmith8118/RiverLB/issues/16) (privilege separation)
and [#18](https://github.com/codyasmith8118/RiverLB/issues/18) (recent account proof).
#16 is merged at `363e9cf160c43f43cb53da5479f485fd747a4825`; exact merged-commit
RPM qualification and paired review-appliance delivery are still pending.
#18 is implemented in [PR #100](https://github.com/codyasmith8118/RiverLB/pull/100),
with local proof/export/restore tests passing and GitHub CI pending. Neither
prerequisite is claimed complete here.

The installed daemon now runs as `riverlb` with only the bind-service capability.
The root-owned helper authenticates kernel peer credentials and independently
validates delegated operations. #18 adds a one-use, actor/session/action-bound
proof with a 60-second expiry, enforced by the authentication database.

Do not substitute a daemon-spawned shell/tcpdump command, additional daemon
capabilities, an administrator checkbox, or a generic login session for these
prerequisites. Complete their boundaries before activating capture on either
appliance. Their implementation/review must settle the trusted proof-verification
interface; this proposal does not invent an already implemented authority.

## Proposed behavior

An administrator reviews an interface, narrow traffic selector, capture mode,
time/byte limits, retention and sensitive-data warning, then explicitly consents
and provides recent password/MFA proof. Require MFA when enrolled. Bind proof to
the actor, current session, action and canonical capture request; expire it
quickly and consume it atomically once. Reject operators, read-only users,
bearer tokens, revoked sessions and disabled accounts. Starting and exporting
are separate sensitive actions; an old start proof must not authorize export.

Password/MFA proof protects against a stolen browser session. As with #16's
network delegation, the application remains trusted for human authentication;
the helper does not attest human presence against a fully compromised daemon.
The helper independently authenticates its kernel peer and enforces capture
interface, selector, privacy and resource policy. Caller-supplied role flags
never broaden that policy. A compromised daemon could exercise the deliberately
delegated bounded operation, but receives neither a raw socket nor arbitrary
filters, paths, namespaces or commands.

Expose only start/status/cancel/export/delete for opaque capture IDs. Bind start
proof to a canonical validated request, and export proof to the specific capture
ID. Starting and exporting remain separate authorizations.

Initial bounds, subject to installed qualification measurements:

| Resource | Default | Hard maximum |
|---|---|---|
| Duration | 15 seconds | 60 seconds |
| Stored capture bytes, including record headers | 4 MiB | 16 MiB |
| Concurrent jobs | One per appliance | One per appliance |
| Retention after completion | 10 minutes | 10 minutes |
| Structured selector | One exact endpoint address and port, TCP or UDP | One endpoint |

Use one exact unicast IPv4/IPv6 endpoint and port with a TCP/UDP enum. The
address and port must match the same packet endpoint in either direction. Reject
CIDRs, unspecified/loopback/link-local/multicast/reserved addresses, scoped IPv6,
free-form BPF, shell text, offsets, executable options and unknown fields.
The helper uses its trusted traffic-interface registry and independently derived
management network exclusions; requests cannot supply those inventories. Reject
loopback, management interfaces and protected management/SSH/HA ports, including
packets whose opposite endpoint uses a protected port. Stop on interface identity
or address/link changes.

The initial feature supports **headers only**; no payload collection mode.
Store Ethernet (up to two VLAN tags), plain IPv4/IPv6 base headers and the first
20 TCP or eight UDP header bytes. Never store TCP options, transport payload or
Ethernet padding. Drop IPv4 options/fragments, IPv6 extension chains/fragments,
unsupported protocols, malformed lengths and truncated packets. Preserve original
wire length in each PCAP record so deliberate truncation is visible. Tests must
prove actual byte removal, rather than assuming a fixed snap length suffices.
Captures still contain identifiers and traffic metadata; they are neither
anonymized nor suitable for public posting.

The worker must remain separate from the forwarding path. Bound its CPU,
memory, descriptors, execution time, output and queue; drop diagnostic packets
under pressure rather than blocking traffic. Do not enable promiscuous mode or
change firewall, routes, addresses, interface state or traffic ownership. The
main daemon must neither gain raw capture privileges nor receive a capture socket.

Create helper-owned private directories/files (0700/0600), with unpredictable
IDs and no user-supplied output path. Enforce size before writing each complete
record. Cancel/time/size completion must close resources promptly and produce a
valid bounded file; disk exhaustion must fail safely and clean partial output.
Export must reauthorize the actor and return only that job's bounded content;
reject expired IDs, traversal, links, replaced files and cross-user access.
Expiry/delete/reboot cleanup must cover completed, canceled, failed and orphaned
jobs. Audit authorization, start, stop reason, export and deletion without
recording credentials, proof tokens or packet contents.

## Acceptance and evidence plan

| Area | Required positive and negative evidence |
|---|---|
| Authorization | Administrator consent plus valid password/MFA; absent/wrong/expired/replayed/concurrently reused proof; operator/token/disabled/revoked access; action/request/session substitution |
| Helper boundary | Wrong peer, malformed/oversized messages, unknown fields, command/path/filter injection, FD substitution, foreign namespace, forbidden interface and interface replacement |
| Selection/privacy | IPv4 and IPv6; options/extensions/fragments/truncation; effective narrow selectors; management IPv4/IPv6 exclusions and binding changes; actual transport payload/options/padding removal |
| Resource bounds | Sustained offered traffic reaches byte/time limits without exceeding them; cancellation during start/read/write/export; full disk, descriptor pressure, slow clients and worker failure |
| Files/export | Ownership/mode, symlink/hardlink/replacement attacks, cross-job access, separate export proof, valid capture parsing, bounded response and expiry/deletion/reboot cleanup |
| Traffic impact | Matched baseline/capture/recovery traffic runs; record errors, throughput/latency, worker resources and diagnostic drops; measure interruption rather than assume it negligible |
| Installed policy | Packaged helper protocol, systemd sandbox and enforcing SELinux; prove the unprivileged daemon cannot open capture sockets or read capture storage directly |

Current pure tests: `python3 tests/capture_policy.py` (five passed) and
`python3 tests/capture_file.py` (six passed). They cover
selector/interface/management exclusions, forbidden inputs and bounds, IPv4/IPv6
TCP/UDP with zero/one/two VLAN tags, reverse endpoint matching, actual payload/
option/padding removal, malformed/truncated packets and deterministic byte fuzz.
The private PCAP writer additionally proves file ownership/mode, complete-record
byte limits, late-receive deadline/cancellation, unmatched packet bounds, and
cleanup on disk-full, short/zero writes and sync failure. Existing paths/links
are never overwritten. These tests establish no operational socket worker,
retention/export or traffic-impact qualification.

Use private synthetic payloads and disposable interfaces for fixtures. Run actual
IPv4/IPv6 capture/export and traffic-impact checks on an isolated installed
platform after the prerequisite architecture is qualified. Coordinate with the
EVE fixture's supported addressing; do not infer IPv6 qualification from an
IPv4-only VIP run. Do not collect unrelated EVE labs or real management secrets.

Retain the exact source, qualified artifact identity, helper/tool/kernel versions,
commands, expected/actual results and redacted measurements. Do not commit raw
captures, keys, proof material, credentials or VM disks. Run relevant regressions
and exact-commit GitHub CI/security/RPM qualification, then follow the
[paired development delivery procedure](../development-lab.md). A design review,
fixture result or generic HTTP smoke test alone does not complete #55.
