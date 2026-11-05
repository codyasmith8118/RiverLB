# Restricted diagnostic packet capture

Status: implemented architecture. Delivery and installed evidence are tracked in
[PR #101](https://github.com/codyasmith8118/RiverLB/pull/101) and
[task #55](https://github.com/codyasmith8118/RiverLB/issues/55).
Updated November 5, 2026.

The implementation includes capture UI/API, action/request-bound proof, a fixed
helper job lifecycle and a separate worker. Installed package/SELinux and
traffic-impact evidence are required alongside source tests; the design itself
does not establish delivery or qualification.

## Prerequisites and observed baseline

Task #55 explicitly depends on
[#16](https://github.com/codyasmith8118/RiverLB/issues/16) (privilege separation)
and [#18](https://github.com/codyasmith8118/RiverLB/issues/18) (recent account proof).
#16 and #18 are complete and delivered on both review appliances. The accepted prerequisite
integration baseline is `b70f96d812dd72b94415756c3387374fe0aaafae`;
[PR #100](https://github.com/codyasmith8118/RiverLB/pull/100) records #18's
actual enforcing-SELinux proof/export/restore qualification and delivery receipt.

The installed daemon runs as `riverlb` with only the bind-service capability.
The root-owned helper authenticates kernel peer credentials and independently
validates delegated operations. Recent proof is one-use, actor/session/action-
bound with a 60-second expiry, enforced by the authentication database.

Do not substitute a daemon-spawned shell/tcpdump command, additional daemon
capabilities, an administrator checkbox, or a generic login session for these
prerequisites. The implemented proof-verification boundary comes from #18 and
is extended with separate canonical-request and capture-ID scopes.

## Capture behavior

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
management network exclusions; requests cannot supply those inventories. The
authenticated server adds its actual management ports as mandatory additional
exclusions; those can only narrow the root policy. A management binding change
stops existing capture before reconfiguration, and capture cannot start during
pending confirmation. Reject
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

Use `/run/riverlb-captures` and per-job systemd runtime directories: reboot,
helper stop and worker exit remove ephemeral files. A worker closes its packet
sockets before a fixed ten-minute retention wait, then deletes its own private
files. The template unit provides independent runtime-directory cleanup and a
hard runtime bound. Cancel uses a private fixed marker checked after setup and during collection,
so stopping before worker readiness still produces a valid empty PCAP; delete/helper stop terminates the worker cgroup and removes output.
Captures are excluded from application backups and HA synchronization.

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
`python3 tests/capture_file.py` (seven passed),
`python3 tests/capture_worker.py` (eight passed) and
`python3 tests/capture_jobs.py` (ten passed). They cover
selector/interface/management exclusions, forbidden inputs and bounds, IPv4/IPv6
TCP/UDP with zero/one/two VLAN tags, reverse endpoint matching, actual payload/
option/padding removal, malformed/truncated packets and deterministic byte fuzz.
The private PCAP writer additionally proves file ownership/mode, complete-record
byte limits, late-receive deadline/cancellation, unmatched packet bounds, and
cleanup on disk-full, short/zero writes and sync failure. Existing paths/links
are never overwritten. The worker source subscribes to link/address events before inventory and
binding, cancels before reading packets when an event arrives, binds a protocol-
zero packet socket only to the selected interface, and drops all remaining
capabilities after setup. Its fixed entrypoint applies CPU/memory/file/descriptor
limits and reads only a private root-owned request for an opaque job ID.
Linux packet-socket receive/drop counters expose diagnostic pressure separately
from stored packet counts. Dropped diagnostic packets are not forwarding drops.
The lifecycle tests include the systemd case where a collected template instance
is not loaded for reset-failed but show reports it as loaded/inactive with zero
main/control PIDs; cleanup accepts that safe state and rejects a running worker.

`tests/capture_worker_network.py` passed actual IPv4/IPv6 TCP/UDP packet delivery,
private PCAP output, payload/options removal, a one-second deadline and zero
remaining capabilities inside a fresh disposable network namespace. It uses
only synthetic veth traffic and replaces trusted management inventory; it does
not test installed broker authorization, SELinux, retention/export, or traffic
impact. For installed results and paired deployment receipts, consult PR #101 and #55.

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

## Implemented resource and export boundary

The template worker keeps only `CAP_NET_RAW` for setup and drops every capability
after opening its bound packet socket. It cannot open Unix IPC sockets or reach
the privileged helper, application database or credential directories. CPU quota,
CPU time, memory, file size and descriptor limits are fixed, separate from the
forwarding daemon. The helper controls only generated capture template instances;
there is no caller-selected unit, executable or signal.

Capture ownership is bound to the current browser session, not merely a reusable
account name. Signing out, session expiry or credential changes make old captures
unavailable to a replacement session; expiry still removes them. Export requires
a separate capture-ID-bound proof, streams bounded chunks under one download
permit held until the response is dropped, checks file integrity and rechecks
account/session validity while streaming. Slow/disconnected clients do not cause
unbounded buffering or extend root file retention.

The helper restricts application peers to the kernel-authenticated main PID of
`riverlb.service` or `riverlb-ha.service`, with PID 1 confirming the fixed account,
host network namespace and namespace restrictions. It does not need ptrace
privileges to inspect another account’s `/proc` namespace links. Root console
peers must share the helper’s network namespace. These checks are independent of
caller-supplied selectors and session ownership.
