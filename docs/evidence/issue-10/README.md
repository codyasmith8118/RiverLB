# Issue #10 qualification evidence

## Current result: full BIOS and UEFI qualification passed

[Run 39880100867](https://github.com/codyasmith8118/RiverLB/actions/runs/39880100867)
tested source `7215510e3b44dfb4d2f858f56dcc42b7adbeed25` on `release-2.0`
after explicit `appliance-build` review. RPM qualification and both firmware jobs
passed. The downloaded artifacts contained exactly `report.json` and `SHA256SUMS`;
each checksum, source/run/attempt identity, exact stage/assertion lists, locked
inputs, tools identity and artifact hash inventory was verified before retention.

| Firmware | Build/test stages | Boot assertions | Installer assertions | Cleanup | Report |
|---|---|---|---|---|---|
| BIOS | 9 passed | 11 passed | 4 passed | Passed | [JSON](full-39880100867/bios/report.json) |
| UEFI | 9 passed | 11 passed | 4 passed | Passed | [JSON](full-39880100867/uefi/report.json) |

Both used hosted image `20261012.334.1`, kernel `6.17.0-1022-azure`, the same
verified RPM manifest and pinned build inputs. Reports preserve the exact
commands/deadlines, host resources and four artifact SHA256 identities. Verify
copies with `sha256sum -c SHA256SUMS` inside each firmware directory. Original
Actions artifacts are `qualification-<firmware>-39880100867-1` (30-day retention);
these copies preserve the sanitized evidence beyond expiration.

Together with the earlier [negative admission run](#historical-runs-and-fixture-corrections),
actual resource-control probes and the 27 qualification regressions in
[PR #83](https://github.com/codyasmith8118/RiverLB/pull/83), this supplies issue #10's
workflow evidence. Regression checks cover untrusted-ref denial, process-group
deadlines/SIGTERM, report privacy and owned cleanup; the real resource probes
exercise OOM limits and preserve a differently labeled container. A hard GitHub
cancellation can still prevent final cleanup/reporting; hosted-runner disposal
is the final boundary, as the [runbook](../../isolated-qualification.md) explains.

This run qualifies the listed checks for this exact source and artifacts. It does
not establish completed graphical installations, existing-disk upgrades, Secure
Boot, HA/provider qualification, extended load testing, protected release signing,
or production readiness. Later code changes need their own qualification.
No VM disks, private logs, screenshots, sockets, credentials or signing keys are
retained here. Main is unchanged; the broader 2.0 release gates remain separate.

## Historical runs and fixture corrections

Initial negative-run source: `cc3acee8fe0c4d6fbe65a8a271dbf4ed4cfc76a3` on `release-2.0`.
Implementation: [PR #76](https://github.com/codyasmith8118/RiverLB/pull/76).

The [negative run](https://github.com/codyasmith8118/RiverLB/actions/runs/39700106027)
passed both firmware jobs after explicit environment approval. The downloaded
JSON reports were verified against their SHA256SUMS and source identity before
retention here. Both report `status: rejected`, `reason: insufficient-disk`,
`expected_negative: true` and `cleanup: passed`. The measured available disk was
109,199,089,664 bytes (BIOS) and 109,982,515,200 bytes (UEFI), below the intentional
1,073,741,824,000,000-byte requirement. No guests were started in this mode.

- [BIOS report](negative-39700106027/bios/report.json)
- [UEFI report](negative-39700106027/uefi/report.json)

Verify each report with `sha256sum -c SHA256SUMS` from its directory. Original
artifacts are named `qualification-<firmware>-39700106027-1`; Actions retention is
30 days. These copies preserve the sanitized reports beyond that expiration.

The [full run](https://github.com/codyasmith8118/RiverLB/actions/runs/39700108775)
passed RPM qualification and BIOS resource probes, disk installation, boot suite,
and both ISO structure checks. It then failed at `installer-suite`; cleanup
passed. The [BIOS failure report](full-39700108775/bios/report.json) and checksum
were verified before retention. This is partial evidence, not full qualification.

The installer requested `-vga virtio`, but the pinned tools image's real
`/usr/libexec/qemu-kvm -vga help` reports only `none` and `std`. This was reproduced
with the exact image identity in the report, without booting a guest. The fixture
now requests supported standard VGA. A fresh protected run must verify this fix;
passing image boot does not establish passing interactive installer coverage.
Issue #10 remains In Progress.

## Corrected display run: installer qualification still fails

Run [39793312559](https://github.com/codyasmith8118/RiverLB/actions/runs/39793312559)
tested `071d0b0bb2f2bdb64d89e35009f6172e0546775b` with supported standard VGA.
Both firmware jobs passed resource probes, disk installation, all eleven boot
assertions and both ISO structure checks, then failed at `installer-suite`.
Both completed cleanup. Verified reports retain the four artifact hashes,
commands, input identity and actual platform metadata:

- [BIOS failure report](full-39793312559/bios/report.json)
- [UEFI failure report](full-39793312559/uefi/report.json)

These are partial results, not complete guest qualification. The original reports
do not identify the installer case/checkpoint; a later run must verify the probe
corrections and supply allowlisted diagnostic codes if it still fails.

Inspection of the pinned installation runtime's `pyanaconda/display.py` shows
`start_user_systemd()` creates the graphical session bus at `XDG_RUNTIME_DIR/bus`
and sets its address after process startup. The probe now discovers that actual
socket instead of depending on the initial `/proc/.../environ` snapshot. Probe
transport compresses the typed script and waits for an explicit completion marker
instead of assuming the result is available three seconds after submission.
Component regressions use synthetic process metadata, a real local Unix socket
and a delayed local shell response; they are not guest qualification evidence.

## Probe completion timeout on both firmware types

Run [39811444098](https://github.com/codyasmith8118/RiverLB/actions/runs/39811444098)
tested `5d75c95d93d5242d0e9b911b07f845228136199a`. Both firmware jobs
passed the eight stages preceding the installer suite, all eleven boot assertions,
and cleanup. The checksum-verified sanitized reports identify the same failure:
`graphical` / `graphical-summary` / `probe-timeout`.

- [BIOS failure report](full-39811444098/bios/report.json)
- [UEFI failure report](full-39811444098/uefi/report.json)

The completion marker did not arrive. This does not distinguish an unresponsive
console from a hung guest probe; private guest state was removed by cleanup.
The fixture now verifies a short shell-readiness response before transmitting the
probe, uses compressed lowercase hex like the passing boot fixture, and bounds
guest execution with Python's default 30-second termination alarm. Fixed probe-stage markers distinguish
which operation was active if execution hangs. These changes require a fresh
approved guest run; the host component regressions do not qualify the installer.

## Readiness marker returned, but long probe exchange still times out

Run [39819651615](https://github.com/codyasmith8118/RiverLB/actions/runs/39819651615)
tested `c218b1642b61fbf5ff09a75f9dfcfab1f53df757`. Both firmware reports again
record eight preceding stages passed, eleven boot assertions passed, successful
cleanup, and `graphical` / `graphical-summary` / `probe-timeout`.

- [BIOS failure report](full-39819651615/bios/report.json)
- [UEFI failure report](full-39819651615/uefi/report.json)

This failure occurs after the original short shell-readiness marker was received. The
longer probe exchange still did not return its completion marker; the reports do
not establish whether that command was received intact. The fixture now delivers
public probe scripts on a separate read-only test CD and types only a short file
invocation. It verifies fixture-media readiness, keeps the guest execution deadline,
and uses lowercase nonce completion markers. The candidate installer ISO remains
unchanged by this test transport. A fresh approved real-guest run must verify it;
local shell/media checks do not establish installer qualification.

## Fixture media readiness fails on both firmware types

Run [39829613032](https://github.com/codyasmith8118/RiverLB/actions/runs/39829613032)
tested `3ea88298937e6d87badeefb45898f9e4c3558a7c`. Both firmware jobs passed
the eight preceding stages, all eleven boot assertions and cleanup, then reported
`graphical` / `graphical-summary` / `probe-media-not-ready`. The probe itself did
not run. Checksum-verified reports retain exact source/input/artifact identity:

- [BIOS failure report](full-39829613032/bios/report.json)
- [UEFI failure report](full-39829613032/uefi/report.json)

That check combined label-link discovery, mounting and content readiness, so its
failure does not establish which operation failed. It also accepted a literal
readiness nonce; echoed command text alone cannot prove execution. The revised
protocol requires a computed numeric exit status, rejects echoed input, checks
the known secondary CD device directly, and reports a separate static failure
code for each media step. It keeps read-only mounting and existing assertions.
A fresh protected guest run must verify this change; host regressions are not
installer qualification evidence.

## Executed shell replies expose distinct installer failures

Run [39844963597](https://github.com/codyasmith8118/RiverLB/actions/runs/39844963597)
tested `bb16fb94d97fd50ea0620327748ffee2d826a2ab`. Both firmware jobs passed
the eight stages preceding installer qualification, all eleven boot assertions,
and cleanup. Checksum-verified reports preserve source, inputs and artifact hashes:

- [BIOS failure report](full-39844963597/bios/report.json)
- [UEFI failure report](full-39844963597/uefi/report.json)

BIOS reached the `select` case and failed at `storage-selection` with
`shell-not-ready`, after completing the graphical case. UEFI failed at
`graphical` / `graphical-summary` with `probe-command-timeout`: shell readiness
was established but a subsequent command did not return its status. This code
does not identify which command timed out. These partial results do not establish
full installer qualification. Issue #10 remains In Progress.

A bounded local software-emulation diagnostic using the pinned tools and an
existing development installer ISO reproduced a text-boot sequencing problem:
the original separate input submissions left the guest at GRUB. Allowing initrd
loading to finish, or submitting `linux; initrd; boot` as one command list, entered
the kernel. The revised command list reached the installer shell, mounted the
read-only fixture CD and executed its probe. That local text case later failed
`text-screen-not-ready`; it is diagnostic evidence, not source-matched KVM
qualification. No private local guest files are retained here.

The fixture now submits one GRUB command list, reselects the shell VT before each
command (Anaconda graphical startup explicitly activates VT6), and emits distinct
ready/mountpoint/device/mount/content/script/execution timeout codes. The UEFI
report above does not prove a focus switch caused its timeout. Fresh protected
BIOS/UEFI qualification is still required.

## UEFI fully passes; BIOS loses a fixture-preparation reply

Run [39873797031](https://github.com/codyasmith8118/RiverLB/actions/runs/39873797031)
tested `9ab1f1c8c5935e9bca9740e8cd001cfe6414fba8`. Both downloaded reports
were checked against their SHA256SUMS and source identity.

- [UEFI passing report](full-39873797031/uefi/report.json): all nine stages, all
  eleven boot assertions, all four installer assertions, and cleanup passed.
  The exact assertion lists, four artifact hashes and locked inputs were verified.
- [BIOS failure report](full-39873797031/bios/report.json): eight preceding stages,
  all eleven boot assertions and cleanup passed. Installer qualification failed
  at `graphical` / `graphical-summary` / `probe-mountpoint-timeout`. The `mkdir -p`
  operation did not return its status after shell readiness and the initial
  media-content check. This does not establish whether input delivery, guest
  execution or reply delivery failed.

The fixture now hands its probe shell's input/output to a private QEMU UART
socket, using display keyboard input only for the short initial handoff. An
executed nonce/status reply over UART is required before any probe. Subsequent
probe commands do not depend on the displayed VT. UART socket output is drained
to prevent backpressure; QEMU's private serial log remains the response source.
The socket, logs, overlays and guest output are removed by normal owned-workspace
cleanup. Existing deadlines, read-only media and installer assertions remain.
Fresh protected qualification must verify this change on both firmware types;
UEFI's pass above does not qualify a later source. Issue #10 remains In Progress.
