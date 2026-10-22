# Issue #10 qualification evidence

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
guest execution with a 30-second timeout. Fixed probe-stage markers distinguish
which operation was active if execution hangs. These changes require a fresh
approved guest run; the host component regressions do not qualify the installer.
