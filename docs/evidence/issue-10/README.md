# Issue #10 qualification evidence

Source under test: `cc3acee8fe0c4d6fbe65a8a271dbf4ed4cfc76a3` on `release-2.0`.
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
