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
has passed RPM build/package qualification. At this record's creation, guest
qualification is waiting for its separate protected-environment approval. This
record proves negative preflight and cleanup only; it does not establish passing
BIOS/UEFI guest qualification. Issue #10 remains In Progress.
