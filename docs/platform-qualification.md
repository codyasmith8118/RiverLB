# KVM platform qualification

Issue [#12](https://github.com/codyasmith8118/RiverLB/issues/12) is an entry gate
for the networking, provider, update, capacity and soak qualification leading to
[#37](https://github.com/codyasmith8118/RiverLB/issues/37). A passing short load
profile does not establish any of those gates.

The maintainer selected **KVM/QEMU and libvirt first** on November 5, 2026.
This selects qualification scope, not a completed support certification. Other
hypervisors, cloud providers, physical controllers and Secure Boot remain
unqualified until their own actual cells pass. Libvirt provider permissions and
power control are covered separately by #13; direct QEMU boot tests do not prove
that provider integration.

## Declared reference

The machine-readable [reference](../appliance/qualification/kvm-reference.json)
is checked before guest tests. The pinned tools image actually reports:

| Dimension | Initial reference |
| --- | --- |
| OS and architecture | AlmaLinux 10.2, x86_64; checksum-pinned base media and retained build inputs |
| Emulator | qemu-kvm-core 10.1.0-16.el10_2.5.alma.1.x86_64 |
| Machine | pc-i440fx-rhel10.0.0, the pinned emulator's default; other machine types are separate cells |
| Firmware | BIOS and UEFI; edk2-ovmf 20251114-5.el10_2.2.alma.1.noarch |
| Execution | Actual writable KVM, host CPU model; no software-emulation substitution |
| Resources | Two vCPUs, 4 GiB RAM, 16 GiB virtio target disk |
| Network devices | virtio-net-pci; separate private management and traffic networks during boot/traffic checks |
| Installer network | One private virtio management NIC; installation scenarios own their disposable disks |

The build recipe already uses this resource profile. The boot fixture now uses
4 GiB as well and verifies the actual guest CPU count, memory range, disk size
and virtio drivers. The boot fixture discovers NIC names from its own assigned
MAC addresses; Linux interface numbering is not a support assumption. It checks
DHCP on management only and a non-root daemon retaining only bind-service
capability. Neither the resource profile nor a successful boot establishes a
production minimum or measured sustainable capacity.

The public boot report must contain the exact declared platform identity, with
actual tool package/default-machine checks. Missing identity, unexpected keys,
changed versions and wrong numeric types fail admission to the public report and
signed provenance. Console recovery uses a verified executed UART challenge
and a private metadata reply; it opens no temporary guest audit HTTP port.
Private console text, credentials and arbitrary guest metadata
are not forwarded. Host kernel, runner image, locked tools image, source and
artifact digests remain recorded by the protected qualification controller.

## Evidence coverage

The [protected workflow](isolated-qualification.md) must run against integrated
`release-2.0` code after CI/security review. Required `appliance-build` review
remains enabled; do not auto-approve it or enroll EVE as a shared Actions runner.
Verify both firmware reports and retain their checksums before declaring results.

| Requirement | Existing or updated fixture | Remaining qualification |
| --- | --- | --- |
| INST-01/02 | Packer completes automated blank-disk image installation; native installer startup/storage/cancel fixtures | Completed graphical and text native installations, selected-target and existing-disk preservation scenarios |
| INST-03 | Real console setup, pinned-CA HTTPS login and independent generated identities | Static management setup and negative address selection on real guests |
| INST-04 | Unit regressions cover validation, activation journals and overwrite refusal | Actual no-DHCP, invalid inputs, back/cancel/retry and interrupted setup |
| INST-05 | Updated guest suite performs two completed-appliance reboots, preserving account, TLS identity, configuration, traffic and counters | Successful protected runs of the updated suite for both firmware cells |
| INST-06 | Two independently provisioned overlays with per-guest temporary passwords, machine IDs and certificates | Successful protected runs; no identity state from the build host |
| NIC isolation | Real two-NIC boot assertions plus existing bootstrap policy regressions | Hot-added NIC isolation and persistence on real guests |

This table describes coverage and open work. It is not a passing #12 report.
The older #10/#11 evidence applies only to its recorded source and cannot close
these newer platform cells. Unrun cells remain unqualified.

## Delivery and subsequent gates

Retain exact source, candidate/input/media/disk hashes, tool/kernel versions,
commands, expected/actual results, privacy checks and owned cleanup. Publish only
allowlisted redacted reports. Private disks, screenshots, passwords, keys and
raw console logs stay outside Git and public artifacts.

After #12's complete matrix passes, follow the
[paired development delivery procedure](development-lab.md) for the exact
accepted commit. Keep each review appliance's own management address, accounts,
certificates and configuration. Continue #13, #17/#22/#23, #25, #30, #24 and #36
as their dependencies permit; only then schedule the real 24-hour and 72-hour
mixed-traffic soak at measured load on a frozen candidate. The ten-minute
`loadgen.py soak` profile is a functional check, not #37 evidence.
