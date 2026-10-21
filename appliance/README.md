# Build and test appliance media

For installation as an appliance user, start with the
[installation guide](../docs/installer-experience.md). This page is the builder
reference.
For simple steps including update signing keys, use the [ISO README](../ISO-BUILD-README.md).

- [Build an installer ISO](#build-iso-candidates).
- [Build and test disk images](#build-a-disk-image).
- [Understand first-boot behavior](#guided-installation-and-console-setup).
- [Run deployment qualification](#appliance-qualification).

Implemented tooling produces unsigned installation media and packages console
setup. Earlier image candidates passed BIOS and UEFI/OVMF installation and
initial boot tests. The current graphical installer, service policy and updater
need a fresh appliance qualification run. These remain development candidates;
the supported networking/platform matrix, upgrades and HA qualification are
required before appliance distribution.

## Appliance qualification

Use the [detailed qualification plan](../docs/appliance-test-plan.md) for backend
node deployment, HTTP/TLS traffic generation, TRex TCP capacity testing, real
two-node HA/fencing, updates and release gates. Runnable lab tools are in
[`tests/lab/`](../tests/lab/README.md). Unexecuted platform tests remain release
qualification work even after a successful ISO build.

## Guided installation and console setup

The interactive installer starts Anaconda’s graphical interface, with **Install
RiverLB appliance** branding, the application version, and the release stage.
The reviewed minimal ISO contains the GUI, GTK and Mutter runtime; builds inspect
these components before creating graphical media. A text-console fallback is
available under Troubleshooting. See [the installation guide](../docs/installer-experience.md)
and [branding policy](../docs/branding.md). First boot uses five numbered steps,
input retries, network tools, a review with Back/Cancel, and clear progress.

The `riverlb-appliance` RPM supplies `riverlb-setup` and
`riverlb-firstboot.service`. RPM installation leaves setup disabled. The image
recipe enables it on the primary VGA console (`tty1`); serial-only setup is not
yet supported. Setup selects an assigned IPv4 management address, sets hostname,
creates a RiverLB administrator and a separate Linux root recovery password,
generates a unique self-signed management certificate with hostname/IP SANs,
and opens destination-scoped HTTPS access on port 18090. It starts no traffic
listeners and configures no HA group. SSH remains disabled in the image recipe.

The appliance package adds a service startup gate: `systemctl start riverlb`
is skipped until setup commits its activation journal, HTTPS configuration,
certificate, key and administrator database, or completes successfully. This
prevents an early service start from creating a loopback bootstrap database and
blocking the wizard. Ordinary base-RPM installations keep their existing startup
behavior. Use the VGA first-boot wizard; do not manually start the server binary
before setup. The wizard ends with `https://<selected-IP>:18090`.

The guard is included in the appliance package source. Older ISO and disk
candidates need rebuilding to include current setup changes. Updating
an existing appliance with an incomplete setup/database does not repair its
management configuration; preserve that state and recover access separately.

When no address is available, setup offers NetworkManager's `nmtui`. Use static
management addressing or a DHCP reservation: the application currently binds the
selected address and does not follow later DHCP address changes automatically.
IPv6-only initial setup is a future extension. Use the GUI for traffic objects,
HA setup and device certificate replacement after initialization.

Additional NICs stay unconfigured rather than requesting DHCP automatically.
The image's bootstrap DHCP connection is bound to its first NIC before networking
starts. Use [Network → Interfaces](../docs/interface-management.md) for static or
automatic addressing, DNS, MTU and default routing. Each change requires a
connectivity confirmation within 90 seconds before it is saved to disk.

Setup never puts passwords in command arguments or saves them in its journal.
Private files are written atomically with mode 0600. The completed marker is
`/var/lib/riverlb/.firstboot.complete`. A failed final activation has a resumable
`.firstboot.pending` journal; rerun `riverlb-setup` from the root console after
fixing the error. Existing state without a valid activation journal is refused,
including interrupted data/configuration commit. Recover such a case using a
private backup and operator review; deleting the marker alone must not reset
accounts or overwrite data. This is not a factory-reset implementation.

## Build ISO candidates

From the repository, run this as your regular user (without sudo):

```bash
./scripts/build-appliance-iso.sh
```

This builds the current working tree, including uncommitted application and GUI
changes; fetches/caches the pinned AlmaLinux base ISO; builds and tests RPMs;
generates the interactive installer; and verifies its checksum and boot structure.
It uses rootless Podman and requires x86-64 Linux, Python 3.11+, Git, and flock.
Internet access is required for package tests; the first run also downloads
build tools and base media. KVM is not required to generate the ISO. Avoid editing sources or running the lower-level
build commands while it runs.

The result is `dist/iso/riverlb-installer.iso`, with a `.iso.sha256` file alongside
it. Previous media is kept in `dist/iso/archive/`; failures during ISO creation or
verification restore the previous media and retain failed output for inspection.
Build logs are in `dist/logs/`. Each run defaults to a new UTC timestamp RPM release;
set `RIVERLB_RPM_RELEASE` explicitly for a controlled release number. Existing
appliance configuration, accounts, and certificates are not included in the ISO.
This is new installation media, not an in-place update of an existing appliance.
A successful build still requires VM installation/boot qualification.

For unattended **disposable image-builder disks only**, use
`./scripts/build-appliance-iso.sh --mode image`. For the individual build stages:

Start by building/testing RPMs. `scripts/fetch-base-iso.py` downloads the base
media pinned in `appliance/base-media.json`; that digest was obtained from the
signature-verified AlmaLinux CHECKSUM. Use a verified AlmaLinux 10.2 x86-64 minimal or
DVD installation ISO. The minimal ISO's manifest contains the current required
OS packages; the automated recipe has passed an offline VM installation. The boot ISO
alone does not contain an installation package repository.

```bash
scripts/build-rpm.sh
scripts/test-rpm.sh
scripts/build-iso.sh /path/to/base.iso TRUSTED_SHA256 installer
scripts/build-iso.sh /path/to/base.iso TRUSTED_SHA256 image
scripts/test-iso.sh installer
scripts/test-iso.sh image
```

Use a checksum from the distribution's signature-verified CHECKSUM file, not a
hash computed from an untrusted download. The build checks the given hash and
RPM checksums. It uses native Lorax/mkksiso when installed, or builds a rootless
Podman tool container. The container uses a regular-file FAT helper with mtools
to rebuild the EFI boot image without loop devices or privileged mounts. It
supports only the mkksiso boot-directory operation, not Apple or full disk modes.
An AlmaLinux-specific adapter reconstructs GRUB BIOS and appended EFI boot
records because the distribution tool cannot replay its non-file EFI entry.
The adapter fails on unexpected Lorax arguments; structural tests inspect both
boot entries and the actual embedded FAT boot configuration.
BIOS and EFI boot configuration are retained and updated by
[Lorax mkksiso](https://weldr.io/lorax/mkksiso.html); retaining boot metadata does
not establish successful firmware boot or Secure Boot qualification.

`dist/iso/riverlb-installer.iso` opens the native graphical storage workflow.
Select Installation Destination, review the disk/layout and choose Begin Installation
only when ready. The interactive Kickstart contains no unattended disk clearing
or partitioning. The text-console entry uses the same storage confirmation.
Installer branding is applied through Anaconda’s documented product.img overlay,
including the graphical product name, logo and colors; BIOS and embedded EFI menus
are branded consistently while base distribution identity and licenses are preserved.
The automated `riverlb-image.iso` is exclusively for the disposable builder guest:
it clears its `vda` disk. Do not use that media as an interactive installer.
Neither recipe installs an administrator, shared key or a configured HA identity.
No build invokes a partitioning command on the host.

## Build a disk image

On a dedicated x86-64 Linux builder with accessible `/dev/kvm` and Packer:

```bash
scripts/build-image.sh
scripts/test-image.sh
```

The [Packer QEMU builder](https://developer.hashicorp.com/packer/integrations/hashicorp/qemu/latest/components/builder/qemu)
boots the automated ISO into a fresh 16-GiB virtio disk, waits for installer
shutdown, and produces QCOW2 plus raw derivatives. It uses the pinned QEMU plugin
and no SSH communicator or embedded build credentials. BIOS is the default.
Select UEFI explicitly for both build and test:

```bash
RIVERLB_IMAGE_FIRMWARE=uefi scripts/build-image.sh
RIVERLB_IMAGE_FIRMWARE=uefi scripts/test-image.sh
```

UEFI candidates are written to `dist/image-uefi`; tests use private
`dist/test-vm-uefi` overlays and copy NVRAM per guest. The build retains
`efivars.fd` for QEMU boot and hashes it alongside the disks. OVMF tests use
non-Secure-Boot firmware; Secure Boot and other platforms remain unqualified.
Native QEMU builders can set `RIVERLB_EFI_CODE` and `RIVERLB_EFI_VARS` to a
matching OVMF pair; the container uses its packaged AlmaLinux OVMF.

Set `RIVERLB_QEMU_BINARY` when the binary is installed
outside PATH. If QEMU is absent, the script runs it in the rootless Podman tool
container; install Podman and set `RIVERLB_PACKER_BINARY` to a verified Packer
executable if it is outside PATH. The guest uses the host CPU with KVM or `max`
with emulation to satisfy AlmaLinux 10 x86-64-v3 requirements.
KVM is required by default; `RIVERLB_IMAGE_ACCELERATOR=tcg` explicitly
selects slower software emulation. Do not advertise platform support merely from
successful disk-format conversion.

`scripts/test-image.sh` checks image hashes and boots disposable overlays with
private NAT networking. It exercises console setup, HTTPS authentication, VIP TCP
forwarding through firewalld, reboot persistence, independent clone certificates
and machine IDs, enforcing SELinux, disabled SSH, root console recovery login
and private database permissions.
Test overlays contain known fixture credentials and live under private
`dist/test-vm`; never distribute them. Only the unconfigured disks in
`dist/image` are appliance candidates. Preserve or remove the test directory
before rerunning. The tests require KVM and the image tool container.

`scripts/test-installer.sh` checks branded graphical startup and the text-console
storage/quit workflows on blank disposable disks. It compares the disks against a
blank image to verify that stopping before storage confirmation leaves them untouched.
Results live under private `dist/test-installer-vm`; preserve or remove that directory
before rerunning. Use the VM VGA console; serial-only installation/setup is not yet
supported. These updated boot checks require a KVM builder and remain a release
gate until rerun against the new media.

Next gates: finish an interactive installation on existing-disk scenarios,
exercise VLANs and failure recovery, test RPM upgrades, then repeat with
supported hypervisor NIC/controller models and Secure Boot.
Publish only after signing, SBOM/license, provenance and full release CI gates.

The manual `Appliance ISO candidate` workflow repeats package tests, downloads
the pinned base media, builds both ISO variants and runs structural tests. It
uploads unsigned CI artifacts only; it does not deploy or publish a release.

The manual `Appliance disk candidate` workflow runs on a dedicated disposable
self-hosted runner labeled `riverlb-kvm`, with Podman, verified Packer and
read/write KVM access. Configure the `appliance-build` environment with trusted
ref restrictions and runner isolation before enabling it. It repeats package,
ISO, installation and boot tests in a BIOS/UEFI matrix, with interactive
installer checks in the BIOS job, then uploads unconfigured disks and test
reports. It excludes credential-bearing overlays. Neither workflow signs or
publishes releases.

For post-installation configuration, use the
[web configuration guide](../docs/web-configuration.md) and
[documentation index](../docs/README.md).

## Deploy high availability

The ISO includes RiverLB HA integration and all resolved cluster dependencies,
so installation does not need internet access. HA services stay disabled until
you configure **High Availability → HA Configuration**. Prepare each appliance,
exchange public identities, authenticate the cluster hosts, and start standby
from that page. Fencing resources can also be created there with the installed
platform agents. See the [GUI deployment steps](../docs/high-availability.md#deploy-an-iso-installed-appliance-from-the-gui).
