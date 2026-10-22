# Build and release guide

RiverLB has working application, RPM, installer ISO and disk-image build recipes.
These produce development candidates. Production signing/promotion and complete
platform qualification remain unfinished; see [release readiness](release-readiness.md).

## Build an installer from your changes

From the repository root, as your regular user:

```bash
./scripts/build-appliance-iso.sh
```

Requirements: x86-64 Linux, rootless Podman, Git, Python 3.11+, `flock` and internet
access for package/build inputs. KVM is not needed to generate the ISO. The command
builds current application/UI sources, tests RPMs, fetches the pinned base media,
creates the interactive installer and checks media structure/checksums.

The output is `dist/iso/riverlb-installer.iso`, with an adjacent checksum. Previous
media is archived under `dist/iso/archive/`, and logs go to `dist/logs/`. A failed
ISO build/verification restores the preceding media. Each orchestrated build uses
a new timestamp RPM release unless `RIVERLB_RPM_RELEASE` is set explicitly.
Do not edit source or run competing lower-level builds during this command.

The installer is for new installations. It does not update an existing appliance.
Use [signed offline updates](offline-updates.md) for standalone application updates.
See the [appliance build reference](../appliance/README.md) for firmware options,
disk images, individual stages and VM tests.

## Artifact types

| Artifact | Build command | Use and limits |
|---|---|---|
| Application archive | `scripts/build-release.sh` | Unsigned binary/HA helpers matching the build host ABI; not an installer or signed update |
| AlmaLinux RPMs | `scripts/build-rpm.sh` then `scripts/test-rpm.sh` | Base, HA and appliance-setup packages built/tested in containers |
| Interactive installer | `scripts/build-appliance-iso.sh` | Native disk selection and confirmation; installs an unconfigured appliance |
| Image-builder ISO | `scripts/build-appliance-iso.sh --mode image` | Clears the disposable builder guest's `vda`; not interactive installation media |
| QCOW2/raw images | `scripts/build-image.sh` then `scripts/test-image.sh` | Fresh guest install and boot tests; KVM required by default |
| Signed application bundle | `scripts/sign-update.py --help` | Offline publisher-signed application update; requires separately owned keys and installed trust |

VMDK/VHDX/OVA conversion, additional hardware profiles and platform-specific
qualification remain future work. A format conversion alone does not establish
support.

## Build identity and source handling

`Cargo.lock` fixes application dependency resolution. The AlmaLinux builder uses
a digest-pinned container and Rust 1.92.0 packages. Base ISO identity lives in
[`appliance/base-media.json`](../appliance/base-media.json). OS repositories still
move; builds are not yet claimed to be bit-for-bit reproducible.

RPM manifests record commit, dirty state, source fingerprint and build/package
identity. Application archive manifests record commit, dirty state, binary checksum
and lockfile checksum. `CARGO_TARGET_DIR` is honored for application archive builds.
An uncommitted build must not be presented as a clean release commit.

RPM source staging uses explicit directories and tracked example TOMLs. Add a new
public example to Git before expecting it in that source package. Local databases,
keys and runtime sidecars are not intended inputs. Do not place operational secrets
inside source directories. Installer images generate their own machine/device
identity and administrator credentials during setup.

Checksums detect corruption; they do not authenticate a publisher. Unsigned
application archives/RPM/ISO candidates are separate from signed update bundles.

## CI responsibilities

| Workflow | What it does |
|---|---|
| [CI](../.github/workflows/ci.yml) | Formatting, lint, Rust/socket/DOM regressions, documentation checks and isolated networking/HA fixtures |
| [Application release candidate](../.github/workflows/release-candidate.yml) | Unsigned application archives and AlmaLinux RPM install tests; tags must match the package version |
| [Appliance ISO candidate](../.github/workflows/appliance-media.yml) | Pinned media fetch, package tests, both ISO variants and structural verification |
| [Isolated KVM appliance qualification](../.github/workflows/appliance-image.yml) | Fresh hosted VMs, protected BIOS/UEFI disk boot and interactive installer suites; sanitized JSON evidence only |

Candidate workflows upload artifacts; they do not publish a production release.
KVM qualification accepts only `release-2.0` and requires the protected
`appliance-build` environment. Follow the [qualification runbook](isolated-qualification.md)
for approval, resource limits, evidence retention and recovery. Untrusted pull-request code must not receive signing
keys, deployment access or privileged appliance-builder access.

## Application update pipeline

The implemented first step is **signed offline standalone updates**:

1. Build and test the intended application binary for AlmaLinux's ABI.
2. Create a signed bundle with version, monotonic sequence, platform/schema range,
   expiry and payload checksum. Keep publisher private keys outside build outputs.
3. Provision the publisher's public key through a trusted console procedure.
4. Upload and verify the bundle in Application Updates, review readiness and stage it.
5. Activate through the installed updater, with stopped-service backup, readiness
   checks and rollback/recovery handling.

Use the [offline update runbook](offline-updates.md) for exact commands and limits.
The application bundle does not update the OS/kernel. Online channels, automatic
rollout, production key ownership and trust-rotation qualification remain separate work.

## Standalone and HA activation

Standalone activation is implemented. Existing connections may need to reconnect.
A process starting successfully is not enough to prove its traffic works; verify
the application and a representative service after activation.

**HA rolling application updates are blocked.** The following is a future
qualification design, not an executable supported update procedure:

1. Establish a tested mixed-version/schema/checkpoint compatibility window.
2. Update standby while proving it retains standby ownership.
3. Synchronize and perform a controlled move with fencing/withdrawal verification.
4. Verify traffic before updating the former active.
5. Exercise interruption, rollback and incompatible-version recovery on both nodes.

Traffic configuration sync is independent of software rollout. Do not bypass
fencing or quorum to force an upgrade. OS updates and OS rollback also need their
own maintenance and recovery procedures.

## Delivery milestones and release gates

Before publishing a production artifact:

1. Build from a recorded final commit and run full CI on that revision.
2. Test actual installation, existing-disk confirmation, BIOS/UEFI boot, console
   recovery, unique identity, firewalld, SELinux and supported NIC/storage models.
3. Run real two-node HA fencing/partition/failover qualification where HA is offered.
4. Exercise update interruption and data-compatible rollback.
5. Measure capacity, latency and long-duration resource behavior.
6. Complete dependency/license review, SBOM, provenance, immutable OS inputs and
   protected signing/promotion. Pin CI actions to reviewed commits before production.

Use [the appliance test plan](appliance-test-plan.md) for scenarios and lab tools.
Keep test reports with the artifact manifest and identify any unexecuted gates.

## Initial package verification

Historical package/image runs are useful evidence for their recorded source and
platform. They do not qualify a newer build. Current tooling and fixture results
are described in the [package guide](../packaging/README.md), while historical
feature records remain under [verification](verification.md).

The RPM build also stages a local repository in `dist/rpm/ha-dependencies` and
includes its packages and repository metadata in `SHA256SUMS`. Both ISO modes
embed that dependency set alongside the base, HA, and appliance RPMs. Package
smoke tests install from the local repository with networking disabled; vendor
package signatures are checked against the included OS signing key.

Set `RIVERLB_RPM_OUTPUT_DIR` when RPM output needs another filesystem. For ISO
builds, `RIVERLB_RPM_DIR` selects that package directory and
`RIVERLB_ISO_OUTPUT_DIR` selects the output directory.
