# Retained build inputs and reproducibility

Release builds use `packaging/build-inputs.lock.json`. It pins a retained HTTPS
archive by SHA-256 and size, its complete inventory, immutable OCI image IDs,
the AlmaLinux signing key, and source files that determine dependencies. Normal
builds never run `podman build`, resolve live DNF repositories, fetch Cargo
registries, install from PyPI, or download Packer plugins. Missing or changed
inputs fail the build; there is no online fallback.

## Build an existing snapshot

Use Linux x86_64, Python 3.11+, Git, rootless Podman and sufficient storage
(allow 30 GB for the snapshot, an empty compilation target, and outputs).
Choose a cache on a volume with space; it contains public build dependencies,
not signing keys:

```sh
export RIVERLB_BUILD_INPUTS_CACHE=/path/with/space/riverlb-build-inputs
python3 scripts/build-inputs.py verify
scripts/build-rpm.sh
scripts/test-rpm.sh
scripts/build-appliance-iso.sh
```

The first invocation downloads the retained snapshot. Subsequent invocations
verify its archive, every extracted file, container config identities, and
vendor RPM signatures. Containers use `--pull=never --network=none`. Base media
is separately pinned by `appliance/base-media.json`, and ISO builds require that
exact checksum. Prepopulate the input cache and base ISO to build disconnected.
The build helper uses new temporary Cargo homes and target directories on each
invocation; `$TMPDIR` can select a larger scratch volume.

`build-manifest.json` identifies the source content, commit/dirty state,
`SOURCE_DATE_EPOCH`, compiler, base image, base media and full snapshot lock.
`build-inputs.json` records every retained file's SHA-256 and size, exact installed
builder/tool/runtime package NEVRAs, source RPM/license names, the signed HA RPM
closure, wheels, Cargo vendor sources, and tool provenance. Both are covered by
output `SHA256SUMS`. Preserve these beside release artifacts; the manifest is
also installed in the main RPM.

Packer 1.16.1 and QEMU plugin 1.1.4 are retained with vendor-signed checksum lists.
Their signing key fingerprint is pinned in `packaging/toolchain.lock.json`.
The QEMU executable and OVMF firmware come from the locked tools image. No host
Packer executable, mutable plugin cache, or native ISO-tool version is selected.

## Compare two clean builds

```sh
export RIVERLB_REPRO_OUTPUT_DIR=/path/with/space/repro-evidence
scripts/test-reproducible-build.sh
```

This runs two new containers with empty Cargo homes and target directories.
It compares parsed manifests and SHA-256 for every unsigned RPM, dependency RPM,
repository metadata file, compiler/package inventory, and checksum list. A
changed field or byte fails; `comparison.json` contains the exact identities.
Use the same source tree, RPM release and `SOURCE_DATE_EPOCH` for both attempts.
RPM build host/time and payload timestamps are fixed, and gzip headers omit
wall-clock time. Do not compare signed RPM bytes: signing is a separate stage
with signature metadata. A source commit or dirty-state change is a different
build identity and is expected to change the manifest and RPM containing it.

ISO comparisons require equal extracted file hashes (including the complete
RPM payload, kickstarts, trust policy and branding), boot configuration and base
media identity. ISO volume creation dates and generated EFI filesystem metadata
can vary with remaster time; whole-ISO equality is not promised. Installed disks
also contain generated filesystem UUIDs, machine identities, logs, install times
and first-boot secrets. Their byte equality is not a release criterion. Guest
boot/traffic qualification remains a separate test, requiring isolated VMs;
reproducible RPM inputs do not establish successful boot or HA operation.

## Intentionally refresh retained inputs

Only the maintainer capture path uses current repositories. The Containerfiles
are bootstrap recipes, not normal release build commands. Review updates and
build each named image explicitly, prepare and test the full HA RPM closure,
then capture a **new** snapshot ID/retained release URL:

```sh
podman build -t localhost/riverlb-builder:alma10.2 -f packaging/container/Containerfile packaging/container
podman build -t localhost/riverlb-image-tools:alma10.2 -f appliance/tools/Containerfile appliance/tools
podman build -t localhost/riverlb-network-tests:alma10.2 -f tests/appliance/Containerfile.network-manager tests/appliance
python3 scripts/snapshot-build-inputs.py --output /path/to/new-capture \
  --snapshot-id NEW-ID --url https://github.com/OWNER/REPO/releases/download/NEW-TAG/build-inputs.tar.gz
```

Capture requires the reviewed closure in `dist/rpm/ha-dependencies`; retain the
original vendor signatures and repodata rather than re-resolving dependencies
inside the release build. Cargo uses `Cargo.lock`; SDK downloads require exact
hashes from `deploy/ha/vendor/openstack-requirements.txt`. Capture verifies the
OS key fingerprint and HashiCorp checksum signatures. Publish the resulting
archive at the declared URL, review the new lock/inventory and licenses, run the
negative tests, two-build comparison and disconnected install, then submit the
lock change in a PR. Never replace an already published snapshot silently.
`--reseal` is for an unpublished capture under preparation, not a published one.

If retention becomes unavailable, restore the **same verified bytes** from a
trusted mirror or review a new snapshot/lock in a PR. Do not weaken validation
or resolve current repositories as a substitute.

## Regression checks

```sh
python3 tests/appliance/build_inputs.py
python3 tests/appliance/build_workflow.py
```

The input tests reject absent/altered/extra files, corrupt cached archives,
source-lock drift, unavailable snapshots, non-HTTPS URLs/redirects, oversize
archives, traversal, links, duplicate entries, and unsigned/untrusted RPM
verification results. Actual vendor signature validation and disconnected
installation run in the package qualification path.
