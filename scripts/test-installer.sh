#!/usr/bin/env bash
# Only blank disposable guest disks are attached; never mounts or edits host disks.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM device is not accessible.' >&2; exit 1; }
(cd dist/iso; sha256sum -c riverlb-installer.iso.sha256)
[[ ! -e dist/test-installer-vm ]] || { echo 'Preserve or remove existing dist/test-installer-vm before rerunning.' >&2; exit 1; }
install -d -m 0700 dist/test-installer-vm
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
cp tests/appliance/installer.py tests/appliance/vnc.py "$stage_dir/"
image=$(python3 scripts/build-inputs.py image tools)
source scripts/qualification-container.sh installer
podman run --rm "${qualification_args[@]}" --pull=never --network=none --device /dev/kvm --security-opt=no-new-privileges \
    -v "$project_dir/dist/iso:/media:ro,z" -v "$project_dir/dist/test-installer-vm:/output:Z" \
    -v "$stage_dir:/tests:ro,Z" -e RIVERLB_VM_TEST=disposable-container -e "RIVERLB_IMAGE_FIRMWARE=${RIVERLB_IMAGE_FIRMWARE:-bios}" \
    "$image" python3 /tests/installer.py "$@"
