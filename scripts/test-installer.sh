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
podman run --rm --device /dev/kvm --security-opt=no-new-privileges \
    -v "$project_dir/dist/iso:/media:ro,z" -v "$project_dir/dist/test-installer-vm:/output:Z" \
    -v "$stage_dir:/tests:ro,Z" -e RIVERLB_VM_TEST=disposable-container \
    localhost/riverlb-image-tools:alma10.2 python3 /tests/installer.py "$@"
