#!/usr/bin/env bash
# Uses read-only base disks and private overlays; no host interfaces or disks changed.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
firmware=${RIVERLB_IMAGE_FIRMWARE:-bios}
[[ "$firmware" == bios || "$firmware" == uefi ]] || { echo 'Invalid firmware.' >&2; exit 1; }
image_dir=dist/image
output_dir=dist/test-vm
if [[ "$firmware" == uefi ]]; then image_dir=dist/image-uefi; output_dir=dist/test-vm-uefi; fi
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM device is not accessible.' >&2; exit 1; }
(cd "$image_dir"; sha256sum -c SHA256SUMS)
[[ ! -e "$output_dir" ]] || { echo "Existing test overlays found in $output_dir. Preserve or remove them before rerunning." >&2; exit 1; }
install -d -m 0700 "$output_dir"
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
cp tests/appliance/boot.py tests/appliance/vnc.py "$stage_dir/"
podman run --rm --device /dev/kvm --security-opt=no-new-privileges \
    -v "$project_dir/$image_dir:/base:ro,z" -v "$project_dir/$output_dir:/output:Z" \
    -v "$stage_dir:/tests:ro,Z" -e RIVERLB_VM_TEST=disposable-container -e "RIVERLB_IMAGE_FIRMWARE=$firmware" \
    localhost/riverlb-image-tools:alma10.2 python3 /tests/boot.py
