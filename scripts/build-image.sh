#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
accelerator=${RIVERLB_IMAGE_ACCELERATOR:-kvm}
firmware=${RIVERLB_IMAGE_FIRMWARE:-bios}
[[ "$firmware" == bios || "$firmware" == uefi ]] || { echo 'Invalid firmware.' >&2; exit 1; }
output_dir=dist/image
if [[ "$firmware" == uefi ]]; then output_dir=dist/image-uefi; fi
efi_code=${RIVERLB_EFI_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}
efi_vars=${RIVERLB_EFI_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.fd}
[[ "$accelerator" == kvm || "$accelerator" == tcg ]] || { echo 'Invalid accelerator.' >&2; exit 1; }
if [[ "$accelerator" == kvm ]] && [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    echo 'KVM is unavailable. Use a KVM-capable builder, or explicitly set RIVERLB_IMAGE_ACCELERATOR=tcg.' >&2; exit 1
fi
qemu_binary=${RIVERLB_QEMU_BINARY:-$(command -v qemu-system-x86_64 || true)}
if [[ -z "$qemu_binary" && -x /usr/libexec/qemu-kvm ]]; then qemu_binary=/usr/libexec/qemu-kvm; fi
if [[ ${RIVERLB_LOCKED_TOOLS:-0} != 1 ]]; then
    if [[ -n ${RIVERLB_EFI_CODE:-} || -n ${RIVERLB_EFI_VARS:-} ]]; then
        echo 'Custom OVMF paths require native QEMU; the container uses its packaged firmware.' >&2; exit 1
    fi
    inputs=$(python3 scripts/build-inputs.py prepare tools)
    image=$(python3 -c 'import json; print(json.load(open("packaging/build-inputs.lock.json"))["images"]["tools"]["id"])')
    stage_dir=$(mktemp -d)
    trap 'rm -rf -- "$stage_dir"' EXIT
    mkdir -p "$stage_dir/scripts" "$stage_dir/appliance"
    cp scripts/build-image.sh "$stage_dir/scripts/"
    cp -a appliance/packer "$stage_dir/appliance/"
    device_args=()
    if [[ "$accelerator" == kvm ]]; then device_args=(--device /dev/kvm); fi
    source scripts/qualification-container.sh build
    podman run --rm "${qualification_args[@]}" --pull=never --network=none -e RIVERLB_LOCKED_TOOLS=1 "${device_args[@]}" --security-opt=no-new-privileges \
        -v "$stage_dir:/workspace:ro,Z" -v "$project_dir/dist:/workspace/dist:z" \
        -v "$inputs/tools/packer:/usr/local/bin/packer:ro,z" \
        -v "$inputs/packer-plugins:/plugins:ro,z" -e PACKER_PLUGIN_PATH=/plugins \
        -e "RIVERLB_IMAGE_ACCELERATOR=$accelerator" -e "RIVERLB_IMAGE_FIRMWARE=$firmware" -w /workspace \
        "$image" bash scripts/build-image.sh
    exit
fi
[[ -n "$qemu_binary" && -x "$qemu_binary" ]] || { echo "Install QEMU or set RIVERLB_QEMU_BINARY to its executable." >&2; exit 1; }
for program in packer qemu-img; do command -v "$program" >/dev/null; done
if [[ "$firmware" == uefi ]]; then
    [[ -r "$efi_code" && -r "$efi_vars" ]] || { echo 'Install OVMF or set RIVERLB_EFI_CODE and RIVERLB_EFI_VARS.' >&2; exit 1; }
fi
iso="$project_dir/dist/iso/riverlb-image.iso"
(cd dist/iso; sha256sum -c riverlb-image.iso.sha256)
checksum=$(sha256sum "$iso" | cut -d ' ' -f 1)
packer init appliance/packer
packer validate -var "qemu_binary=$qemu_binary" -var "iso_path=$iso" -var "iso_sha256=$checksum" \
    -var "output_directory=$project_dir/$output_dir" -var "accelerator=$accelerator" \
    -var "firmware=$firmware" -var "efi_code=$efi_code" -var "efi_vars=$efi_vars" appliance/packer
packer build -var "qemu_binary=$qemu_binary" -var "iso_path=$iso" -var "iso_sha256=$checksum" \
    -var "output_directory=$project_dir/$output_dir" -var "accelerator=$accelerator" \
    -var "firmware=$firmware" -var "efi_code=$efi_code" -var "efi_vars=$efi_vars" appliance/packer
qemu-img check "$output_dir/riverlb.qcow2"
qemu-img convert -O raw "$output_dir/riverlb.qcow2" "$output_dir/riverlb.raw"
files=(riverlb.qcow2 riverlb.raw)
if [[ "$firmware" == uefi ]]; then files+=(efivars.fd); fi
(cd "$output_dir"; sha256sum "${files[@]}" > SHA256SUMS.partial; mv SHA256SUMS.partial SHA256SUMS)
echo 'Disk formats built. A successful installation is not a first-boot or traffic qualification test.'
