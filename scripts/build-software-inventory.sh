#!/usr/bin/env bash
# Inspect only public build outputs; no VM mounts, package installation or network.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
firmware=${RIVERLB_IMAGE_FIRMWARE:-bios}
[[ "$firmware" == bios || "$firmware" == uefi ]] || exit 1
image_dir=dist/image
boot_dir=dist/test-vm
if [[ "$firmware" == uefi ]]; then image_dir=dist/image-uefi; boot_dir=dist/test-vm-uefi; fi
output=dist/qualification-evidence/software
[[ ! -e "$output" ]] || { echo 'Software evidence output must be fresh.' >&2; exit 1; }
inputs=$(python3 scripts/build-inputs.py prepare tools)
image=$(python3 scripts/build-inputs.py image tools)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/scripts" "$stage/packaging" "$stage/appliance" "$stage/deploy/ha/vendor"
cp Cargo.toml Cargo.lock LICENSE "$stage/"
cp scripts/software-inventory.py scripts/software_inventory.py scripts/artifact_inventory.py \
    scripts/appliance_inventory.py scripts/package_inventory.py "$stage/scripts/"
cp packaging/build-inputs.lock.json "$stage/packaging/"
cp -a packaging/third-party "$stage/packaging/"
cp appliance/base-media.json "$stage/appliance/"
cp -a deploy/ha/vendor/fence-agents "$stage/deploy/ha/vendor/"
cp deploy/ha/vendor/openstack-requirements.txt "$stage/deploy/ha/vendor/"
for helper in riverlb-authority riverlb-cluster riverlb-traffic riverlb-ha.service; do
    cp "deploy/ha/$helper" "$stage/deploy/ha/"
done
mkdir -m 0700 "$output"
source scripts/qualification-container.sh inventory
common=(--root /source --inputs /inputs --packages /packages --media /media --disks /disks
    --installed /installed.json --report /qualification.json --firmware "$firmware" --output /evidence)
podman run --rm "${qualification_args[@]}" --pull=never --network=none --security-opt=no-new-privileges \
    -v "$stage:/source:ro,Z" -v "$inputs:/inputs:ro,z" \
    -v "$project_dir/dist/rpm:/packages:ro,z" -v "$project_dir/dist/iso:/media:ro,z" \
    -v "$project_dir/$image_dir:/disks:ro,z" \
    -v "$project_dir/$boot_dir/installed-rpms.json:/installed.json:ro,z" \
    -v "$project_dir/dist/qualification-evidence/report.json:/qualification.json:ro,z" \
    -v "$project_dir/$output:/evidence:Z" "$image" \
    python3 /source/scripts/software-inventory.py appliance "${common[@]}"
# Reconstruct from original artifacts; do not validate coverage against the SBOM itself.
podman run --rm "${qualification_args[@]}" --pull=never --network=none --security-opt=no-new-privileges \
    -v "$stage:/source:ro,Z" -v "$inputs:/inputs:ro,z" \
    -v "$project_dir/dist/rpm:/packages:ro,z" -v "$project_dir/dist/iso:/media:ro,z" \
    -v "$project_dir/$image_dir:/disks:ro,z" \
    -v "$project_dir/$boot_dir/installed-rpms.json:/installed.json:ro,z" \
    -v "$project_dir/dist/qualification-evidence/report.json:/qualification.json:ro,z" \
    -v "$project_dir/$output:/evidence:ro,z" "$image" \
    python3 /source/scripts/software-inventory.py verify-appliance "${common[@]}"
