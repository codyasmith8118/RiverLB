#!/usr/bin/env bash
# Remaster a verified AlmaLinux DVD; no disks are mounted or modified on the host.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
if [[ $# != 3 || ! "$3" =~ ^(installer|image)$ || ! "$2" =~ ^[a-fA-F0-9]{64}$ ]]; then
    echo 'Usage: scripts/build-iso.sh /path/AlmaLinux-10.2-x86_64-dvd.iso TRUSTED_SHA256 installer|image' >&2; exit 1
fi
python3 - "$2" <<'CHECK'
import json, sys
assert sys.argv[1].lower() == json.load(open('appliance/base-media.json'))['sha256'], 'Base ISO must match appliance/base-media.json'
CHECK
iso=$(realpath -- "$1")
actual=$(sha256sum "$iso" | cut -d ' ' -f 1)
[[ "${actual,,}" == "${2,,}" ]] || { echo 'Base ISO checksum mismatch.' >&2; exit 1; }
rpm_dir=$(realpath -- "${RIVERLB_RPM_DIR:-$project_dir/dist/rpm}")
mkdir -p -- "${RIVERLB_ISO_OUTPUT_DIR:-$project_dir/dist/iso}"
iso_output_dir=$(realpath -- "${RIVERLB_ISO_OUTPUT_DIR:-$project_dir/dist/iso}")
if [[ ${RIVERLB_LOCKED_TOOLS:-0} != 1 ]]; then
    command -v podman >/dev/null
    image=$(python3 scripts/build-inputs.py image tools)
    tool_stage=$(mktemp -d)
    trap 'rm -rf -- "$tool_stage"' EXIT
    mkdir -p "$tool_stage/scripts" "$tool_stage/appliance"
    mkdir -p "$tool_stage/tmp"
    cp scripts/build-iso.sh "$tool_stage/scripts/"
    cp appliance/base-media.json "$tool_stage/appliance/"
    cp -a appliance/kickstart appliance/tools appliance/branding "$tool_stage/appliance/"
    podman run --rm --pull=never --network=none -e RIVERLB_LOCKED_TOOLS=1 --security-opt=no-new-privileges \
        -v "$tool_stage:/workspace:ro,Z" -v "$rpm_dir:/workspace/dist/rpm:ro,z" \
        -v "$iso_output_dir:/workspace/dist/iso:z" -v "$tool_stage/tmp:/tmp:Z" \
        -v "$iso:/input/base.iso:ro,z" -w /workspace \
        -e PATH=/workspace/appliance/tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        "$image" bash scripts/build-iso.sh /input/base.iso "$2" "$3"
    exit
fi
(cd "$rpm_dir"; sha256sum -c SHA256SUMS)
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
# Include optional HA integration and its offline dependency closure on every ISO.
[[ -d "$rpm_dir/ha-dependencies" ]] || { echo 'Rebuild RPMs to stage offline HA dependencies.' >&2; exit 1; }
cp "$rpm_dir"/riverlb-*.rpm "$stage_dir/"
cp -a "$rpm_dir/ha-dependencies" "$stage_dir/ha-dependencies"
source_epoch=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_date_epoch"])' "$rpm_dir/build-manifest.json")
[[ "$source_epoch" =~ ^[0-9]+$ ]] || { echo 'Invalid source epoch.' >&2; exit 1; }
(cd "$stage_dir"; tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -cf riverlb-packages.tar ./*.rpm ./ha-dependencies)
cp appliance/kickstart/common.ks "$stage_dir/riverlb-common.ks"
cp "$rpm_dir/update-trust.json" "$stage_dir/update-trust.json"
# Refuse to advertise graphics if the reviewed media lacks the offline runtime.
# This inspects a regular extracted file; it never mounts or changes host disks.
if [[ "$3" == installer ]]; then
    command -v unsquashfs >/dev/null || { echo 'squashfs-tools is required to check installer graphics; use RIVERLB_ISO_USE_CONTAINER=1.' >&2; exit 1; }
    xorriso -osirrox on -indev "$iso" -extract /images/install.img "$stage_dir/install.img" >/dev/null 2>&1
    python3 appliance/tools/installer-branding.py --runtime "$stage_dir/install.img"
    rm -- "$stage_dir/install.img"
fi
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$rpm_dir/build-manifest.json")
release_stage=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("release_stage", "In development"))' "$rpm_dir/build-manifest.json")
python3 appliance/tools/installer-branding.py --source appliance/branding \
    --version "$version" --release-stage "$release_stage" --output "$stage_dir/images/product.img"
output="$iso_output_dir/riverlb-$3.iso"
[[ ! -e "$output" && ! -e "$output.partial" ]] || { echo "Output already exists: $output" >&2; exit 1; }
iso_tool=$(command -v riverlb-mkksiso || true)
if [[ -z "$iso_tool" ]]; then iso_tool="$project_dir/appliance/tools/remaster-iso.py"; fi
trap 'rm -rf -- "$stage_dir"; rm -f -- "$output.partial"' EXIT
RIVERLB_INSTALL_MODE="$3" python3 "$iso_tool" --ks "appliance/kickstart/$3.ks" --add "$stage_dir/riverlb-common.ks" \
    --add "$stage_dir/riverlb-packages.tar" --add "$stage_dir/update-trust.json" --add "$stage_dir/images" "$iso" "$output.partial"
mv "$output.partial" "$output"
(cd "$iso_output_dir"; sha256sum "riverlb-$3.iso" > "riverlb-$3.iso.sha256")
echo "Created $output (unsigned; boot qualification required)"
