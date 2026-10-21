#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
mode=${1:-installer}
[[ "$mode" == installer || "$mode" == image ]] || { echo 'Use installer or image.' >&2; exit 1; }
(cd dist/iso; sha256sum -c "riverlb-$mode.iso.sha256")
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
cp tests/appliance/iso_structure.py "$stage_dir/"
podman run --rm --security-opt=no-new-privileges \
    -v "$project_dir/dist/iso:/media:ro,z" -v "$stage_dir:/tests:ro,Z" \
    localhost/riverlb-image-tools:alma10.2 python3 /tests/iso_structure.py "/media/riverlb-$mode.iso" "$mode"
