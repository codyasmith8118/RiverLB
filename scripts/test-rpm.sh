#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
rpm_dir=$(realpath -- "${RIVERLB_RPM_DIR:-$project_dir/dist/rpm}")
[[ -f "$rpm_dir/SHA256SUMS" ]] || { echo 'Run scripts/build-rpm.sh first.' >&2; exit 1; }
(cd "$rpm_dir"; sha256sum -c SHA256SUMS)
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
cp packaging/container/test.sh tests/rpm_smoke.py tests/firstboot.py scripts/sign-update.py "$stage_dir/"
# A pinned clean runtime base, not the developer build environment.
image=$(python3 scripts/build-inputs.py image runtime)
podman run --rm --pull=never --network=none --security-opt=no-new-privileges \
    -v "$rpm_dir:/packages:ro,z" -v "$stage_dir:/tests:ro,Z" \
    -e RIVERLB_PACKAGE_TEST=disposable-container \
    "$image" \
    bash /tests/test.sh
