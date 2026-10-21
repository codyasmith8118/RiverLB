#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
[[ -f dist/rpm/SHA256SUMS ]] || { echo 'Run scripts/build-rpm.sh first.' >&2; exit 1; }
(cd dist/rpm; sha256sum -c SHA256SUMS)
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
cp packaging/container/test.sh tests/rpm_smoke.py tests/firstboot.py scripts/sign-update.py "$stage_dir/"
# A pinned clean runtime base, not the developer build environment.
podman run --rm --network=none --security-opt=no-new-privileges \
    -v "$project_dir/dist/rpm:/packages:ro,z" -v "$stage_dir:/tests:ro,Z" \
    -e RIVERLB_PACKAGE_TEST=disposable-container \
    docker.io/library/almalinux@sha256:ba31c3299856068f77bc10574cad51b0a4f6a3dafb882668656e1639bee63db6 \
    bash /tests/test.sh
