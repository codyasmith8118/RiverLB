#!/usr/bin/env bash
# Only source files enter the fixture; host state and networking remain private.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
image=$(python3 scripts/build-inputs.py image network_tests)
stage_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir"' EXIT
umask 022
chmod 0755 "$stage_dir"
mkdir -p "$stage_dir/deploy" "$stage_dir/tests"
cp -a deploy/privileged "$stage_dir/deploy/"
cp tests/privileged_network.py "$stage_dir/tests/"
find "$stage_dir" -type d -name __pycache__ -prune -exec rm -rf -- {} +
podman run --rm --pull=never --network=none --cap-add=NET_ADMIN --cap-add=NET_RAW \
    --security-opt=no-new-privileges -v "$stage_dir:/source:ro,Z" \
    -e RIVERLB_PRIVILEGED_TEST=disposable-container "$image" \
    python3 /source/tests/privileged_network.py
