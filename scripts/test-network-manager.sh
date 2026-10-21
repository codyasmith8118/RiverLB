#!/usr/bin/env bash
# Kernel/network changes remain inside a disposable rootless container.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
image=$(python3 scripts/build-inputs.py image network_tests)
podman run --rm --pull=never --network=none --cap-add=NET_ADMIN --security-opt=no-new-privileges \
    -v "$project_dir/tests/appliance/network_manager.py:/test.py:ro,Z" \
    -e RIVERLB_PACKAGE_TEST=disposable-container "$image" python3 /test.py
