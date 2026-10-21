#!/usr/bin/env bash
# Kernel/network changes remain inside a disposable rootless container.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
podman build -t localhost/riverlb-network-tests:alma10.2 -f tests/appliance/Containerfile.network-manager tests/appliance
podman run --rm --network=none --cap-add=NET_ADMIN --security-opt=no-new-privileges \
    -v "$project_dir/tests/appliance/network_manager.py:/test.py:ro,Z" \
    -e RIVERLB_PACKAGE_TEST=disposable-container localhost/riverlb-network-tests:alma10.2 python3 /test.py
