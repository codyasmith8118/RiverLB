#!/usr/bin/env bash
set -euo pipefail
parent_namespace=${RIVERLB_TEST_PARENT_NETNS:-$(readlink /proc/1/ns/net)}
if [[ -z "$parent_namespace" || "$(readlink /proc/self/ns/net)" == "$parent_namespace" ]]; then
    echo "Refusing to run NAT tests in the host network namespace" >&2
    exit 1
fi
cd "$(dirname "$0")/.."
ip link set lo up
python3 tests/nat_managed.py
