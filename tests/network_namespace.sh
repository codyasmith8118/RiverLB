#!/usr/bin/env bash
set -euo pipefail
parent_namespace=${RIVERLB_TEST_PARENT_NETNS:-$(readlink /proc/1/ns/net)}
if [[ -z "$parent_namespace" || "$(readlink /proc/self/ns/net)" == "$parent_namespace" ]]; then
    echo "Refusing to run outside a disposable network namespace" >&2
    exit 1
fi
ip link add uplink type dummy
ip link set uplink up
python3 tests/network_managed.py
