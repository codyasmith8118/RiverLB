#!/usr/bin/env bash
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then
    echo "Run the installer as root after installing HA dependencies." >&2
    exit 1
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/../.." && pwd)
release_binary=${1:-"$project_dir/target/release/riverlb"}
if [[ ! -x "$release_binary" ]]; then
    echo "Build with cargo build --release --locked, or provide the release binary path." >&2
    exit 1
fi
if [[ ! -x /usr/libexec/riverlb/privileged/prepare.py || ! -f /usr/lib/systemd/system/riverlb-privileged.service ]]; then
    echo "Install the matching RiverLB core RPM first; the HA service requires its protected helper and service account." >&2
    exit 1
fi
if [[ -e /usr/lib/riverlb/current || -L /usr/lib/riverlb/current ]]; then
    echo "Recover the active offline selection before a console source installation." >&2
    exit 1
fi
[[ $("$release_binary" privileged-protocol) == 1 ]] || { echo "Helper protocol 1 is required." >&2; exit 1; }
install -d -m 0755 /usr/libexec/riverlb /usr/lib/ocf/resource.d/riverlb
# Preserve the installed root-owned launcher and dedicated account ownership.
install -m 0755 "$release_binary" /usr/lib/riverlb/base/riverlb
install -m 0755 "$script_dir/riverlb-cluster" /usr/libexec/riverlb/riverlb-cluster
install -m 0755 "$script_dir/riverlb-authority" /usr/libexec/riverlb/riverlb-authority
install -m 0755 "$script_dir/riverlb-traffic" /usr/lib/ocf/resource.d/riverlb/traffic
install -m 0644 "$script_dir/riverlb-ha.service" /etc/systemd/system/riverlb-ha.service
install -D -m 0644 "$script_dir/pacemaker-riverlb.conf" /etc/systemd/system/pacemaker.service.d/riverlb.conf
systemctl daemon-reload
echo "Installed HA integration. Configure node identity, SSH, two-node quorum (or witness) and fencing before starting services; see docs/high-availability.md."
