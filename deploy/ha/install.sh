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
install -d -m 0755 /usr/libexec/riverlb /usr/lib/ocf/resource.d/riverlb
install -d -m 0700 /etc/riverlb /var/lib/riverlb
install -m 0755 "$release_binary" /usr/bin/riverlb
install -m 0755 "$script_dir/riverlb-cluster" /usr/libexec/riverlb/riverlb-cluster
install -m 0755 "$script_dir/riverlb-authority" /usr/libexec/riverlb/riverlb-authority
install -m 0755 "$script_dir/riverlb-traffic" /usr/lib/ocf/resource.d/riverlb/traffic
install -m 0644 "$script_dir/riverlb-ha.service" /etc/systemd/system/riverlb-ha.service
systemctl daemon-reload
echo "Installed HA integration. Configure node identity, SSH, two-node quorum (or witness) and fencing before starting services; see docs/high-availability.md."
