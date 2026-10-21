#!/usr/bin/env bash
# Run on a disposable AlmaLinux backend VM after copying tests/lab/ there.
# Explicitly invoked deployment: installs files/service, leaves firewall policy to operator.
set -euo pipefail
if [[ $# != 2 || ! $1 =~ ^[a-zA-Z0-9_.-]{1,64}$ || ! $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Usage: sudo $0 NODE_NAME BACKEND_BIND_IPV4" >&2
    exit 2
fi
if [[ $EUID != 0 ]]; then echo 'Run with sudo on a disposable backend VM.' >&2; exit 2; fi
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$2"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null
if [[ -e /etc/systemd/system/riverlb-lab-backend.service || -e /opt/riverlb-lab/backend.py ]]; then
    echo 'Lab service already exists; review it before replacing.' >&2; exit 1
fi
id riverlb-lab >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin riverlb-lab
install -d -m 0755 /opt/riverlb-lab
install -m 0644 "$script_dir/backend.py" /opt/riverlb-lab/backend.py
cat > /etc/systemd/system/riverlb-lab-backend.service <<EOF
[Unit]
Description=RiverLB functional test backend $1
After=network-online.target
Wants=network-online.target
[Service]
User=riverlb-lab
Group=riverlb-lab
ExecStart=/usr/bin/python3 /opt/riverlb-lab/backend.py --name $1 --bind $2 --port 8080 --unhealthy-file /run/riverlb-lab/unhealthy
RuntimeDirectory=riverlb-lab
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now riverlb-lab-backend.service
echo "Backend: http://$2:8080/ ; health: /healthz"
echo 'Allow TCP/8080 from the appliance backend self/SNAT addresses in the backend firewall.'
echo 'Mark unhealthy: sudo touch /run/riverlb-lab/unhealthy'
echo 'Recover: sudo rm /run/riverlb-lab/unhealthy'
