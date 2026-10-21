#!/usr/bin/env bash
# Runs only inside a disposable, rootless container.
set -euo pipefail
dnf -y --disablerepo='*' --repofrompath=riverlb-offline,file:///packages/ha-dependencies \
    --enablerepo=riverlb-offline --setopt=riverlb-offline.gpgcheck=1 \
    --setopt=riverlb-offline.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10 install /packages/riverlb-*.rpm
rpm -V riverlb riverlb-ha riverlb-appliance
/usr/bin/riverlb validate --config /etc/riverlb/riverlb.toml
# Check dependency resolution, file layout and a real management startup/login.
python3 /tests/firstboot.py
python3 /tests/rpm_smoke.py
# Removing packages must preserve user-created state and edited configuration.
printf '\n# operator change\n' >> /etc/riverlb/riverlb.toml
printf 'persistent-state\n' > /var/lib/riverlb/package-retention-fixture
rpm -e riverlb-appliance riverlb-ha riverlb
[[ -f /etc/riverlb/riverlb.toml.rpmsave ]]
[[ $(cat /var/lib/riverlb/package-retention-fixture) == persistent-state ]]
echo 'RPM installation, administration, service layout and removal checks passed.'
