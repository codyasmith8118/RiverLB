# RiverLB appliance on AlmaLinux. Installation mode is selected by the boot menu.
# Only the public update trust key is included; no private keys, passwords or HA identities.
cdrom
lang en_US.UTF-8
keyboard us
timezone UTC --utc
rootpw --lock
selinux --enforcing
firewall --enabled --service=ssh
network --bootproto=dhcp --device=link --activate --hostname=riverlb-unconfigured
services --enabled=NetworkManager,firewalld,chronyd --disabled=sshd,riverlb,riverlb-ha,pcsd,pacemaker,corosync,riverlb-ha-sshd
firstboot --disable
%packages
@core
NetworkManager-tui
firewalld
iproute
openssl
python3
policycoreutils
chrony
openssh-server
%end
%post --nochroot --erroronfail --log=/mnt/sysroot/var/log/riverlb-image-install.log
set -eu
mkdir -p /mnt/sysroot/var/tmp/riverlb-packages
tar -xf /run/install/repo/riverlb-packages.tar -C /mnt/sysroot/var/tmp/riverlb-packages
chroot /mnt/sysroot /bin/sh -c 'dnf -y --disablerepo="*" --repofrompath=riverlb-offline,file:///var/tmp/riverlb-packages/ha-dependencies --enablerepo=riverlb-offline --setopt=riverlb-offline.gpgcheck=1 --setopt=riverlb-offline.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10 install /var/tmp/riverlb-packages/riverlb-*.rpm'
rm -rf /mnt/sysroot/var/tmp/riverlb-packages
chroot /mnt/sysroot systemctl enable riverlb-firstboot.service
chroot /mnt/sysroot systemctl enable riverlb-bootstrap-network.service
chroot /mnt/sysroot systemctl disable riverlb.service sshd.service
# Keep systemd boot progress from overwriting the interactive setup prompts.
# Service diagnostics remain available in the journal and status commands.
mkdir -p /mnt/sysroot/etc/systemd/system.conf.d
cat > /mnt/sysroot/etc/systemd/system.conf.d/riverlb-console.conf <<'CONSOLE'
[Manager]
ShowStatus=no
CONSOLE
# Brand console/boot presentation; retain distribution ID and package identity.
chroot /mnt/sysroot /usr/libexec/riverlb/riverlb-brand-appliance
# Installer-created machine identity must not be cloned into each appliance.
: > /mnt/sysroot/etc/machine-id
rm -f /mnt/sysroot/var/lib/dbus/machine-id /mnt/sysroot/etc/ssh/ssh_host_* /mnt/sysroot/var/lib/systemd/random-seed
# Preserve Anaconda network profiles, including operator-selected static IPs.
%end
