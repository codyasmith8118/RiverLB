# AUTOMATED IMAGE BUILDER ONLY: the guest has one disposable virtual disk (vda).
%include /run/install/repo/riverlb-common.ks
text
ignoredisk --only-use=vda
clearpart --all --initlabel --drives=vda
autopart --type=lvm
bootloader --location=mbr
shutdown

# Only reusable images discard the build VM network identity. Interactive
# installs retain the networking selected in Anaconda.
%post --nochroot --erroronfail --log=/mnt/sysroot/var/log/riverlb-image-network.log
set -eu
# Replace installer NIC-specific profiles with a MAC/name-independent DHCP profile.
rm -f /mnt/sysroot/etc/NetworkManager/system-connections/*
cat > /mnt/sysroot/etc/NetworkManager/system-connections/riverlb-bootstrap.nmconnection <<'PROFILE'
[connection]
id=RiverLB bootstrap DHCP
type=ethernet
autoconnect=false
[ethernet]
[ipv4]
method=auto
[ipv6]
method=auto
PROFILE
chmod 0600 /mnt/sysroot/etc/NetworkManager/system-connections/riverlb-bootstrap.nmconnection
%end
