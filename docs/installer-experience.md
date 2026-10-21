# Installing a RiverLB appliance

Use the **RiverLB installer ISO** for a new appliance. Attach the ISO to a new VM
with at least 4 GiB of RAM, an x86-64-v3 compatible CPU, a supported virtual display,
an Ethernet adapter and an installation disk. The separate image-builder ISO
clears `vda` automatically and must never be used for an interactive installation.

1. Boot the installer ISO. Select **Test this media & install RiverLB appliance**.
2. In the graphical installation summary, select **Installation Destination**.
   Choose the target disk and review the storage layout and any existing data.
3. Select **Begin Installation** only after confirming the intended disk. Until
   this action, the interactive recipe requests no unattended partitioning or
   disk clearing. Quit the installer to abandon the installation.
   In **Network & Host Name**, configure IPv4 as **Manual** for a static address,
   enter the address, prefix/netmask, gateway and DNS, and enable the connection.
   Interactive installs preserve these network settings on the installed system.
4. When installation finishes, detach the ISO and reboot from the installed disk.
5. Complete RiverLB's guided setup in the VM console. It creates a unique device
   HTTPS certificate and your chosen administrator and recovery credentials.

The installation summary uses Anaconda's native storage workflow. RiverLB
provides product branding and an appliance package selection on the reviewed
AlmaLinux base. A separate desktop environment is not installed on the appliance.
Distribution identifiers, package signatures and licenses remain intact;
normal installer and console screens use the RiverLB product name and version.

If the graphical display cannot start, reboot the ISO and choose
**Troubleshooting → Install RiverLB appliance (text console)**. Text mode presents
the same storage choices with keyboard navigation. The default graphical mode
also retains Anaconda's own low-memory/display fallback. Serial-only setup is
not yet supported; use the VM's VGA console for initial installation and setup.

First boot provides five clearly separated steps:

1. Appliance hostname, with a default and input validation.
2. Assigned IPv4 management address. **N** opens NetworkManager's network editor;
   **R** refreshes addresses, and **Q** cancels.
3. RiverLB administrator and separate Linux root console recovery password.
4. A review showing hostname, interface, management URL and administrator.
   **APPLY** commits, **BACK** returns to setup, and **CANCEL** exits.
5. Certificate/account creation, firewall configuration and HTTPS readiness.

Passwords are hidden and excluded from the review, command arguments and setup
journal. The console prints the exact URL, normally `https://<management-IP>:18090`.
The first browser visit warns about the generated self-signed certificate; after
signing in, replace it under **System → Device Certificates**. Traffic listeners and HA
are configured through the management portal after setup.

Use a static management address or a DHCP reservation. The selected address is
bound explicitly and does not automatically follow subsequent DHCP changes.
SSH stays disabled. Keep the separate recovery password so you can sign in
locally if management networking is unavailable.

Older installer media reset network profiles to DHCP at the end of installation,
even when a static address was selected in Anaconda. On an affected appliance,
use **Configure networking** in first boot (or `sudo nmtui` from the VM console)
to edit the active connection, set IPv4 to **Manual**, enter the static settings,
and reactivate the connection. Verify the address with `ip -br -4 addr` before
selecting the management address. If setup already completed, changing the IP
also requires updating RiverLB's management binding and device certificate;
perform that change with console access available.

Only the automated image-builder recipe replaces network profiles with a generic
DHCP bootstrap profile, so exported images do not inherit the build VM's NIC.

If activation fails after the setup state is committed, the private activation
journal allows `riverlb-setup` to resume. Check
`journalctl -u riverlb-firstboot -u riverlb` from the local recovery console.
Setup never overwrites an existing application database without a valid resumable
journal; preserve backups and use the documented recovery procedure.

## If initial setup cannot start RiverLB

Use the VM's local console and sign in as `root` with the separate recovery
password chosen during setup. The web administrator is an application account;
it does not automatically create a Linux/SSH account.

```bash
systemctl status riverlb riverlb-firstboot riverlb-update-recovery --no-pager -l
journalctl -b -u riverlb -u riverlb-firstboot -u riverlb-update-recovery -n 100 --no-pager
ip -br -4 addr
ss -lntp
```

Include update recovery in the diagnostics because its failure prevents the main
service from starting. Setup preserves committed state after activation failure;
fix the reported service error and run `riverlb-setup` again to resume. Do not
delete the database or setup journals to make the wizard start over.

If the journal shows `226/NAMESPACE` and a permission denial mounting over
`/etc/gshadow`, check the installed RiverLB SELinux compatibility policy described
in [service security](service-hardening.md). Keep SELinux enforcing and the
password-file sandbox enabled. The RPM includes the required policy; updating
only the application binary does not install service or OS policy changes.

New images suppress systemd boot progress during console use, wait for console
initialization/splash shutdown, and temporarily reduce kernel console notices
while collecting input. The previous kernel console level is restored even if
setup is cancelled. Logs remain available through `journalctl`. Setup failure
output includes bounded service status/journal diagnostics. Its local HTTPS
readiness check bypasses environment HTTP proxies.

SSH is disabled by default. If you deliberately enable it for lab diagnostics,
start `sshd` and permit SSH in the management interface's firewalld zone. A working
network route alone does not make port 22 available.

## Builder qualification

Structural checks inspect the pinned ISO's GUI runtime, branding archive and boot
menus. Qualifying a candidate also requires a fresh VM boot and installation;
structural success alone is insufficient. Run `scripts/test-installer.sh` on a
disposable KVM builder, finish an installation, then repeat with an existing-disk
scenario before publishing. See [the appliance test plan](appliance-test-plan.md).
