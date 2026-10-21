# Appliance service security

The standalone and HA services run with a restricted systemd sandbox. They retain
root identity because current Linux network provisioning, firewalld authorization,
and Pacemaker integration require it. This implementation limits privileges and
writable paths; it does not provide complete separation between the traffic
daemon and privileged network control. A compromised process still has network
administration capability and access to RiverLB's private state.

The standalone capability bound contains only `CAP_NET_ADMIN`,
`CAP_NET_BIND_SERVICE`, and `CAP_NET_RAW`. These support managed networking, privileged listener ports,
ICMP probes, device binding, and HA gratuitous ARP. Standalone excludes other
capabilities, including mount, kernel module, identity switching, and broad
filesystem bypass privileges. `NoNewPrivileges` prevents children gaining privileges through
setuid programs or file capabilities. HA additionally retains `CAP_CHOWN`,
`CAP_FOWNER`, `CAP_SETUID`, `CAP_SETGID`, and `CAP_DAC_OVERRIDE` for fixed pcs setup
operations and hacluster-owned state/IPC. Consequently HA does retain broader
filesystem and identity privileges; removing these safely requires qualifying
separate provisioning and runtime helpers against a real cluster. The source
audit reports this distinction explicitly. Neither service grants `CAP_SYS_ADMIN`.

Both units use systemd's `OpenFile=` to pass a read-only host network namespace
descriptor named `riverlb-host-netns`. RiverLB compares its device and inode with its own
network namespace before contacting firewalld. This avoids requiring
`CAP_SYS_PTRACE` to inspect PID 1 under the capability bound. A process in a
different network namespace still skips host firewall provisioning. Direct
console launches fall back to inspecting PID 1 when permitted; an unverifiable
namespace produces a warning rather than silently skipping the integration.
The descriptor is marked close-on-exec before firewall commands run. This service
setting requires systemd 253 or later, as provided by the appliance's OS baseline.

The filesystem is read-only except `/etc/riverlb`, `/var/lib/riverlb`,
`/run/riverlb`, and the optional backup mount `/mnt/riverlb-backups`. HA also permits
the local Corosync, pcsd, and Pacemaker state directories used by the fixed cluster
helper. HA also shares the host's `/dev/shm` mount because Pacemaker's libqb
control channel uses shared-memory files. `NoExecPaths=/dev/shm` prohibits
executing files from that mount; `memfd_create` remains blocked. The standalone
service keeps shared memory inaccessible. Home directories remain read-only for existing SSH identity access.
OS password hashes are inaccessible. Publisher trust at
`/etc/riverlb-updater/update-trust.json` remains outside writable daemon paths;
install or rotate it through the appliance console before restarting the service.
The fixed root preflight helper prepares lifecycle directories before daemon
startup; its systemd `+` command prefix intentionally permits that preparation
outside the daemon's mount/capability restrictions. It accepts only the fixed
preflight operation and is not a general command-execution endpoint.

The services restrict socket families, namespace creation, realtime scheduling,
setuid file creation, personality changes, writable executable memory, and
dangerous syscall groups. Only HA permits packet sockets. The update activation
and boot recovery helpers run in separate fixed-operation units; these units have
their own filesystem permissions and are not executed as arbitrary administrator
commands supplied through the portal.

Scheduled backups require an independently mounted directory. The default unit
permits `/mnt/riverlb-backups` if it exists. For another destination, add only that
mount point through a service override and requalify the effective writable paths:

```ini
[Service]
ReadWritePaths=/mnt/site-riverlb-backups
```

Run the source audit and its rejection regressions during development:

```sh
python3 scripts/audit-appliance-security.py
python3 tests/appliance/service_hardening.py
```

On a disposable systemd machine with firewalld running, exercise the real daemon
under both service sandboxes and verify isolated namespaces skip the host
firewall. The fixture uses loopback-only listeners and private databases; it
does not create or remove firewall rules:

```sh
sudo python3 tests/appliance/firewall_sandbox.py --binary /usr/lib/riverlb/base/riverlb
```

On a disposable, installed AlmaLinux appliance, run the packaged live audit as root:

```sh
sudo /usr/libexec/riverlb/riverlb-audit-security --live --service riverlb.service
# For an HA appliance:
sudo /usr/libexec/riverlb/riverlb-audit-security --live --service riverlb-ha.service
```

The source audit validates declared policy; it does not demonstrate kernel or
SELinux enforcement. The live audit reads effective unit restrictions, process
capabilities, private directory modes, and SELinux enforcing state without
changing the appliance. It reports retained root identity and operational
qualification as explicit limitations.

Before publishing an image, verify boot and management access, configuration
apply/rollback, real firewalld and VLAN provisioning, ICMP/TLS probes, signed
update recovery, mounted backups, and certificate generation in the restricted
unit. For HA, also verify SSH synchronization, pcs setup/actions, raw ARP, owner
loss, and fencing. Review the service's SELinux AVC denials and qualify a minimal
policy against those operations while SELinux remains enforcing. The RPM's
`riverlb-sandbox.cil` grants systemd (`init_t`) two narrowly scoped `mounton`
permissions: files labeled `shadow_t` for the inaccessible password-file
placeholder, and directories labeled `semanage_store_t` for the HA preparation
helper's writable `/var/lib/selinux` mount. The helper uses that policy store
when `semanage` registers the dedicated SSH port. AlmaLinux 10 otherwise denies
namespace setup before the process starts, with `226/NAMESPACE` and an AVC for
`mounton` on `/etc/gshadow` or `/var/lib/selinux`. These system-wide permissions
apply to systemd's sandbox setup; they add no file or directory read/write
permissions and no permission to the RiverLB process itself. Broader SELinux
compatibility still requires installed appliance qualification. Do not remove
the sandbox or disable SELinux to
make a failed qualification check pass.
