# AlmaLinux application packages

Build and test candidates without installing anything on the host:

```bash
scripts/build-rpm.sh
scripts/test-rpm.sh
```

Requirements: x86-64 Linux, rootless Podman, Git and Python 3.11 or newer. The
builder uses a digest-pinned AlmaLinux 10.2 base and Rust/Cargo 1.92.0 RPMs.
It downloads OS packages and locked Cargo dependencies. Podman named volumes
cache dependencies and compiled objects. Output is `dist/rpm/`: base/HA/appliance-setup RPMs,
checksums, source identity and the installed builder package inventory. Dirty
workspace builds are marked in the manifest with a source-content fingerprint.
Set `RIVERLB_RPM_RELEASE=2` to create another RPM release of the same app version.

The base RPM supplies `/usr/bin/riverlb`, `riverlb.service`, a private
`/etc/riverlb/riverlb.toml`, and `/var/lib/riverlb`. Configuration is
`%config(noreplace)`; upgrades retain local edits. Application database and keys
are not package payloads. Install/upgrade does not create accounts, enable or
restart services. The package includes signed offline standalone updates and recovery; see [offline updates](../docs/offline-updates.md). HA rolling software activation remains blocked pending qualification.

The bootstrap config has loopback HTTP and no virtual servers, VLANs or routes.
It is a setup starting point, not the final network-accessible HTTPS first-boot
experience. The service currently runs as root for managed Linux networking;
systemd capability/filesystem/syscall hardening is implemented and SELinux behavior still requires appliance qualification. See [service hardening](../docs/service-hardening.md).

For base-RPM installations without the appliance addon, initialize an account
on a disposable test VM:

```bash
sudo riverlb admin --database /var/lib/riverlb/riverlb.db
```

The command prompts for a password. Configure a specific management address and
device HTTPS certificate before exposing the GUI. Start `riverlb.service` for
standalone operation. Loopback setup can be accessed through an SSH tunnel to
port 18090. Do not change management firewall policy without confirming access.

Appliance images instead use the console `riverlb-setup` wizard. The appliance
addon gates the systemd service until management setup is ready; do not create
the appliance administrator database separately before running that wizard.
An existing incomplete database is preserved and requires management recovery.

The optional `riverlb-ha` RPM supplies the existing HA unit and agents and depends
on Pacemaker, Corosync, pcs and SSH clients. AlmaLinux's `highavailability`
repository must be available when installing it. Select/install fencing agents
for the actual deployment separately. Follow [HA setup](../docs/high-availability.md)
and use `riverlb-ha.service` instead of the standalone unit; the packaged units
conflict to prevent concurrent starts. Installing the HA package does not create
a cluster, HA credentials or an HA configuration.

`test-rpm.sh` installs both packages into a clean, rootless container, checks
runtime dependencies and permissions, creates a fixture admin, starts a packaged
daemon and tests login and TCP forwarding, then checks that removal preserves edited config and
user state. It does not test systemd boot, real firewalld, SELinux policy or real
fencing. These remain VM release gates. Unsigned artifacts are for testing only;
production requires a reviewed signing/promotion pipeline and full CI evidence.

The optional `riverlb-appliance` RPM adds console initial setup. See
[appliance media and first boot](../appliance/README.md). It is not enabled by
package installation; the image recipe enables the first-boot unit.
