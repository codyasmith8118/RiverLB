# Configure appliance interfaces

Open **Network → Interfaces** and select **Configure** beside an Ethernet adapter.
Use this page for the appliance's IP addresses, DHCP, DNS, MTU, and default routes.
Use **VLANs**, **Self IPs**, and virtual servers for traffic addresses.

New NICs have no automatic DHCP profile. Reusable images bind bootstrap DHCP to
the first Ethernet NIC's name and MAC on first boot, so that profile cannot move
onto a second NIC. Interactive installations retain the installer network settings.
Adding a NIC does not change existing connections or routes.

## Configure an adapter

1. Select **Configure** and review IPv4 and IPv6 settings.
2. Choose **None** to leave that family unconfigured, **Static** for addresses
   with prefixes, or **DHCP / Automatic** to request addresses. Separate multiple
   addresses and DNS servers with commas.
3. Leave **Allow default routing** disabled for traffic adapters. Enable it only
   when this adapter should provide a default gateway. Automatic addressing can
   be used without accepting a DHCP/IPv6 default route. Automatic DNS is also
   ignored when default routing is disabled; explicitly entered DNS servers still
   participate in the host resolver configuration.
4. Set the route metric if needed. Lower values are preferred. New profiles use
   600. Existing profiles retain their metric, or use the normal Ethernet default
   of 100 when NetworkManager reports automatic selection.
5. Click **Apply interface changes**, verify connectivity, then click **Keep
   interface changes** within 90 seconds. **Revert interface changes** restores
   the previous connection immediately. **Done** returns to the list; it does
   not confirm a trial.

For a new NIC, **Enable and apply interface settings** brings the link up with
the chosen settings. Leave both address families set to **None** to enable a
link without DHCP or IP addresses. **Enabled** in the interface list describes
the administrative state; **Link state** describes the physical connection.
An enabled NIC can have a down link if its cable or virtual connection is disconnected.

Use **Disable interface** to disconnect a configured NIC and lower its link.
Click **Keep interface changes** within 90 seconds to also turn off reconnection
on boot. Revert or let the timer expire to restore the previous connection.
Saved addresses and other settings are retained for **Enable interface**, which
also restores reconnection on boot when confirmed. Disabling the interface that
carries management, or a parent with configured traffic VLANs, is rejected;
move those bindings first.

For an inactive saved connection, first use **Enable interface**, keep
that change, then reopen the editor. This lets NetworkManager capture the active
profile before changing it. New adapters need no separate activation step.

The yellow appliance indicator shows when an interface change awaits confirmation.
Return to **Interfaces** to keep or revert it. Interface edits do not change the
traffic revision; **Discard and reload** does not undo a confirmed interface change.
Finish the interface trial before applying traffic configuration.

## Preserve management access

The management listener binds to the IP configured in **Settings**. The interface
editor will not remove that address from a static profile or disable its
reconnection on boot. To move management, add the new static IP alongside the old
IP and confirm the interface change. Then change the management binding and device
certificate in Settings, confirm connectivity at the new address, and remove the
old IP. Reserve static IPs outside DHCP allocation or through DHCP reservations.

Reactivating a connection can briefly interrupt traffic. Configure adapters before
attaching untagged self IPs or VIPs. Adapters carrying those managed addresses
cannot be edited here until the addresses are removed or moved to tagged VLANs:
NetworkManager could otherwise remove RiverLB-owned IPs. Tagged VLAN parents must
retain an MTU of at least 1500.

## Persistence and recovery

These are device-local NetworkManager profiles. Confirmed settings persist across
boots but are not pushed to the HA peer or included in the application database
backup. Keep an OS configuration backup for appliance recovery.

Trials change runtime profiles only; Keep writes them to disk. NetworkManager owns
the rollback timer, so closing the browser or restarting RiverLB does not cancel
rollback. A reboot before confirmation retains the previous persistent profiles.
Do not restart NetworkManager or make concurrent network changes from other tools
during a trial: checkpoints belong to that running process. Confirmation rejects
a missing checkpoint. Use the local console and `nmtui` for OS network recovery.

Editing requires an administrator session, managed network mode, NetworkManager,
and system D-Bus access. Operators, read-only accounts and API tokens cannot edit
device networking. Loopback, VLAN, bridge/bond member and unsupported profile types
are not edited here. Appliance packages provide the dependencies; source deployments
must supply NetworkManager and system D-Bus tools separately.

## Existing installations

Install updated RiverLB and appliance RPMs for the GUI and new-NIC policy.
The appliance RPM reloads NetworkManager's configuration without restarting
existing connections. If installing the policy manually, run
`sudo nmcli general reload conf` to load
`/etc/NetworkManager/conf.d/90-riverlb-network-defaults.conf` without restarting
NetworkManager. Existing DHCP profiles are retained: disable unwanted DHCP and
default routes explicitly under Interfaces. The policy prevents new automatic
profiles; it does not delete existing operator configuration.

Older images may have an unbound **RiverLB bootstrap DHCP** profile. Confirm
interface settings through the GUI to bind that connection to its intended
interface before adding more NICs. New images bind bootstrap networking before
NetworkManager starts and need no manual conversion.

Development checks:

```sh
python3 tests/appliance/network_defaults.py
cargo test interfaces::tests
bash scripts/test-network-manager.sh
```

The last check runs real NetworkManager in a disposable container with no external
network. It tests rollback, timeout, disk persistence, and recovery after runtime
profiles are cleared. Real NIC hotplug, DHCP/IPv6 advertisements, SELinux,
management reconnection and firmware boot still require the
[appliance qualification plan](appliance-test-plan.md).
