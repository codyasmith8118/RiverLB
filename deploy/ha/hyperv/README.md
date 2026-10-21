# Hyper-V failover protection

RiverLB can power off a specific Hyper-V VM when the cluster cannot safely stop
the old traffic owner. It connects to a restricted Windows SSH account; it cannot
run an arbitrary PowerShell command or control VMs outside an explicit allowlist.

This integration targets a **single, fixed Hyper-V host**. A host that becomes
unreachable cannot confirm fencing. Automatic takeover then waits rather than
risking two VIP owners. Live migration and Windows failover clusters need a
separate fencing design and qualification; this receiver does not locate VMs on
other hosts. Two appliances on one host also share that host's failure domain.

## Prepare the Windows host once

Use an elevated Windows PowerShell 5.1 session on the Hyper-V host. The host needs
the Hyper-V PowerShell module and Windows OpenSSH Server. If OpenSSH Server is
not installed, use your normal Windows feature installation process. Microsoft
describes the prerequisite in [Get started with OpenSSH for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).
Keep its listening port reachable from both appliances on the management network.

Copy this whole directory, including `Grant-RiverLBCimv2Read.ps1`, from the repository or the installed appliance's
`/usr/share/riverlb/ha/hyperv` directory onto the host. Review the scripts before
running them and unblock your trusted local copies if Windows marked them as
downloaded files. The installer creates a dedicated, non-administrator local
account with Hyper-V Administrators membership, protects the receiver and
allowlist, and limits that account to the receiver with key authentication.
Existing SSH users retain their authentication configuration.

For host-information queries from SSH key logons (Network/S4U), the installer
grants the dedicated account SID **Enable Account/read + Remote Enable**
(`0x21`) on `root\cimv2` only. This grant has no child inheritance and adds no
method-execution or write rights. Existing namespace permissions and auditing
are preserved. Before the first change, the installer saves the original
security descriptor as `%ProgramData%\RiverLB\Fencing\root-cimv2-original.sd`,
readable and writable only by SYSTEM and Administrators. Reruns retain that
backup; a failed verification restores the descriptor and stops installation.

The fixed receiver process uses `RemoteSigned` so Windows' default script
restriction does not prevent it from starting. The installer leaves the machine
and user execution policies unchanged; centrally enforced policies still apply.
The receiver script is writable only by SYSTEM and Administrators.

First, select the two VM IDs. Names are only used here to find the stable GUIDs:

```powershell
Get-VM | Format-Table Name, Id, State
$allowedVMs = @(
    (Get-VM -Name 'riverlb-a').Id
    (Get-VM -Name 'riverlb-b').Id
)
```

On both appliances, finish **Prepare local HA services** in the HTTPS GUI. Copy
their displayed synchronization public keys. Each appliance keeps its private
key; do not copy a private key to Windows. Enter the public keys and the
appliances' non-floating source IP addresses:

```powershell
$publicKeys = @(
    (Read-Host 'Public key displayed by RiverLB A')
    (Read-Host 'Public key displayed by RiverLB B')
)
.\Install-RiverLBFencing.ps1 -AllowedVMIds $allowedVMs `
    -AppliancePublicKeys $publicKeys `
    -ApplianceAddresses '192.0.2.10', '192.0.2.20'
```

This does not stop either VM. It restarts Windows SSH after validating its
configuration. It prints the dedicated username, host public key, its fingerprint
and the allowed VM IDs. Verify the host public key/fingerprint directly in this
host session; do not trust a key obtained from an unverified network scan.

The allowed source addresses must match what Windows actually sees, including
any management-network NAT. If an existing Windows `AllowUsers`/`AllowGroups`
policy excludes the new account, update that policy through your host
administration process. Domain and Microsoft Entra accounts are not used by this
receiver. Do not add the dedicated user to the ordinary Administrators group.

## Finish in the RiverLB GUI

On **High Availability → HA Configuration → Failover protection**, choose
**Hyper-V** and enter:

| Setting | Value |
| --- | --- |
| Host address | The Windows host's reachable management IP or DNS name |
| SSH port | Usually `22`; use the actual Windows SSH port |
| Username | `riverlb-fence`, unless changed during host setup |
| Verified host public key | The complete `ssh-ed25519 …` public key printed on Windows |
| Appliance SSH identity | Keep `/etc/riverlb/ha-sync-ed25519` after GUI HA preparation |
| Appliance A/B mappings | Match each RiverLB cluster hostname to its VM GUID |

**Check connection / discover targets** reads only the allowlisted VMs. Check both
GUIDs against the Windows output before saving the resource. The host public key
is public configuration; the private SSH identity remains in a root-owned file on
each appliance. Both appliances must have key authorization on the host because
either may need to fence its peer.

Existing deployments can use a separate root-private key and pinned `known_hosts`
file under `/etc/riverlb` instead. Supply **either** the verified host public key
or the existing host file, not both. The agent refuses symlinks, group/world
readable key files, or writable parent directories. Install equivalent private
file paths on both appliances; private keys are never configuration-synchronized.

After saving, schedule a maintenance test that powers off each selected appliance
in turn. Fencing uses a hard power-off, equivalent to removing power, and confirms
that Hyper-V reports `Off`. A paused, missing, unknown or unconfirmed state is
never accepted as a successful stop. A connection check does not perform this
disruptive qualification test. Confirm that only one VIP owner serves traffic
during failover, and that both appliances can reach the host independently.

Microsoft documents [Stop-VM -TurnOff](https://learn.microsoft.com/en-us/powershell/module/hyper-v/stop-vm)
and [Windows SSH server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration).

## Verification in this repository

```bash
python3 tests/ha_hyperv_fencing.py
python3 tests/ha_hyperv_fencing.py --ssh-smoke
```

The optional SSH smoke test starts a disposable loopback OpenSSH server and
simulates VM states in temporary files. It verifies the actual encrypted
transport, strict host-key pinning, key authentication and fixed receiver
protocol. It does not contact Hyper-V or prove that a particular Windows host can
power off its VMs. Windows receiver/host policy and real power-fencing tests remain
required before enabling automatic failover.
