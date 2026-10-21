# Active/standby RiverLB appliances

RiverLB HA keeps a management daemon running on both nodes. Pacemaker/Corosync owns one `riverlb-traffic` resource, and its OCF agent activates exactly one data plane. Native hooks acquire/release floating IPv4/IPv6 self IPs and VIPs, listeners, ingress return routes and firewall rules. Promotion sends gratuitous ARP and unsolicited IPv6 neighbor advertisements. Standby configuration is read-only for traffic; management addresses, device certificates, administrator accounts and local self IPs stay local.

The default topology is two appliances with working out-of-band power fencing; no third appliance or quorum witness is required. An independent network quorum witness is optional. A missed heartbeat is not proof that the other appliance stopped serving. Pacemaker must confirm fencing before starting traffic on a replacement when the former owner cannot be stopped. A paused VM is included in this failure model. Never disable fencing, use a dummy fence agent, or change `no-quorum-policy=stop` to `ignore`.

References: [Red Hat cluster quorum/fencing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/configuring_and_managing_high_availability_clusters/index), [OCF resource-agent contracts](https://clusterlabs.org/pacemaker/doc/2.1/Pacemaker_Administration/pdf/Pacemaker_Administration.pdf), [AlmaLinux HA repository](https://wiki.almalinux.org/repos/AlmaLinux).

## Supported replication and limits

The active node pushes snapshots over OpenSSH with strict, pinned host-key checking, using a dedicated key with a forced receive command. Snapshots include virtual servers, pools, nodes, monitors, profiles, RiverRules, domain routes, common VLAN definitions/static routes, configured floating self IPs, virtual-server certificates/private keys, pending virtual-server CSRs, virtual-server ACME schedules/accounts, and source/cookie persistence assignments. Management certificates and credentials are excluded. VLAN parent-interface names and non-floating self IPs are overlaid from the receiving node's configuration. Use the same logical VLAN/self-IP names on both nodes.

Automatic replication is asynchronous, every two seconds by default. Select Manual in the HA Device Group page to send traffic changes only with **Sync traffic configuration now**. Background checkpoint refresh continues using the last explicitly synchronized configuration, so manual mode does not expire an otherwise healthy standby merely because no edits were made. While pending configuration changes exist, persistence remains at the last synchronized assignments; synchronize before moving traffic. **Force failover** from the active node synchronizes current changes before requesting the move. The banner/API reports role, last send/receive, peer revision and synchronization errors. Changes or assignments made after the last acknowledged snapshot can be lost on failover. There is no distributed transaction committing an edit to both nodes. A peer keeps its own local configuration revision numbers; these are not cluster-wide sequence numbers. Expired/out-of-order snapshots and snapshots from a peer that is not the cluster's current owner are rejected. A standby with no recent, matching checkpoint cannot activate. Checkpoint validity defaults to 300 seconds and is configurable from three synchronization intervals to one hour. Clock synchronization is required; incoming timestamps more than five seconds in the future are rejected.

Source affinity and opaque/hashed cookie assignments are replicated with their backend endpoints and absolute expiry, subject to configured capacity and member validation. Private checkpoints retain these assignments across standby restarts. Snapshots are limited to 32 MiB; an excessive snapshot fails synchronization and is visible as an error. These files contain sensitive persistence identifiers and require root ownership/private permissions.

Every daemon restart begins in standby. Before changing ownership or an active configuration, RiverLB writes a private ownership journal containing the old/new network definitions and managed firewall rules. Startup withdraws floating addresses and rules recorded in that journal, including obsolete VIPs left by an interrupted configuration change. The active node also checkpoints its last acknowledged snapshot, allowing a restart to recover from that checkpoint while the cluster still controls promotion. Failed withdrawal or uncertain rollback requires fencing.

Live TCP sockets, TLS cryptographic state, in-flight HTTP requests and WebSocket connections are **not** replicated. Existing sessions close during demotion/fencing and clients must reconnect. Traffic statistics, audit history, administrator accounts/sessions, device certificate requests, device renewal schedules and device keys stay local. External backend trust/PEM files must be installed separately with identical paths on both nodes. Incoming virtual-server TLS must use managed certificates in HA mode. Only the active appliance runs ACME issuance; standby management certificates should be provisioned externally or renewed before they expire.

Place appliances in independent failure domains appropriate to the deployment. The appliance includes fencing integrations; you supply permission to control the correct VMs or physical servers. RiverLB does not require a particular hypervisor. Machine identifiers depend on the integration.

## Deploy an ISO-installed appliance from the GUI

New appliance builds include the HA integration and its full package dependency
set on the ISO. Installation needs no package downloads. HA services remain off
until an administrator deploys them; ordinary standalone operation is unchanged.
Older installations need a matching updated base, HA, and appliance RPM set.

On each appliance, open **High Availability → HA Configuration** over HTTPS:

1. Save the group with the actual local hostname, peer hostname, reachable local
   and peer cluster IPs, and the floating self IP names. Reverse local and peer
   fields on the second appliance. Keep cluster addresses local and non-floating.
2. Under **Deploy HA on this appliance**, enter your current RiverLB password
   and authenticator code if enabled. Choose a separate cluster password of at
   least 12 bytes, using the same value on both appliances. Select **Prepare local
   HA services** on each appliance. This prepares pcsd, its cluster account,
   firewall permissions, synchronization keys, and a restricted SSH endpoint.
   It refuses to reset credentials on an existing cluster.
3. Copy each appliance's displayed synchronization public key, host public key,
   and host fingerprint into the other appliance's peer fields. Verify the
   fingerprint directly in the peer's HTTPS GUI. Select **Install verified peer
   trust** on both appliances. No private key is copied.
4. Re-enter the cluster password and your current administrator password, then
   select **Authenticate cluster hosts** on each appliance. Check the result
   under deployment status before continuing. Password fields clear after each
   request; passwords are not saved in HA settings, logs, or command arguments.
5. Select **Start HA standby service** on each appliance. This stops standalone
   traffic and switches services. Management briefly disconnects; refresh after
   it starts. Confirm that both appliances report Standby.
6. Select **Provision two-node cluster** on the initial primary only. This
   creates the traffic resource disabled. Under **Configure failover
   protection**, choose your hosting platform and an installed integration.
   Enter its management connection, discover machines if available, and match
   each appliance's cluster name to the correct machine. Save the protection
   connection from one appliance; the cluster shares it. Follow the checks below
   and test actual power fencing for both appliances before enabling traffic.
7. Select **Seed initial primary** on exactly one appliance, then **Enable
   cluster traffic**. Check Configuration Sync and perform a controlled failover.

Deployment requires an administrator session and password/MFA reauthentication.
Operators and API tokens cannot deploy HA. A fixed, short-lived systemd helper
performs privileged preparation separately from the management daemon. Requests
are private, expire after 60 seconds before processing, and are removed when read
or when the helper stops. Failed stages are visible in deployment status; there
is no automatic rollback of a partially completed cluster deployment. Correct
the reported problem and retry that stage. Existing clusters require a planned
maintenance procedure for credential or key rotation.

The dedicated synchronization listener uses TCP 2223, only key authentication,
a pinned host key, and a forced receive command. It does not enable ordinary
management SSH or change its authentication policy. Existing manually configured
HA deployments retain their default SSH port 22 unless explicitly migrated.
Preparation opens HA services and TCP 2223 in the cluster interface's current
firewall zone, without reloading firewalld. Use an isolated, trusted cluster
network and the intended zone policy. Settings and keys remain device-local.

Real two-appliance boot, SELinux, synchronization, fencing and partition tests
remain required qualification; package/helper/GUI tests do not establish safe
failover on a particular deployment platform.

## Install dependencies and integration files (source deployments)

On AlmaLinux 9/10, enable the `highavailability` repository and install the HA tools. Confirm package availability for the installed release using the AlmaLinux repository documentation above.

```bash
sudo dnf config-manager --set-enabled highavailability
sudo dnf install pacemaker corosync pcs resource-agents fence-agents-all corosync-qdevice openssh-clients python3 iproute
cargo build --release --locked
sudo deploy/ha/install.sh
```

The installer copies the release binary, OCF agent, authority helper, cluster helper and `riverlb-ha.service`. It does not start services or create a cluster. Configure `/etc/riverlb/riverlb.toml`, create the initial administrator/database, and install a node-specific `/etc/riverlb/ha.json` with mode 0600. Use [node-a.example.json](../deploy/ha/node-a.example.json) as a starting point. The HA socket and state-file parent directories must be root-owned and not writable by other users. The service creates `/run/riverlb` and `/var/lib/riverlb` with mode 0700. Network changes and address announcements require `CAP_NET_ADMIN` and `CAP_NET_RAW`; firewalld changes also require authorization. The supplied service runs as root.

Use the exact Corosync node names in `node_id`/`peer_id`, matching their operating-system hostnames. On the second node, reverse those IDs and the SSH target. Keep `cluster_id`, the ordered `floating_self_ips` list and logical VLAN names identical. Configure different management addresses and different non-floating self IP addresses. A VIP cannot equal a non-floating self IP. HA listeners must use explicit, non-loopback IPs.

For the current VLAN 11 example, `external-floating` could be `192.168.11.69/24` and the virtual server VIP `192.168.11.70:8080`. List `external-floating` in `floating_self_ips`; RiverLB derives ownership of `192.168.11.70` from the virtual server configuration. Give each node an additional unique, non-floating self IP on this VLAN. The host interfaces and switches must carry VLAN 11 for both nodes.

Generate a separate synchronization SSH key on each appliance and pin the peer host key after verifying it through a trusted channel. Permit that key on the peer only with a forced command, for example in root's `authorized_keys`:

```text
restrict,command="/usr/bin/riverlb ha --socket /run/riverlb/ha.sock receive" ssh-ed25519 <peer-sync-public-key>
```

The forced command receives JSON on stdin; it cannot activate/deactivate the appliance or execute arbitrary shell commands. Keep keys and `/etc/riverlb` private. `ssh_program` normally defaults to `/usr/bin/ssh`; its configurable override exists for controlled test fixtures, not to bypass SSH verification in deployment. Do not disable SELinux to work around an installation error; validate the service and SSH/socket accesses under the site's enforced policy.

## GUI setup and operation

Open **High Availability → HA Configuration** on each appliance. Enter the group name, local and peer Corosync names/IPs, floating self IP names, synchronization mode, and the IDs of operator-configured fencing resources. Reverse local/peer fields on the second appliance. Group membership and floating-address changes require standby and a service restart; synchronization mode applies immediately. Set the same mode on both appliances so it remains consistent after failover.

For an initial GUI setup, start the installed binary with `sudo /usr/bin/riverlb serve --config /etc/riverlb/riverlb.toml --database /var/lib/riverlb/riverlb.db`, save the group, then stop that process and start `sudo systemctl enable --now riverlb-ha`. Do not run both processes against one database. Without an explicit `--ha-config`, RiverLB discovers `/etc/riverlb/ha.json` on startup. The installer creates its private directories. Each appliance retains its local GUI group settings; these settings and SSH/fencing credentials are not part of traffic synchronization.

For source deployments or older installations without GUI deployment, both nodes require the installed HA packages/integration, restricted SSH synchronization keys and pinned host keys, and platform-specific fencing credentials configured by the operator. Authenticate both pcs hosts first (for example `pcs host auth riverlb-a addr=NODE_A_IP riverlb-b addr=NODE_B_IP -u hacluster`, entering the cluster password interactively). These are installation/trust prerequisites, not traffic settings.

On the first appliance, click **Provision two-node cluster** once. This creates the two-node Corosync cluster, enables startup wait-for-all and creates the traffic resource disabled. It refuses to overwrite an existing cluster. If provisioning fails partway through, traffic remains disabled; inspect the reported pcs error and reconcile the partial cluster before retrying. It does not create or assume a fencing agent. Configure agents for your deployment platform, covering both appliance names, before enabling traffic.

Click **Seed initial primary** on exactly one appliance, then **Enable cluster traffic**. Open **High Availability → Configuration Sync** to check the saved local revision, last peer acknowledgment, last received configuration and synchronization mode. Use **Sync traffic configuration now** on active to push configuration to standby. Manual mode does not permit concurrent traffic edits on standby. It controls configuration replication only: quorum, fencing and ownership checks continue, and authority loss withdraws traffic in either mode. **Force failover** moves traffic to the peer when clicked on active, or to this appliance when clicked on standby. It requires a recent checkpoint and safe cluster authority; it does not bypass fencing or quorum. **Clear forced placement** removes the move constraint without forcing another move.

A persistent header on every page displays the operating-system hostname, Standalone/Active/Standby role with a light, and a separate configuration sync light linked to Configuration Sync. Green means the saved local configuration matches an acknowledged snapshot with a recent confirmation. Yellow means pending changes, no synchronization or stale confirmation. Red means a synchronization or appliance fault. Gray means standalone or unavailable status. A failed live status request clears the previous green confirmation. The header updates with normal status polling; successful saves and sync requests refresh it. The acknowledgment describes committed traffic configuration, not unsaved form drafts. Device-local settings and administrator credentials are not traffic sync contents. Check for a restart-required message after saving settings. Existing TCP/TLS connections reconnect after a move.

## Two-node quorum or optional witness

For a cluster provisioned outside the GUI, keep startup wait-for-all enabled. With exactly two members and no witness or automatic tie breaker, pcs sets `two_node=1` automatically; `two_node` is not an editable pcs quorum option. Set `wait_for_all` after cluster setup, while Corosync is still stopped, then start the cluster. For an existing running cluster, schedule a traffic interruption before stopping both members to change this setting.

```bash
sudo pcs quorum update wait_for_all=1
sudo pcs cluster start --all
sudo pcs cluster enable --all
sudo pcs property set stonith-enabled=true startup-fencing=true no-quorum-policy=stop stonith-action=off stonith-timeout=180s priority-fencing-delay=30s
```

Both nodes must have been visible before initial quorum is established. Check `sudo corosync-cmapctl` for `quorum.two_node = 1` and `quorum.wait_for_all = 1`, and confirm power fencing for each node before enabling traffic. The GUI verifies these effective quorum settings and the member names before creating its disabled traffic resource. The authority helper accepts either a network quorum witness or exactly two Corosync members with two-node quorum, wait-for-all, and explicit fencing coverage of both names. Fencing remains required in either topology.

### Optional witness

Install `corosync-qnetd` on the independent witness and enable its service. Set up pcs authentication and a two-node Corosync cluster using the documented workflow for the installed pcs version. Add the witness with the network `ffsplit` algorithm:

```bash
sudo pcs quorum device add model net host=WITNESS_IP algorithm=ffsplit
sudo pcs property set stonith-enabled=true startup-fencing=true no-quorum-policy=stop stonith-action=off
```

The authority helper reads live Pacemaker XML and Corosync's quorum settings. It refuses activation when quorum is absent, fencing is disabled/missing, the policy is unsafe, a dummy/manual fence agent is configured, or multiple owners are reported. On authority loss, RiverLB attempts immediate demotion. Pacemaker fencing remains the protection when a daemon/VM is frozen or cannot withdraw its addresses.

Keep management daemons running on both nodes. They always boot in standby and first withdraw stale floating ownership from an earlier process exit. Standalone `riverlb serve` is not an HA deployment: use the provided service/`--ha-config` consistently and do not start an additional standalone daemon.

## Configure failover protection

Failover protection gives the surviving appliance a way to stop its peer before
taking the VIP. It must use a management path that still works during the failure
you intend to survive. A heartbeat failure alone cannot establish that the old
traffic owner is stopped.

Open **High Availability → HA Configuration → Configure failover protection**.
Choose where the appliances run. The next dropdown shows the power-fencing
integrations installed on this appliance. Connection fields come from each
agent's real metadata, so the form shows the settings that implementation accepts.

| Platform | Integration and prerequisites |
| --- | --- |
| VMware vSphere / ESXi | VMware REST or SOAP; use the API supported by your management server and grant power control for both appliance VMs. |
| Microsoft Hyper-V | RiverLB's restricted SSH receiver on a fixed Windows host; complete the [Windows host setup](../deploy/ha/hyperv/README.md) first. |
| Proxmox VE | Proxmox API; provide the host, account and the appliance VM IDs. |
| KVM / libvirt | Virsh over SSH, or fence-virt where installed; the corresponding host-side service and permissions must be prepared. |
| Amazon Web Services | EC2 fencing with the required region, instance IDs and appropriate AWS credentials or instance role. |
| Microsoft Azure | Azure fencing with the required identity and resource settings; grant access to stop the appliance VMs. |
| Google Cloud | Compute Engine fencing with project, zone and appropriate service-account or instance credentials. |
| OpenStack | The bundled OpenStack SDK wrapper; supply the authentication endpoint, project and credentials, or a prepared cloud configuration. |
| Nutanix AHV | Nutanix management API and the appliance VM identifiers. |
| oVirt / Red Hat Virtualization | Its management API and appliance VM identifiers. |
| Physical server remote management | IPMI, Redfish and installed vendor controllers; create a separate protection connection for each server controller. |
| Managed power distribution | An installed PDU integration, with the correct outlet mapping for each appliance. |

An **unavailable** platform is not selectable as a working integration until its
agent can load. Discovery does not download packages. New ISO builds carry the
required Linux packages; older appliances need the matching updated package set.
A listed integration still needs credentials, host preparation where applicable,
and qualification against your actual platform. Metadata discovery is not a
successful connection or power test.

Give the connection a clear protection name. For VMs and multi-outlet devices,
select **Both appliances** only when that management endpoint can control both.
Match the displayed RiverLB names to the exact VM IDs, names or outlet numbers
expected by the integration. Discovery can help find them; verify the IDs against
the hosting platform before saving. A shared label or a similar VM name is not
enough. If appliances run on separate management hosts, create one connection for
each appliance instead.

An IPMI or Redfish connection addresses one fixed server controller. Select
**This appliance only** or **Peer appliance only**, then create another resource
for the other controller. RiverLB rejects a fixed-controller resource that claims
to protect both appliances. It also rejects duplicate mappings to the same
machine, unknown appliance names, dummy/manual agents and storage-only fencing,
which cannot establish that a VIP stopped serving.

Use **Check connection and find machines** when the integration supports listing.
Use **Check selected appliance power state** to read a mapped machine's state.
These checks request only list or status operations; they do not power off or
restart a machine. A successful check proves that the connection can read data.
It does not prove that the account can stop a VM, that fencing remains reachable
during a partition, or that the intended appliance loses its VIP after a stop.
Credentials clear from the form after each request; re-enter them for another
check or save.

**Save failover protection** creates a new cluster resource and records its ID.
It does not overwrite an existing resource with the same name. Credentials travel
to the local helper over a private short-lived request and to the agent or cluster
over stdin; they are not included in RiverLB's command arguments or audit text.
The cluster retains the credentials it needs for future fencing. Protect cluster
administrative access. Private key and credential-file paths must be root-owned,
private files under `/etc/riverlb`, with equivalent paths prepared on both nodes.
These files are not traffic-configuration synchronization contents.

Ordinary setup does not need JSON. **Advanced integration settings** exposes
additional metadata fields and bounded cluster delays. Local command overrides,
password scripts, debug-output paths and shell environment files are rejected on
the server as well as hidden from the form. Do not replace a missing integration
with a dummy agent to make setup pass.

Before enabling traffic, schedule a maintenance test that actually powers off
each appliance in turn through its configured fencing resource. Confirm the
correct machine stops, the other appliance can perform the operation, and only
one appliance owns the floating addresses during takeover. Test the failure paths
you rely on, including loss of the heartbeat while the active VM remains running.
Connection and power-state checks do not replace these disruptive tests. For
Hyper-V, the receiver targets a fixed host and does not follow live migration or
Windows failover-cluster placement; see its setup guide for those limits.

For an existing cluster managed with deployment tooling, the equivalent command
shape is shown below. It is not a runnable platform-specific configuration:

```text
pcs stonith create FENCE_RESOURCE_ID PLATFORM_AGENT PLATFORM_PARAMETERS \
  pcmk_host_list="riverlb-a riverlb-b" pcmk_host_map="riverlb-a:PLATFORM_ID_A;riverlb-b:PLATFORM_ID_B"
```

For separately managed devices, enter all relevant resource IDs in **HA Configuration → Fencing resource IDs**. GUI-created resources are added to the local list automatically. Before enabling traffic, the cluster helper verifies that those IDs are real STONITH resources, rejects dummy/manual agents, and requires explicit coverage of both appliance names. The authority helper retains its quorum and fencing checks. Test actual fencing for both appliances in the deployment before enabling automatic failover.

Existing groups saved with the previous platform-specific fields should be saved again with the generic fencing resource IDs. Old platform-specific values are discarded on that save.

## Initial activation and planned moves

Start the management services on both nodes:

```bash
sudo systemctl enable --now riverlb-ha
sudo riverlb ha --socket /run/riverlb/ha.sock status
```

For the initial deployment only, seed the validated configuration on the chosen first primary. The seed is a local, audited authorization that lasts for this process, not an automatic election or a fencing bypass. Do not seed both nodes. Then create the traffic resource with failure actions that fence the node if activation/withdrawal is uncertain:

```bash
# Run on the initial primary.
sudo riverlb ha --socket /run/riverlb/ha.sock seed
# Create disabled, pin initial placement, then enable.
sudo pcs resource create riverlb-traffic ocf:riverlb:traffic \
  binary=/usr/bin/riverlb socket=/run/riverlb/ha.sock \
  op start timeout=90s on-fail=fence \
  op stop timeout=90s on-fail=fence \
  op monitor interval=10s timeout=15s on-fail=restart \
  meta resource-stickiness=100 priority=100 --disabled
sudo pcs constraint location riverlb-traffic prefers riverlb-a=INFINITY
sudo pcs resource enable riverlb-traffic
```

Verify synchronization to standby, then remove the initial placement constraint (use its ID from `pcs constraint config`). Stickiness prevents automatic failback solely because a preferred node returns. Use `pcs resource move riverlb-traffic riverlb-b` for a planned move and `pcs resource clear riverlb-traffic` to remove the temporary move constraint afterward. Do not independently issue activation commands on both appliances; Pacemaker is the ownership authority. If all usable checkpoints expire, inspect the committed configuration and fencing state before an explicit recovery seed on the selected node.

CLI actions are `status`, `seed`, `activate`, `deactivate`, `export`, `receive` and `sync`; mutating ownership is for the local cluster controller. The Unix socket is private and verifies UID 0. `export` includes private keys/persistence identifiers; use it only over the restricted synchronization channel. Management `/api/v1/status` and the portal banner expose role/synchronization metadata, not the private replication bundle.

## Failover acceptance tests

Automated checks:

```bash
python3 tests/ha_agents.py
sudo unshare --net -- python3 tests/ha_failover.py
```

The native integration test uses real isolated node namespaces, IP addresses, TCP/HTTP traffic and IPv6. It tests standby without VIPs, quorum/fencing activation gates, configuration/certificate/CSR synchronization, local identity preservation, standby read-only enforcement, GUI/API group validation, manual/automatic sync behavior, persistence checkpoint restart, interrupted-change journal recovery, planned handoff with TCP session withdrawal, a paused old owner, fencing before replacement activation, client reconnection without flushing ARP/NDP caches, rejoin and quorum-loss withdrawal. Pacemaker decisions and SSH transport are fixtures; OCF/authority/fence-adapter contracts are tested separately. These tests do not substitute for a real Corosync/quorum/platform fencing qualification.

Before production, exercise the actual deployment and record results:

| Failure | Required result |
|---|---|
| Planned move | Old listeners/sessions close, old floating IPs disappear, replacement acquires them, and new requests succeed |
| Kill active daemon | Restart boots standby; cluster recovers one owner without duplicate VIPs |
| Power off active VM | Standby becomes owner after the cluster establishes safe ownership |
| Pause active VM | Replacement waits for confirmed fencing; resume cannot leave two owners |
| Partition Corosync links | Only the quorate, safely fenced side may serve |
| Lose optional witness and peer together | Traffic withdraws when quorum is lost; no autonomous promotion |
| Fence-control failure | No replacement activation while old ownership is uncertain |
| Break synchronization | Error appears; stale/unsynchronized checkpoint cannot activate |
| Restart standby | Management/local addresses remain local; replicated persistence reloads; no floating ownership |
| Rotate certificate/edit a pool | Peer receives the change before declaring synchronization successful |
| Disk full or failed network withdrawal | Controller reports failure; Pacemaker fences rather than treating an uncertain stop as success |

Measure actual detection/fencing/activation time and successful client recovery for IPv4, IPv6, tagged VLANs, HTTPS and application retries. Existing connections cannot survive this implementation's failover. Do not report zero interruption or production split-brain qualification until these deployment-specific tests pass.
