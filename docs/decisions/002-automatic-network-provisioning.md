# 002: Provision Linux networking by default

Save and apply should create the VLANs, self IPs and routes the user configured.
Saving those objects without provisioning them caused a misleading successful
traffic apply and unreachable self IPs.

Enable managed networking for ordinary `serve`. Retain `--manage-network` for
compatibility and add `--external-network` as the explicit OS-provisioned opt-out.
The process still needs Linux `CAP_NET_ADMIN`; permission failures must reject
the apply, preserve the saved revision and report the required capability.
There is no automatic elevation or silent fallback to saving network objects.

Reuse the existing transaction ordering, compensating rollback and ownership
rules. Startup provisions the saved configuration before binding listeners;
successful hot apply provisions the delta before committing the new revision.
Clean shutdown removes owned resources. Existing host objects are not adopted.
Tests cover default startup and hot apply in isolated network namespaces,
including client-side ping of assigned IPv4 and IPv6 self IPs over tagged and
untagged links. VLAN configuration creates local Linux resources; Hyper-V and
the external network must separately carry the configured tag or route to it.

New VLAN forms require explicit adapter selection instead of preselecting `eth0`.
Portal tests verify that selecting `eth1` survives save, reload, and interface
inventory refresh, including when that adapter is temporarily absent.
