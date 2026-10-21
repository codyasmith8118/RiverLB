# Configure your first service

This guide assumes you can sign in to RiverLB. For account setup, use the
[source quick start](../README.md#run-from-source) or complete the appliance console
wizard. Installed appliances display their HTTPS management URL at the end of setup.

## Understand drafts before editing

Configuration pages open as lists. Select an object to edit it, or select Create
to open a new draft. **Done**, at the bottom of an editor, returns to the list and
keeps your changes in the draft. It does not activate them.

The global **Save and apply all changes** action commits the entire draft across
all pages. A yellow **Not yet applied** indicator means you have pending edits.
**Discard and reload** replaces the whole draft with the active configuration.
Export the draft first if you need to preserve it.

Some actions apply immediately: certificate generation/import, account changes,
statistics reset, persistence clearing and operations settings. Read the action's
confirmation rather than assuming Done or Discard will undo it. The
[portal reference](portal.md) explains the page groups.

Physical interface settings use their own **Apply interface changes** and
connectivity confirmation. They are local to each appliance and separate from
the traffic draft. See [interface management](interface-management.md).

## Create a pool

1. Open **Local Traffic → Nodes** if you want to define reusable backend endpoints.
   Enter each node's name, IP and service port. You can assign a node monitor here.
   Nodes can also be populated while adding pool members.
2. Open **Local Traffic → Pools** and select Create. Give the pool a unique name.
3. Add members using separate name, IP and port fields, or choose existing nodes.
   A member is a backend service endpoint, not the client-facing address.
4. Start with **Round robin** and select a suitable health monitor.
5. Select Done to return to the pool list.

For a web application, use an HTTP or HTTPS monitor that matches its real path,
Host header, expected status and TLS trust. TCP only proves the port accepts a
connection. A working TCP check with a failing HTTP check often means those
application settings differ. See [health monitors](health-monitors.md).

## Create a virtual server

1. Open **Local Traffic → Virtual Servers** and select Create.
2. Enter a name, destination IP and service port. Choose a common port from the
   dropdown or enter a custom port.
3. Choose **TCP**, **HTTP** or **UDP**. HTTP enables request-level processing;
   TCP forwards an opaque byte stream. UDP needs a compatible datagram monitor.
   See [virtual-server types](udp-load-balancing.md).
4. Select your pool under Default pool. The pool supplies members and balancing
   settings; edit those on the Pools page.
5. Start with **No persistence** unless your application needs affinity.
6. Select the ingress VLAN for a managed VIP, and configure the backend VLAN/source
   translation if needed. See [two-arm networking](two-arm-networking.md).
7. For TLS termination, select a virtual-server certificate. If the backend also
   requires TLS, assign a verified Server TLS profile.
8. Select Done, review the complete draft, then Save and apply.

An empty configuration is valid; you do not need to create a listener just to
administer the appliance. Named pools and inline members are alternatives, so a
virtual server cannot specify both. Deleted or renamed references must be fixed
in the same draft before applying.

## Check the result

Overview shows live status icons for virtual servers, pools and members. New or
changed backends can remain down while background probes establish readiness.
Statistics retain totals across applies and restarts. Hover or focus a control
for help, and inspect monitor diagnostics when a backend stays down.

Round robin selects among eligible members. TCP selects once per connection, so
browser keepalive can repeatedly use one backend. HTTP processing can select per
request; images and scripts also take turns. Weights, priorities, capacity and
persistence affect the sequence. UDP pins a client IP/port flow until idle expiry.

Applying ordinary traffic changes preserves established TCP sessions. UDP flows
restart. Network/address edits can interrupt either. A failed validation, bind or
commit keeps the previous revision and attempts rollback of prepared OS changes.
Management/network changes can require [connectivity confirmation](configuration-recovery.md).

## Import, history and conflicts

Import / Export can load JSON or a saved revision into the draft. Review it, then
apply explicitly. JSON export contains configuration, not accounts, private keys
or a full appliance backup. Use [encrypted backups](appliance-operations.md#encrypted-backups)
for recovery.

A revision conflict means someone else applied first. Export your draft, reload
and reconcile the differences. RiverLB will not silently overwrite that newer
revision. Editing the initial TOML file does not replace database settings; use
the [stopped-daemon import command](operations.md#configuration-and-database) when needed.

For hostname routing, certificate issuance and redirect behavior, continue with
[domain routing](domain-routing.md) and [certificates](certificates.md).
