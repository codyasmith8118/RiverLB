# Portal reference

Use [the first-service guide](web-configuration.md) for a walkthrough. This page
explains where settings live and which actions change running state.

## Find the right page

| Section | Pages and purpose |
|---|---|
| Overview | Live service status, appliance role, hostname and configuration sync indicator |
| Local Traffic | Virtual Servers, Pools, Nodes, Domain Routing, Health Monitors, Profiles and RiverRules |
| Network | Interface inventory, VLANs, Self IPs and Routes |
| High Availability | HA Configuration and Configuration Sync, including manual sync and controlled failover |
| System: security | Device Certificates, Virtual Server Certificates, Local Administrators and Management Security |
| System: operations | Settings, Statistics, System Health, Alerts, Backups, Audit Events, Application Updates and Import / Export |

Object pages use a list and a separate editor. Click a name to edit. The bottom
Done action returns to the list and retains the draft. Repeated Create clicks
reuse an unnamed draft instead of adding empty rows indefinitely. Browser back
and forward follow page hash URLs without discarding pending traffic edits.

The persistent header identifies the appliance hostname and Standalone, Active
or Standby role. Its sync indicator concerns **saved HA traffic configuration**;
the yellow draft indicator concerns **unsaved edits in this browser**. These are
separate states. See [HA synchronization](high-availability.md).

## Save behavior

| Action | Result |
|---|---|
| Edit a traffic/network object, profile or rule | Stages a draft across pages |
| Done / return to list | Keeps the draft without applying it |
| Save and apply all changes | Validates and commits the full draft as one revision |
| Discard and reload | Replaces the full draft with active configuration |
| Load JSON or a history revision | Replaces the draft after validation; requires apply |
| Generate/import a certificate, CSR or renewal schedule | Saves the asset/schedule independently; assigning it to traffic still requires apply |
| Change accounts/security, clear persistence or reset statistics | Performs an immediate authenticated action |
| Save operations settings or stage an update/restore | Performs the page-specific action independently of the traffic draft |
| Apply interface changes | Starts a device-local 90-second trial; Keep writes the profile to disk, Revert or timeout restores the previous connection |

See [interface management](interface-management.md) for DHCP/default-route controls,
management IP migration and the difference between interfaces and traffic objects.

When an invalid field is on another page, validation opens that page before
highlighting it. A concurrent save produces a revision conflict. Export your draft
before reloading if you need to keep it.

## Reusable objects and references

Pools, nodes, monitors, profiles, certificates, VLANs and self IPs appear in
reference dropdowns. A renamed or deleted reference is marked unavailable until
you fix it. Update referring objects in the same draft before deleting definitions.

Named pools supply balancing and membership to every referring virtual server.
Their runtime scheduler, health and capacity remain per virtual server. See
[priorities and capacity](priority-and-capacity.md). Inline members remain available
when Default pool is blank.

Built-in profiles and RiverRules are read-only. View or assign them directly, or
copy/clone to customize. Copying makes an independent definition. The monitor
choices include built-in `tcp` and `http`; create a custom monitor for different
HTTP Host/path settings or other supported protocols. See [profiles](profiles.md),
[RiverRules](river-rules.md) and [monitors](health-monitors.md).

## Protocol and certificate choices

New virtual servers offer TCP, HTTP, UDP and domain routing. The legacy Automatic
type, formerly called Standard, selects HTTP when HTTP settings are enabled and
TCP otherwise. UDP exposes an idle timeout and accepts UDP, DNS or ICMP monitors;
it cannot use TCP TLS or HTTP profiles. See [UDP and types](udp-load-balancing.md).

Device certificates secure the management interface. Virtual-server certificates
secure client-facing traffic. Both stores support import, self-signed generation
and external-CA CSR completion. Their private keys are omitted from normal
configuration exports. [Certificate management](certificates.md) covers assignment,
rotation and public exports.

## Status, help and appearance

Status icons distinguish up, down, disabled, unavailable and unknown. A healthy
but draining member cannot accept new work; an unused or unprobed object may have
no meaningful readiness result yet. Background monitor results establish health;
an unchanged monitor context can retain verified health across an apply.

Hover over or keyboard-focus a setting for help; Escape dismisses it. Object lists
share aligned columns, and narrow displays can scroll tables horizontally. The
Appearance selector provides System, Light and Dark modes. It stays in the browser
and does not stage appliance configuration. Reduced motion, contrast and
transparency preferences are respected. No external fonts or visual services are
required. See [UI conventions](ui-review.md) for layout checks and limitations.
