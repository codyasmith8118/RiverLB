# Portal readability and interaction review

Reviewed every portal page, object editor and the sign-in page. The changes keep
the existing configuration model: edits stay in the browser until Save and apply
succeeds. Done appears at the bottom of editors and returns to the appropriate
list. There is no Done button in the page header.

| Area | Changes |
| --- | --- |
| Shared layout | Consistent typography, field spacing, borders, action groups and destructive buttons; green Configuration applied / yellow Not yet applied indicators |
| Navigation | Keyboard skip link and main landmark; heading focus on intentional navigation; compact mobile menu; certificate links preserve the store and object name |
| Overview | Separate latency cards, seven-column member summary, expandable counters and latency details, useful empty states, preserved keyboard focus and expansion during refresh |
| Virtual servers, pools, nodes, domain routing | Existing sections and assignments retained; editor views hide list-only controls; spaced bottom actions; tables scroll within their panels |
| Monitors | Sections for identity, timing, HTTP, trust, UDP and DNS; irrelevant protocol sections hidden; labels distinguish HTTP Host from TLS server name |
| HTTP, server TLS and persistence profiles; RiverRules | Consistent card and list layouts, clone/copy action spacing, readable JSON fields and rule assignment rows |
| Interfaces, VLANs, self IPs and routes | Grouped network fields, accessible table scrolling, long addresses wrap, corrected floating-self-IP help |
| Certificates and signing requests | Aligned inventory rows, grouped download/import/delete actions, wrapped certificate metadata and PEM fields |
| Renewals | Consistent field grid, normal-sized terms checkbox, spaced edit/delete actions with destructive styling |
| HA and synchronization | Separate settings and operation cards, readable detail table, operation results visible on the current page |
| Settings, administrators, import/export | Management settings first, compact password panel, spaced account actions, consistent backup/history rows, bottom Done navigation |
| Statistics | Clear loading/reset/error states, table counts and empty states, keyboard-accessible scrolling, chart axes and a solid/dashed direction legend |
| Sign-in | Focused card layout, readable labels and help, consistent inputs and primary action |

The global draft toolbar remains visible on traffic configuration pages. On
read-only and inventory pages it appears when traffic edits are pending, so
unrelated Apply controls do not compete with the current task. Independent HA
and administrator changes continue to use their own save actions.

Errors move focus to visible feedback. All pages share the same feedback region,
including pages outside the traffic configuration form. Health icons have an
accessible name and image role. The palette's measured text contrast is 15.93:1
for primary text on the page, 8.35:1 for muted text on panels and 9.94:1 for the
accent on panels. This review does not claim a complete accessibility certification.

## Verification

### Form and button review — October 12, 2026

The follow-up review covers all pages listed above, including the new interface
editor and GUI HA deployment. Shared form sections now use responsive columns,
while PEM, JSON and other long text fields retain the available width. Pool
member inputs align from the top, and the existing-node selector has a visible
label. Action rows wrap with consistent spacing. Refresh, Back and Clone/Copy
use secondary styling; destructive editor actions appear at the opposite end
from Done and remain last in keyboard order.

The interface editor has one bottom Done action. Certificate signing-request
Done returns to the matching device or virtual-server certificate inventory.
HA Configuration separates routine ownership controls from an expandable,
numbered initial-deployment guide. Cluster creation appears before fencing,
and activation appears afterward. Password-clearing behavior and ownership
checks are unchanged.

For the current Pacemaker-based automatic HA, fencing remains required. If
heartbeats stop while both appliances can still reach clients, an unreachable
peer may still own the VIP. Power fencing confirms that peer is stopped before
takeover. Standalone operation does not need fencing. A simpler heartbeat-only
HA mode would require a separate design and partition/frozen-appliance testing.
Failover protection now has platform-specific connection fields, appliance
mappings, and read-only discovery and power-state checks. Advanced options stay
in an expandable section. Ordinary setup no longer requires JSON.

The VLAN follow-up found a last-field margin rule that shifted the right-hand
input below its partner. Removing that rule aligns the general, tagging and
return-gateway fields. The browser audit now checks field baselines in shared
form grids as well as overflow and overlapping controls.

Portal, fencing and statistics interaction tests passed. Firefox reviewed 121
snapshots at three widths (363 layout checks), including the installed fencing
agent forms and light/dark variants. Representative network and fencing forms
and their bottom actions were inspected. See the appliance build artifacts for
the image build date; a source review does not update an existing installed VM.

The browser audit checks horizontal overflow and overlapping buttons/inputs in
action rows and pool-member forms at desktop, tablet and phone widths. These are
fixture-based checks, supplemented by representative screenshot inspection;
they do not replace a user study, screen-reader audit or live HA qualification.

`tests/portal.cjs` checks navigation, staged edits, bottom Done, cloning, certificate
routes, shared feedback and keyboard focus through refresh, alongside existing
configuration workflows. `tests/statistics.cjs` covers statistics views, loading,
filtering, chart descriptions and reset behavior.

Optional browser review uses disposable test data and does not access a live
RiverLB instance:

```bash
UI_SNAPSHOT_DIR=/tmp/riverlb-ui-review node tests/portal.cjs
# Optional: include the real installed fencing catalog and its connection forms.
/usr/libexec/riverlb/riverlb-ha-deploy --fencing-catalog > /tmp/fencing-catalog.json
node tests/fencing_snapshots.cjs /tmp/fencing-catalog.json /tmp/riverlb-ui-review
python3 tests/ui_layout.py /tmp/riverlb-ui-review
```

The Node test requires `jsdom`. The layout audit uses Firefox's built-in
[Marionette protocol](https://firefox-source-docs.mozilla.org/remote/marionette/Protocol.html)
over loopback, with an isolated temporary profile. It checks every generated
page at desktop, tablet and 390px content widths, writes measurements to
`layout-results.json`, and captures representative screenshots. A local frame
provides the 390px viewport because desktop Firefox enforces a wider minimum
window size. Tables may scroll inside their panels; the page itself must not
overflow horizontally.

Snapshots cover the portal's pages, object editors, every supported monitor
protocol, the empty overview and sign-in. They verify layout with representative
fixtures; they do not replace deployment or backend integration tests.
