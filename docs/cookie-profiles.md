# Cookie persistence profiles

Cookie persistence has its own reusable objects and portal page, independent of RiverRules. Enable HTTP/1 proxy on the virtual server, then select a **Cookie persistence profile**. Rules and cookies can each be enabled without the other. TCP passthrough cannot inspect HTTP cookies.

## Create, customize, clone and assign

1. Open **Local Traffic > Profiles > Cookie Persistence**.
2. The built-in `cookie` profile is always available and read-only. Click **Clone** to create an editable copy, or **Create profile** to start from its settings.
3. Give the copy a unique profile name and description. Customize method, cookie name, lifetime/capacity and applicable attributes/hash options.
4. Use **Save and apply** to save all draft changes to the database.
5. Open the virtual server and select the profile in **Cookie persistence**. Save/apply the assignment.

A clone copies the current settings into an independent snapshot with a suggested unique name. Editing the copy does not change its source. There is no live inheritance: future parent edits do not propagate. Renaming/deleting an assigned profile requires updating all assignments in the same transaction. The backend rejects dangling references. The built-in name `cookie` is reserved; it does not require a custom database record. Custom profiles and assignments are stored in the existing configuration revision JSON. Up to 1,000 custom profiles are accepted.

The default uses opaque insert mode, name `RIVERLB`, a 3,600-second sliding record lifetime, 10,000 records, Path `/`, no Domain, browser expiry equal to the record timeout, HttpOnly enabled, SameSite Lax, Secure automatically with client TLS, always-send enabled and member-limit override disabled. Clone the default if your application needs different settings.

The editor shows only settings that affect the chosen method. Changing modes preserves the stored values of hidden settings so they can be reused if you switch back.

## Native cookie modes

| Method | Request handling | Response handling |
|---|---|---|
| Insert | Look up a random opaque token in the per-virtual-server table; remove this cookie before forwarding to the app | Suppress app cookies using this name and insert an opaque token according to always-send |
| Rewrite | Look up/remove the opaque token just as insert does | Replace an app Set-Cookie with this name; do not insert when the app supplied none |
| Passive | Look up a SHA-256 digest of the app's cookie value; forward the original cookie unchanged | Learn the member from a single app Set-Cookie using that name; leave all cookie attributes unchanged |
| Hash | Hash the selected byte range of the app cookie and choose from eligible members; no table record | Leave the app's cookie unchanged; no inserted cookie |

These are native RiverLB semantics; existing vendor-specific member-address cookies are not decoded. Passive mode learns an application cookie-to-member association; the application should issue distinct values for clients that must retain independent affinity. Hash mode uses SHA-256, takes the first eight digest bytes as an unsigned big-endian integer and selects modulo the eligible member count. Offset is in bytes; length zero uses the remaining bytes. An empty/out-of-range byte range falls back to the configured load balancer. Changes to eligible membership can remap hash clients. Health, drain and priority-group eligibility apply before hashing.

Insert/rewrite issue 256-bit random tokens that carry no member address. Tokens are not authentication credentials. Duplicate, missing, expired or malformed request cookies select normally. Insert/rewrite clear collisions from app Set-Cookie headers while preserving unrelated cookies and force `Cache-Control: private, no-store`. Passive/hash do not rewrite cookies or cache policy.

All modes keep virtual-server admission limits in force. Persisted members must be healthy and not draining. Full members normally cause fallback. **Persisted clients may exceed member limits** explicitly bypasses the selected member's cap for a valid cookie preference; it does not bypass virtual/global limits or a rule's forced-member cap. For hash mode that option also includes full healthy members in the hash candidate set. Existing connection counters continue to reflect the extra work.

## Settings

| Setting | Meaning and bounds |
|---|---|
| Profile name / description | Unique name of 1–128 bytes; description up to 4 KiB |
| Cookie name | 1–64 letters, digits, underscores or hyphens; use distinct names for virtual servers sharing a hostname |
| Record timeout | 1–86,400 seconds for insert/rewrite/passive; independent of browser expiry |
| Maximum records | 1–1,000,000 per virtual server; expired entries release capacity; new mappings are skipped when full |
| Sliding record timeout | Enabled refreshes the server-side record; disabled retains the original expiry |
| Browser expiry | Blank uses record timeout; zero or Session Cookie omits Max-Age; otherwise 1 second–10 years |
| Always send | Insert sends on every response when enabled; otherwise sends on creation/replacement. Rewrite always replaces a supplied cookie |
| Path / Domain | Path starts with `/` and excludes unsafe separators; Domain is optional and validated as a hostname |
| HttpOnly | Configurable on inserted/rewritten cookies |
| Secure | Auto follows client TLS; Always/Never explicitly set/omit the attribute |
| SameSite | Lax, Strict or None; None requires Secure, and Auto+None requires incoming TLS |
| Hash offset / length | Each 0–4,096 bytes; length zero hashes the remainder |
| Member-limit override | Opt-in behavior described above; disabled by default |

Always-send and sliding record lifetime are separate. With always-send disabled, a browser's persistent cookie can expire before a refreshed server-side record. A session cookie omits browser expiry; its server-side record still has a timeout. Domain/Path and Secure affect whether browsers return the cookie; test against your actual hostname and HTTPS configuration. Passive/hash attribute settings are inactive because the application owns those cookies.

Tables belong to virtual servers even when a profile is shared. Profile sharing reuses configuration, not live records. Records are RAM-only, clear on apply/restart, and do not cause a database write per request. `/api/v1/persistence` shows counts/member/remaining lifetime with opaque tokens and application cookie values redacted. The existing Clear action clears the table. In-flight requests may create records afterward. Fixed expiry is not extended by repeated valid requests. After failover, insert/rewrite can replace the presented mapping even at table capacity.

## Configuration API example

The root configuration contains reusable definitions:

```json
{
  "cookie_profiles": [
    {
      "name": "home-cookie",
      "description": "Custom home application affinity",
      "settings": {
        "method": "insert",
        "name": "HOME_AFFINITY",
        "ttl_secs": 1800,
        "expiration_secs": 900,
        "max_entries": 10000,
        "http_only": true,
        "secure": "auto",
        "same_site": "lax",
        "path": "/",
        "domain": "",
        "session_cookie": false,
        "always_send": false,
        "refresh_on_use": true,
        "hash_offset": 0,
        "hash_length": 0,
        "override_connection_limit": false
      }
    }
  ]
}
```

Assign with `virtual_servers[].http.cookie_profile = "home-cookie"`; rules are separately assigned through `http.rule_sets`. Omit the cookie profile to disable cookie persistence. Combining a named profile with legacy inline `http.cookie` is rejected. The portal copies legacy inline settings to named draft objects on load/import and marks the conversion unsaved until you apply it. The API continues accepting old inline configurations.

## Remaining feature work

The table below records native profile capabilities and remaining work.

| Area | RiverLB state |
|---|---|
| Default/custom/clone | Available; clones are independent snapshots, live `defaults-from` inheritance is pending |
| Insert/rewrite/passive/hash | Native implementations above; third-party cookie format interoperability unqualified |
| Expiry, attributes, always-send, hash range | Available within documented bounds; indefinite records and additional expiry modes pending |
| Cookie encryption policies/passphrases | Pending; current random tokens require server-side records and contain no member identity |
| Cross-pool/service/virtual matching | Pending; live state remains per virtual server |
| HA mirror | Asynchronous source/cookie checkpoints are supported in HA; live connection mirroring is pending |
| Member limit override | Implemented as opt-in, with virtual/global admission enforced |
| Partitions/app-service ownership | Pending in the broader object model |

Unsupported settings are not exposed as functioning controls. See [feature coverage](parity.md) for remaining limits.

## Developer verification

`Cookie`, `CookieProfile` and the header/mode logic live in `src/http_proxy.rs`. `Config::resolve` selects the built-in/custom profile and resolves reusable rule objects before runtime creation; `Config::validate` rejects duplicates, dangling references, unsafe values and ambiguous inline/named configuration. `Pool` owns opaque/hashed passive records, fixed/sliding expiry, hashing and member admission. The portal serializes raw named definitions, not resolved copies, so profile sharing survives editing.

`tests/http_rules.py` exercises default/custom/shared definitions, independent cloned settings, separate assignments, rule ordering/update, cookie attributes, modes/hash ranges, explicit cap override, legacy inline behavior and database restart. `tests/portal.cjs` covers default read-only controls, cloning, dropdowns, assignment order, save/reload and legacy conversion.
