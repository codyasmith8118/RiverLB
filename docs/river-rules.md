# RiverRules and HTTP cookie persistence

RiverRules is RiverLB's declarative traffic-rule engine. Rules use the ordered JSON language below. Enable **HTTP/1 proxy** in a virtual server's **HTTP** section to use rules or cookie persistence. TCP passthrough remains the default. Both plaintext HTTP and HTTPS terminated by RiverLB are supported; encrypted passthrough cannot inspect HTTP or insert cookies. The same verified server TLS and source NAT settings apply to backend HTTP connections.

## Rule language

Open **Local Traffic > RiverRules** to create, edit or clone a reusable named object and paste its ordered JSON rule array. Use the global **Save and apply** action to commit the draft. In a virtual server, use the **RiverRules** dropdown to add objects, then Move up/Move down to order them or Unassign to remove an assignment. Rules and assignments live in configuration revisions and are available through the API, CLI import/export and TOML. Rule names must be unique within each object. The combined assignment is limited to 128 rules. Deleting or renaming an assigned object requires updating its references in the same transaction.

```json
[
  {
    "name": "private-path",
    "when": {"path_prefix": "/private"},
    "actions": [{"kind": "respond", "status": 403, "body": "Forbidden"}]
  },
  {
    "name": "old-host",
    "when": {"host": "old.home.example"},
    "actions": [{"kind": "redirect", "location": "https://new.home.example/"}]
  },
  {
    "name": "legacy-route",
    "when": {"method": "GET", "path_prefix": "/legacy"},
    "actions": [
      {"kind": "rewrite_path", "path": "/new?from=legacy"},
      {"kind": "set_request_header", "name": "X-River-Route", "value": "legacy"},
      {"kind": "set_response_header", "name": "X-RiverLB", "value": "home"}
    ]
  }
]
```

Conditions in `when` are combined with AND. An empty object matches every request.

| Condition | Match |
|---|---|
| `host` | Full Host header, case-insensitively, including any port |
| `path` | Exact literal parsed path, excluding its query |
| `path_prefix` | Prefix of the literal parsed path, excluding its query |
| `method` | Exact, case-sensitive HTTP method |
| `tls` | `true` for client TLS terminated at RiverLB; `false` for plaintext clients |
| `header` | Object with `name` and `value`: case-insensitive name, exact value against any occurrence |

Path conditions do not decode escapes or normalize dot segments. For example, `{"path":"/api"}` matches `/api?x=1` but not `/api/items`; `{"path_prefix":"/api/"}` matches the latter without matching `/apiculture`. `tls` uses the actual client connection, regardless of supplied forwarding headers or encryption between RiverLB and the backend. These conditions provide routing controls; application authorization and sensitive-file protection still belong in the application.

Rules execute in array order, including the virtual server's assignment order. Rewrites and request-header changes are visible to later conditions. All matching rules run until a response action (`respond`, `redirect` or `redirect_https`) returns a local response. Later rules and assignments then stop. Response-header edits already collected apply to local and backend responses, including errors produced after rule evaluation such as 413, 502 and 503. Initial protocol or domain-routing rejection can happen before rules run. Local responses do not select/connect a member and do not issue persistence cookies.

| Action | Parameters | Behavior |
|---|---|---|
| `respond` | `status`, `body` | Return text, status 200–599 excluding 204/205/304; maximum 64 KiB body |
| `redirect` | `location` | Return 302 with a validated origin path or HTTP(S) URL |
| `redirect_https` | Optional `host` | Return 302 to HTTPS, preserving path/query; default uses request hostname without its port |
| `set_forwarded_for` | None | Replace X-Forwarded-For with the connecting client IP |
| `set_proxy_headers` | None | Remove incoming Forwarded and X-Forwarded-* fields, then set forwarding context from the actual connection |
| `rewrite_path` | `path` | Replace the complete origin path and optional query, rather than substituting the matching prefix |
| `set_request_header` | `name`, `value` | Replace an application request header |
| `remove_request_header` | `name` | Remove every occurrence of an application request header |
| `set_response_header` | `name`, `value` | Replace an application response header |
| `remove_response_header` | `name` | Remove every occurrence of an application response header |
| `select_member` | `address` | Force an existing pool member; last matching selection wins; return 503 if unhealthy, draining or full |

Header writes and removals are case-insensitive; later edits to the same header win. Computed forwarding values cannot be suppressed by a client's Connection header nominations. `set_proxy_headers` supplies X-Forwarded-For and X-Real-IP from the peer IP, X-Forwarded-Proto from client TLS, X-Forwarded-Host from the validated client Host, and X-Forwarded-Port from the virtual server's listener port. The Host remains client-reported, rather than an allowlisted application identity. If another proxy connects, its IP is the peer; RiverLB does not trust its forwarding claims automatically.

Forced member selection takes precedence over cookie/source affinity and priority groups, while retaining member capacity enforcement. A cookie preference also precedes priority groups, like source affinity. Framing, connection, Host, proxy-authentication and cookie headers cannot be changed by rules. Header matches are allowed on those headers. Unknown fields/actions, invalid header values, external URI rewrites and references outside the resolved pool are rejected. Limits: 128 rules, 16 actions per rule, 128-byte rule names, 4 KiB header values/paths. There are no regexes, loops, arbitrary code, filesystem access or external command execution.

## Cookie persistence

Cookie persistence is configured independently of rule objects. Open **Local Traffic > Cookie Persistence Profiles**, clone the built-in `cookie` profile, customize its settings and save/apply. Select its name in the virtual server's **Cookie persistence** dropdown. No RiverRules assignment is required. Rules can likewise be assigned without cookie persistence.

See [Cookie profiles](cookie-profiles.md) for insert/rewrite/passive/hash behavior, attributes, expiry, cloning, configuration examples and capability limits. Cookie persistence replaces source persistence on a virtual server; the portal saves source persistence disabled and the API rejects conflicting active source persistence. Legacy inline rule/cookie settings remain accepted by the API; the portal converts them to named draft objects and marks the migration unsaved until you apply it.

## HTTP behavior and limits

The Hyper HTTP/1 parser handles framing and chunked decoding. Client keepalive uses
a separate backend connection/reservation for each request. Hop-by-hop headers and
trailers are removed; buffered bodies use recalculated Content-Length. WebSocket
upgrades are validated and tunnel bidirectionally after handshake rules/cookies;
other upgrades, CONNECT and absolute-form requests are rejected. HTTP profiles
choose buffered or streaming bodies and configurable header/byte limits. See
[HTTP behavior](home-features.md#websockets-and-streaming) for error statuses,
backpressure, deadlines and limitations. Backend connection and TLS share the
connect timeout.

Virtual-server limits count client connections for their full lifetime, including idle keepalive and TLS handshake. Member limits count active backend exchanges. Shared admission counters still survive reload. Existing client connections retain their old runtime/configuration and cookies until they close. HTTP member completed/failed counters count exchanges; byte counters count fully buffered successful body payloads rather than headers/TLS/chunk framing, and completion precedes the client's final socket write. TCP mode retains its existing live socket-byte accounting. Local rule responses and rejected request bodies do not count as completed backend exchanges.

In streaming mode byte counters update as frames are processed and completion
follows response-body exhaustion. WebSocket reservations last for the tunnel;
their counters update live and include frame bytes. Failed/truncated transfers
release reservations and count failures. Existing tunnels also survive apply.

HTTP/2, gRPC, backend connection reuse, general-purpose scripting, Tcl
commands/events, encrypted cookie encoding and cross-virtual cookie state
remain unsupported. Streaming supports SSE
and incremental uploads/downloads. Choose buffered limits and connection limits
to fit the memory budget. Rules inspect HTTP headers/path, not body contents or
WebSocket frames.

## Developer map and verification

`src/http_proxy.rs` owns strict profile/rule schemas, configuration validation, matching/actions, bounded HTTP exchange and cookie header handling. `src/river_rules.json` holds the shared built-in catalog, served by `GET /api/v1/river-rules/builtins`; its metadata and definitions also drive the portal. `src/runtime.rs` owns member scheduling/reservations, per-connection HTTP admission, cookie records and source-bound/TLS backend connections. `web/app.js` owns separate reusable RiverRules/cookie profile pages, copying, dropdown assignment/order and mutually exclusive persistence collection. `config.rs` resolves named objects, reserves built-in names and rejects dangling or ambiguous references. No storage migration is needed: custom profiles/rules and built-in assignments are part of the saved configuration JSON.

Run `python3 tests/http_rules.py` and `python3 tests/rule_catalog.py` after `cargo build --locked`. The first covers keepalive/chunked requests, ordered rule effects, explicit selection, live capacity/health fallback, cookie handling, invalid configuration, body limits, incoming TLS and database restart. The catalog fixture validates every preset through authenticated APIs and real HTTP/TLS exchanges, including spoofed forwarding headers, backend-versus-client TLS, cache/path/method boundaries, local replies, error headers, independent copies and restart. `node tests/portal.cjs` verifies catalog/editor interactions and source-persistence exclusion. Existing TCP/persistence/TLS/NAT and WebSocket suites must also remain green.

## Built-in rule sets

The RiverRules list includes 30 configured built-ins, grouped by purpose. Open one to read its usage guidance and ordered JSON without creating an object. Built-ins are read-only and ready to assign directly from a virtual server's RiverRules dropdown. They resolve without saving a custom object. **Copy** creates an independent editable object; change its name or actions, then use **Save and apply**. Built-in names are reserved. The authenticated catalog API returns each built-in's `name`, `description`, `category`, `usage` and `rules`.

| Purpose | Built-in name | Effect |
|---|---|---|
| Redirects | `builtin-http-to-https` | Plaintext requests only: 302 to HTTPS, preserving path/query and stripping the incoming Host port |
| Forwarding | `builtin-x-forwarded-for` | Replace X-Forwarded-For with the connecting peer IP |
| Forwarding | `builtin-proxy-headers` | Remove incoming Forwarded/X-Forwarded-* and set peer IP, actual scheme, Host and listener port |
| Forwarding | `builtin-strip-forwarding-headers` | Remove common forwarding headers without replacement |
| Forwarding | `builtin-forwarded-proto-http` | Set X-Forwarded-Proto to http on plaintext requests only |
| Forwarding | `builtin-forwarded-proto-https` | Set X-Forwarded-Proto to https on actual TLS requests only |
| Forwarding | `builtin-remove-request-referer` | Remove incoming Referer before forwarding to the backend |
| Browser policies | `builtin-content-type-nosniff` | Set X-Content-Type-Options: nosniff |
| Browser policies | `builtin-frame-deny` | Set X-Frame-Options: DENY |
| Browser policies | `builtin-frame-sameorigin` | Set X-Frame-Options: SAMEORIGIN |
| Browser policies | `builtin-referrer-no-referrer` | Set Referrer-Policy: no-referrer |
| Browser policies | `builtin-referrer-strict-origin` | Set Referrer-Policy: strict-origin-when-cross-origin |
| Browser policies | `builtin-hsts-one-day` | TLS requests only: set Strict-Transport-Security: max-age=86400 |
| Browser policies | `builtin-strip-server-identity` | Remove Server, X-Powered-By, X-AspNet-Version and X-AspNetMvc-Version |
| Browser policies | `builtin-disable-cors` | Remove the listed Access-Control-* permission headers |
| Browser policies | `builtin-robots-disallow` | Exact GET /robots.txt: local 200 with a robots crawl ban |
| Browser policies | `builtin-robots-noindex` | Set X-Robots-Tag: noindex, nofollow |
| Browser policies | `builtin-web-header-baseline` | Combine nosniff, strict-origin referrer policy, SAMEORIGIN and server identity removal |
| Caching | `builtin-cache-no-store` | Set Cache-Control: private, no-store |
| Caching | `builtin-cache-revalidate` | Set Cache-Control: private, no-cache |
| Caching | `builtin-api-no-store` | Apply private, no-store to /api and /api/ descendants |
| Request controls | `builtin-block-trace` | Reject TRACE with local 403 |
| Request controls | `builtin-block-rest-writes` | Reject PUT, PATCH and DELETE with local 403; POST remains allowed |
| Maintenance | `builtin-maintenance` | All matching requests: local text 503 with Retry-After: 60 and no-store |
| Maintenance | `builtin-api-maintenance` | Local maintenance response for /api and /api/ descendants |
| Diagnostics | `builtin-listener-liveness` | Exact GET /__riverlb/live: local text 200 with no-store |
| Diagnostics | `builtin-disable-backend-compression` | Request Accept-Encoding: identity from the backend |
| Path controls | `builtin-deny-root-git` | Reject /.git and /.git/ descendants with local 404 |
| Path controls | `builtin-deny-root-env` | Reject exact /.env with local 404 |
| Path controls | `builtin-deny-admin-path` | Reject /admin and /admin/ descendants with local 403 |

### Assigning useful combinations

For an HTTP proxy, `builtin-proxy-headers` supplies the backend with connection context. Add `builtin-web-header-baseline` if the application uses correct MIME types and permits same-origin framing. Assign `builtin-hsts-one-day` separately after trusted HTTPS works for the hostname.

For HTTP-to-HTTPS redirection, assign `builtin-http-to-https` to the plaintext listener, usually port 80, after HTTPS is available on port 443. Its `tls: false` condition prevents TLS requests from being redirected again. For a fixed hostname or custom HTTPS port, copy it and change the action to `{"kind":"redirect_https","host":"app.example.com:8443"}`. A fixed host also controls the destination instead of relying on the client's Host header.

For a maintenance window with a listener probe, assign these in order:

```json
["builtin-content-type-nosniff", "builtin-listener-liveness", "builtin-maintenance"]
```

GET `/__riverlb/live` returns 200 before maintenance handles other requests. It checks the HTTP listener, not member health, application readiness or HA authority. Domain-routing hostname checks still apply. Unassign maintenance and apply to resume traffic on new connections; connections that retain an older runtime and existing TCP/WebSocket tunnels are unaffected. Use `builtin-api-maintenance` when only the `/api` namespace should return maintenance.

Choose one framing, referrer or Cache-Control policy for a given request. Later header edits replace earlier ones; terminal responses stop later assignments. For example, assigning maintenance first prevents liveness or a later response-policy rule from running. If forwarding cleanup and generated proxy context are both assigned, put cleanup before `builtin-proxy-headers`. Applications must trust RiverLB's listener and restrict direct backend access separately.

### Behavior to check before applying

The forwarding presets use the connecting peer and real client TLS. They do not accept another proxy's claim that a plaintext connection was originally HTTPS. `builtin-proxy-headers` preserves the client's validated Host as X-Forwarded-Host; a backend that requires a fixed application identity should validate it or use explicit domain routing. `builtin-strip-forwarding-headers` removes its finite list of common names, while `builtin-proxy-headers` removes every incoming X-Forwarded-* name before adding its five fields.

HSTS advertises one day of HTTPS use without includeSubDomains or preload. Browsers may retain that policy after it is unassigned; use it only after HTTPS with a trusted certificate works for the hostname. See [the HSTS specification](https://www.rfc-editor.org/rfc/rfc6797.html) for browser policy behavior.

The cache presets replace the application's Cache-Control header. `private, no-cache` permits a private cache to store a response but requires validation before reuse; `private, no-store` asks caches not to store it. Do not replace an application's required no-store policy with revalidation. Cookie persistence may enforce its own private, no-store policy. These presets do not add a RiverLB object cache. See [HTTP caching directives](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2).

Path-control presets match the documented literal paths. They do not cover encoded aliases, nested files or backend normalization differences. Protect sensitive files and administrative routes in the application. CORS header removal still lets requests reach the backend; it does not provide authentication or CSRF protection. Request-method restrictions likewise leave other methods available.

Robots controls are advisory. A crawl ban can prevent crawlers from seeing a noindex header, so combining the two does not ensure removal from search results. See [Google's noindex guidance](https://developers.google.com/search/docs/crawling-indexing/block-indexing). Server-header removal does not remove identifying content from bodies or cookies. Compression diagnostics request identity encoding but do not transform bytes or remove Content-Encoding.
