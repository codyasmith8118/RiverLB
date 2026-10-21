# Domain routing and nodes

Use **Local Traffic > Nodes** to create a named backend endpoint, such as `photos` at `192.168.1.30:8080`. Nodes have a description, an enabled switch and an optional health monitor. The list opens a separate detail editor. Refresh saved status to see availability, active connections, completed sessions, failures and the virtual servers using each node.

Use **Local Traffic > Domain Routing** to create a route. Enter an exact hostname, choose an HTTP virtual server from the dropdown, and choose a node. Save and apply the configuration. For example, `photos.example.com` and `files.example.com` can share one virtual server while forwarding to different nodes. Routes have separate list and detail pages and an enabled switch.

Choose **Domain routing only** on the virtual server to route exclusively by hostname, or **HTTP proxy** if unmatched hosts should use a default pool. For HTTPS, terminate TLS on that virtual server and assign certificates, including SNI mappings where needed. Point DNS at the virtual server's listening address. Domain routing does not create DNS records. The route certificate controls can select an existing certificate, generate a self-signed certificate or request ACME issuance; see [certificate management](certificates.md). Issuance is separate from applying the route listener.

## Request behavior

### Virtual server types and hostname misses

Select **Domain routing only** under a virtual server's General properties to require a domain-table match for every request. HTTP processing is enabled automatically. Default pools, inline members and node members are excluded when saving this type; the API rejects configurations that include them. A domain-routing listener can have no routes and still serve its 404 response. Disabled routes also count as misses. Known routes with unavailable nodes return 503.

Set **Hostname miss: 404 response body** to customize the UTF-8 plain-text response (up to 65,536 bytes). The response remains HTTP 404 and is returned before RiverRules or cookie selection. This body also applies to unmatched requests on legacy route-only Standard listeners.

Other types are **TCP**, **HTTP**, **UDP**, and **Automatic (legacy TCP / HTTP settings)**. Automatic preserves existing protocol settings for backward compatibility. UDP cannot use domain routing. See [virtual-server types](udp-load-balancing.md).

API/TOML fields are `server_type` (`standard`, `tcp`, `udp`, `http`, `domain_routing`) and `hostname_miss_body`. Omitted type fields default to `standard`, so existing saved configurations continue to work. A domain-only example is:

```toml
[[virtual_servers]]
name = "home-domains"
listen = "0.0.0.0:8080"
server_type = "domain_routing"
hostname_miss_body = "Application not found. Contact the server administrator."
[virtual_servers.http]
profile = "http"
```

Create Nodes and Domain Routing entries targeting `home-domains` afterward; until then, requests return the configured 404.

Routing uses the incoming HTTP Host header. Hostname matching ignores case, an optional port and a trailing dot. Configure lowercase exact DNS names; wildcard and path routes are not implemented. Duplicate hostnames on the same virtual server are rejected, including disabled routes. Missing, duplicate or malformed Host headers on a virtual server with domain routes return 400.

A matching enabled route selects its node explicitly. Cookie persistence cannot redirect the request to another domain's node. A disabled, draining or unhealthy target returns 503 instead of silently choosing a different application. Existing accepted connections drain normally when configuration changes.

Unmatched hostnames use the virtual server's default pool or inline/node members. Nodes referenced only by domain routes stay out of that default balancing set. A virtual server can have only domain routes: unmatched hostnames then return 404. Disabling all routes retains that behavior. Response and redirect RiverRules can terminate a request before forwarding; domain selection takes precedence over a rule's member selection.

Routes inherit the virtual server's health monitor, backend TLS, source NAT, HTTP limits, WebSocket/streaming settings and admission limits. Per-route TLS settings, access lists and advanced proxy-manager options are not available yet.

## Reusable members and status

Pools and inline virtual servers can select nodes from a multiple-choice dropdown alongside legacy explicit member addresses. Editing a node's endpoint updates its references on the next successful apply. Deleting a referenced node fails validation. Disabling a node prevents new connections through any reference to its address.

Each node represents an **IP address and service port**. Address-only nodes with different member ports and aggregate node limits are unsupported. A node's explicit monitor overrides the inherited pool check and also checks enabled, unassigned nodes. Without a node monitor, traffic references use their pool/virtual-server monitor. The Nodes view aggregates runtime results; disabled state takes precedence, and an unprobed node has unknown readiness. See [node monitoring](health-monitors.md).

Member weights, priority groups and explicit drain maps still use endpoint addresses. Adjust those maps when changing a referenced endpoint; validation rejects dangling entries. Old connections retain their generation until completion.

Nodes and routes are stored with the versioned configuration in the Rust database, survive restart and are included in configuration export and full backups. The authenticated `GET /api/v1/nodes` endpoint returns saved node status. `tests/domain_routing.py` exercises real traffic, cookie isolation, disabling, fallback, validation and restart recovery.
