# Profiles

Open **Local Traffic > Profiles**, then choose HTTP, Server TLS, Source Persistence or Cookie Persistence. Each type starts with a list of defaults and custom profiles. Click a name to open its settings. **Create** opens a new detail page; **Clone** opens an independent editable copy. Back to list retains unsaved changes. Save and apply commits the entire draft, including assignments on other pages.

Built-in profiles are read-only and available without custom records in the database. Custom definitions and assignments are stored in revisioned configuration. Virtual-server dropdowns include the profiles in the current draft. Each built-in default is documented below.

| Type | Default | Behavior |
|---|---|---|
| HTTP | `http` | HTTP/1 proxy, 8 MiB request/response body limit, 32 KiB parser buffer, client keepalive |
| Server TLS | `server_tls` | Verified backend TLS using the system CA bundle on Ubuntu/Debian or AlmaLinux/RHEL; verifies each member's IP address |
| Source Persistence | `source_addr` | Individual source-address affinity, sliding 180-second expiry, 10,000 records |
| Source Persistence | `source_hash` | Stateless individual-source-address hashing |
| Cookie Persistence | `cookie` | Native opaque cookie insertion; see [cookie profiles](cookie-profiles.md) |

Existing custom source profiles named `source_addr` or `source_hash` take precedence for compatibility. New HTTP, cookie and server TLS defaults have reserved names. Clone defaults to customize them. Clones are snapshots; they do not inherit later changes.

## HTTP profiles

Customize body limits, header/parser buffer (8 KiB–1 MiB), client keepalive, streaming and WebSocket upgrades. Buffered mode accepts limits up to 64 MiB; streaming supports up to 1 TiB with bounded-memory forwarding. The default remains buffered with WebSockets enabled. HTTP/2 and backend connection reuse remain unsupported. See [HTTP behavior and limits](home-features.md#websockets-and-streaming). A named profile cannot be combined with different inline HTTP settings. The portal converts legacy inline settings into a named custom profile when necessary; saving persists the conversion.

```json
{
  "http_profiles": [{"name":"home-http","settings":{"max_body_bytes":1048576,"max_header_bytes":32768,"keep_alive":true}}],
  "virtual_servers": [{"name":"app","listen":"127.0.0.1:8080","members":["127.0.0.1:8000"],"http":{"profile":"home-http"}}]
}
```

Rules and cookie persistence remain separate objects and assignments. Changing a named HTTP profile updates every assigned virtual server on apply.

## Server TLS profiles

A blank server name verifies the destination member IP against the certificate's IP subject alternative names. Set a DNS name to verify that name and send DNS SNI. Clone `server_tls` to select a private CA bundle or explicit server name. The built-in system bundle must exist on the host; self-signed/private CA certificates are not automatically trusted. No insecure verification bypass is provided. See [server TLS](server-tls.md).

Additional profile families remain tracked in [feature coverage](parity.md). Unsupported types are not shown as configurable placeholders.

In the virtual-server editor, choose **No persistence** to remove source and cookie affinity. This also disables stateless source hashing. Choose Source persistence to select a reusable profile or configure inline settings; choose Cookie persistence (HTTP) to select a cookie profile.
