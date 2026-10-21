# WebSockets, streaming, renewal, SNI and recovery

## WebSockets and streaming

Enable the HTTP proxy on a virtual server. Under **Profiles > HTTP**, clone `http`
and select **Streaming** for Body forwarding. Assign the custom HTTP profile to
the virtual server and Save and apply. WebSocket upgrades are enabled by default
and can be disabled in the profile. RiverRules and cookie persistence run on the
HTTP handshake; after a successful upgrade the connection becomes an opaque
bidirectional tunnel. Only WebSocket upgrades are supported, not CONNECT or other
upgrade protocols. Version 13 and a valid handshake key are required.

Streaming forwards request and response frames as they arrive, using Hyper's
backpressure rather than collecting entire bodies. The byte limit applies to each
request/response body, including chunked transfers: up to 64 MiB in buffered mode
or 1 TiB in streaming mode. A known excessive request length returns 413; a known
excessive backend response length returns 502. An oversized or failed stream after
headers have been sent terminates the transfer; its status cannot be changed to an
error response. Trailers are not forwarded. HTTP/2 and backend connection pooling
remain unsupported.

`session_timeout_secs` remains a **total client connection lifetime** limit, not
an inactivity timeout. Set it high enough for long uploads, SSE and WebSockets.
Backend connect/TLS deadlines remain separate. Member admission lasts until the
response ends or the tunnel closes; virtual admission lasts for the client
connection. Existing connections retain their generation across apply, and drain
on shutdown subject to the daemon's shutdown deadline. Stream byte counters update
as body frames are processed; tunnel byte counters update live and include
WebSocket framing, excluding the HTTP handshake and TLS overhead.

## Automatic certificate renewal

Open **System > Certificate Renewals**. Select the Device or Virtual server certificate store. Supply a managed
certificate name, one DNS hostname per line, HTTPS ACME directory, contact email,
challenge listen address and renewal window. Explicitly accept the chosen CA's
terms before enabling the schedule. Save renewal schedule independently of the
configuration draft; Refresh schedules shows success, error and next retry times.

The default directory is Let's Encrypt staging. Staging certificates are for
testing and are not publicly trusted. After testing, select the intended production
CA directory and accept its terms. No public CA is contacted by the test suite.
The implementation uses [instant-acme 0.8.5](https://docs.rs/instant-acme/0.8.5/instant_acme/).

**Public port 80 for every requested hostname must reach the challenge listener.**
The worker binds that endpoint only during issuance. It cannot share an address/
port with an existing virtual server or another process. For example, forward
public port 80 to a dedicated RiverLB port 9080 and configure
`0.0.0.0:9080`; keep application HTTPS on a separate listener. WSL deployments
also need the appropriate host port forwarding and firewall rules. Challenge
requests are served by a dedicated HTTP-01 endpoint, never the admin portal.

Schedules, account credentials and retry status live in the database. The worker
checks every 30 seconds and wakes after portal updates. It issues missing
certificates and renews certificates within the configured 1–90-day window.
Success schedules an hourly expiry check; failures back off from ten minutes to
about 21 hours. Requests have a ten-minute issuance deadline. Restart preserves
credentials and backoff; interrupted orders restart with a new order rather than
resuming a saved order. Up to 100 schedules are supported.

The certificate's names, validity and key pair are checked before activation.
Runtime preparation and the certificate/configuration database commit happen
before switching listeners. Assigned virtual-server and management certificates
rotate without changing their object name; existing TLS connections retain their
previous state. Renewal creates a configuration revision, so an open stale draft
must reload before saving. Failures preserve the last active certificate.
After initial issuance, select the new name from the virtual-server or management
certificate dropdown and apply. DNS-01, wildcard issuance, external account
binding and explicit revocation are not implemented.

CLI setup while the daemon is stopped:

```bash
riverlb renewal --database examples/riverlb.db --settings renewal.json
```

```json
{
  "name":"home-app",
  "domains":["app.example.com"],
  "directory":"https://acme-staging-v02.api.letsencrypt.org/directory",
  "email":"admin@example.com",
  "terms_agreed":true,
  "enabled":true,
  "challenge_listen":"0.0.0.0:9080",
  "renew_before_days":30,
  "ca_certificate":null
}
```

A custom CA PEM path is available for private ACME services. The directory always
uses verified HTTPS. Production tests against a public CA remain outstanding.

## SNI certificate selection

In **Virtual Servers > your server > Client TLS**, select a managed default
certificate. Add SNI hostnames and choose a managed certificate for each from its
dropdown. Hostnames must be unique lowercase DNS names, without ports or wildcard
assignments. A wildcard certificate may cover an explicitly assigned hostname.
Certificates must cover their assigned names. Missing certificates and name
mismatches fail validation before changing traffic.

Clients with a matching SNI hostname receive its assigned certificate. Unknown
hostnames and clients without SNI receive the explicit default certificate. This
does not configure DNS or hostname-based backend routing. Assignments are per
virtual server, limited to 100, and cannot be combined with legacy client PEM paths.
Deletion is blocked for any certificate referenced by the active default or SNI
map. Configuration history may still reference older certificates.

```toml
# Within an existing [[virtual_servers]]:
certificate = "default-site"
sni_certificates = { "photos.example.com" = "photos", "files.example.com" = "files" }
```

## Private backups and restore

**System > Import / Export > Download private backup** creates a consistent logical
database snapshot while the daemon runs. It includes configuration/history,
managed certificates/private keys, administrator password hashes, audit/traffic
history, ACME schedules and account secrets. Sessions and staged restore uploads
are excluded. The format is versioned JSON with a SHA-256 integrity checksum and
a 32 MiB limit. The checksum detects corruption; it is not an authenticity
signature or encryption. Protect backups like the database.

Upload a backup and select **Validate and stage restore**. This validates schema,
integrity, configuration and certificate references, then stores the staged file
inside the protected database. It does not replace active settings or accounts.
Finish from WSL while the daemon is stopped:

```bash
riverlb restore --database examples/riverlb.db --staged --replace
riverlb serve --config examples/riverlb.toml
```

Offline backup and restore into a new database:

```bash
riverlb backup --database examples/riverlb.db --output /private/riverlb-backup.json
riverlb restore --database /private/recovered.db --input /private/riverlb-backup.json
riverlb serve --config examples/riverlb.toml --database /private/recovered.db
```

Local commands acquire exclusive database ownership. Backup creates a new file
with mode 0600 and refuses to overwrite a file. Restore refuses to replace an
existing configuration unless `--replace` is supplied. All record replacement and
session revocation run in one database transaction; a failed restore rolls back.
Successful restore uses backed-up administrator credentials and revokes all live
sessions. Save a current backup before replacing a database.

External PEM/CA files and Linux interface/firewall/DNS state are not included.
Supply referenced external files at their configured paths before validation and
activation. Restore does not execute kernel networking; startup applies networking
by default unless `--external-network` is explicitly selected. The initial TOML file is still
required by `serve`, though saved database configuration is authoritative.

Authenticated APIs: `POST /api/v1/backup`, `POST /api/v1/restore/stage`,
`GET/POST /api/v1/renewals`, `DELETE /api/v1/renewals/{name}`. Backup responses use
`Cache-Control: no-store`; mutation endpoints require the normal CSRF request
header. Private material is included only in the explicit full-backup response,
not ordinary configuration, certificate-list or public-chain responses.
