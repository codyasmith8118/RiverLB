# Home hosting conveniences

## Home hosting features

The first implementation of the prioritized features is available:

1. **WebSockets and streaming:** support live app connections and transfer large
   uploads/downloads incrementally with bounded memory and backpressure.
2. **Automatic certificate renewal:** manage ACME issuance/renewal, report failures
   in the portal and activate renewed certificates without interrupting service.
3. **SNI certificate selection:** serve different managed certificates for multiple
   application hostnames sharing an HTTPS listener.
4. **Backup and restore:** recover configuration, managed certificates/private keys
   and database state through documented web and CLI workflows.

See [setup and limitations](home-features.md) for HTTP profile switches, ACME
challenge forwarding, SNI assignments and private backup/recovery commands.
Restore is validated/staged in the portal and activated offline. The
[parity priorities](parity.md#next-implementation-priorities) still track remaining
qualification work. See [feature coverage](parity.md) for remaining limits.

## App launch links

Set **App launch URL** in Local Traffic → Virtual Servers to your application's
HTTP/HTTPS URL, such as `https://photos.home.example/`. Overview shows an **Open
app** link beside its live member health. Links open a new tab with opener and
referrer isolation. URLs with credentials and non-HTTP schemes are rejected.
This is an administrator-only launch list; it does not configure DNS, certificates
or HTTP hostname routing. Keep admin access local or use the documented SSH tunnel.

In TOML, add `app_url = "https://photos.home.example/"` to the virtual server.
Pair each app with an HTTP/HTTPS readiness monitor to catch services whose ports
are open while their application or dependencies have failed.

## Saved configuration history

System → Import / Export → **Refresh history** lists the latest 100 saved
revisions, their timestamps and actors. **Load into draft** fetches a selected
revision and validates it, then fills the editor. It does not change live traffic.
Review all pages before **Save and apply**; applying creates a new revision and
uses the current revision for concurrency protection. You can cancel with
Discard / Reload. A saved configuration may fail current validation if its TLS
or monitor CA files are missing. PEM files and Linux networking are not part of
the saved revision.

Authenticated read-only APIs:

- `GET /api/v1/config/history`: revision metadata, newest first.
- `GET /api/v1/config/history/{revision}`: configuration JSON, or 404.

Revisions persist in the Rust-native SQLite-compatible database across restarts.
History contains configuration paths and addresses; it has the same administrator
access requirements as configuration. This is configuration recovery, not a full
database backup. Follow the database backup instructions for accounts and samples.
