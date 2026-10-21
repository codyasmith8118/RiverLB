# Certificate management

The portal has two separate inventories under System:

- **Device Certificates** holds certificates for the management web interface.
- **Virtual Server Certificates** holds certificates for incoming virtual-server TLS, SNI and domain routes.

The same object name can exist in both stores. Management resolves its names only
from the device store; virtual servers and routes resolve theirs only from the
virtual-server store. Pending CSRs are also scoped to their store. Both inventories
show validity, DNS/IP names, fingerprints, assignments and downloadable public chains.

## Generate a certificate or CSR

Open either inventory and click **Generate certificate / CSR**. Enter an object
name and every DNS name or IP address clients will use, one per line. The first
name becomes the certificate’s common name; all names become SANs. Optional
organization, organizational unit, country, state and locality fields apply to
both operations. Country uses a two-letter uppercase code.

**Self-signed certificate** creates a key and certificate in the selected store.
Choose a lifetime of 1–825 days. Clients must trust the public certificate;
self-signed certificates do not automatically renew. Generation does not assign
or enable the certificate: select it in a configuration draft and Save and apply.

**CSR for an external certificate authority** creates a pending signing request.
Download the CSR and submit it to your external root/intermediate CA. RiverLB
keeps the matching private key; it is not included in the CSR response/download.
Return to the request in its inventory and paste or upload the CA-signed PEM chain,
leaf first followed by intermediates. **Import signed certificate** validates the
matching key and all requested DNS/IP names before moving it into the certificate
inventory. Failed imports leave the pending request intact. Pending requests and
keys survive restarts and private backups. Deleting a request deletes its key.

## Management HTTP / HTTPS

In **System → Settings**, choose **Web interface protocol: HTTP or HTTPS**.
For HTTPS, choose **Device certificate store** and select a device certificate.
The legacy certificate/key PEM-file source is also available. Choose a certificate
covering the hostname/IP used to open the portal. HTTP removes the TLS assignment
from the saved configuration; switching back to HTTPS requires selecting a certificate.

Save and apply changes protocol on the same IP and port. The response shows a link
to the new portal URL; open it and sign in again if necessary. An HTTP→HTTPS or
HTTPS→HTTP change drains existing management connections after in-flight responses.
New management connections use the current protocol and certificate. Certificate
changes and renewals do not require moving management to another port. Traffic
listeners remain independent of management protocol changes. There is no separate
HTTP-to-HTTPS redirect listener for the management interface.

TOML example:

```toml
management = "192.168.1.7:18090"
management_protocol = "https"
management_certificate = "device-portal"
```

For HTTP set `management_protocol = "http"` and remove management certificate/TLS
assignments. Configurations without `management_protocol` retain their existing
behavior, inferring HTTPS when a TLS assignment is present.

## Import and rotation

**Import certificate** accepts PEM text or files and a matching unencrypted private
key. RSA/ECDSA keys supported by Rustls can be used. The pair is checked before saving.
Expired/not-yet-valid certificates are visibly flagged; importing does not authenticate
the issuer or establish client trust. Managed names and legacy PEM-file sources are
mutually exclusive. Imports, generation, CSR completion and deletion save immediately
and are audited. Assignment changes require Save and apply.

Manual certificates are immutable. Rotate by creating/importing under a new name,
changing the assignment, and applying. Existing TLS connections keep their negotiated
session; new connections use the new certificate. Deletion is blocked for active
assignments in the corresponding store. Older saved revisions can reference deleted
names, so reimport the matching assets before restoring such a revision.

ACME renewal schedules include a **Certificate store** selection. Select Device for
management certificates or Virtual server for traffic certificates. Schedule names
are globally unique; use distinct names for separate device and traffic schedules.
Issued certificates are saved only to the selected store and assigned certificates
rotate for new connections. Existing schedules default to Virtual server; after
upgrading a management certificate, check its renewal schedule’s store.

## Storage and backups

The database stores traffic pairs in `certificates`, device pairs in `device_certificates`,
and pending CSRs/keys/names in `certificate_requests`. Supported older schemas upgrade automatically; see [database upgrades](security-and-database.md).
Previously shared certificates referenced by management in saved configurations are
copied into the device store; the original virtual-server inventory is preserved.

Keys are not encrypted at rest. Database permissions, journals and private backups
protect key material. Normal inventory, CSR, public-chain and configuration APIs never
return private keys. Private database backups include both inventories and pending
request keys. Current private backups support these assets; format-1 backups remain restorable
and migrate former management assignments into the device store. Original upload
files are not needed after import. Configuration JSON alone does not restore keys.

## API and CLI

All endpoints require administrator authentication and the existing request-header
and origin protection. Use `/api/v1/certificates` for virtual-server assets or
`/api/v1/device-certificates` for device assets. Each base provides:

- `GET /`: inventory metadata and assignments.
- `POST /`: `{name, certificate, private_key}` PEM import.
- `POST /self-signed`: `{name, names, days, subject}` generation. Legacy `{name, hostname, days}` also works.
- `GET /objects/{name}/pem`: public certificate chain.
- `DELETE /objects/{name}`: remove an unused certificate.
- `GET /requests`: pending request names, public CSRs, names and creation times.
- `POST /requests`: `{name, names, subject}` creates a CSR and retains its key.
- `GET /requests/{name}`: download the public CSR.
- `POST /requests/{name}/complete`: `{certificate}` imports the CA-signed chain using the retained key.
- `DELETE /requests/{name}`: delete a pending request and its private key.

Legacy `/{name}/pem` and `DELETE /{name}` remain available for names that do not conflict with the API’s operation paths.

Names accept 1–128 letters, digits, dots, underscores or hyphens. Each store holds
up to 1000 certificates; at most 1000 CSRs can be pending across both stores. A chain
is limited to 256 KiB and an imported key to 64 KiB.

Offline commands require stopping the daemon to release its database lock:

```bash
cargo run -- certificate import --database examples/riverlb.db --store device \
  --name device-portal --certificate /path/fullchain.pem --private-key /path/key.pem
cargo run -- certificate list --database examples/riverlb.db --store device
cargo run -- certificate delete --database examples/riverlb.db --store device --name unused
```

The default CLI store is `virtual-server`. See [home features](home-features.md) for
ACME setup and recovery. Certificate-only trust objects, DNS-01, encrypted PEM keys,
HSMs and mTLS remain unsupported. Backend trust uses separate
[Server TLS profiles](server-tls.md) with external CA PEM files.
