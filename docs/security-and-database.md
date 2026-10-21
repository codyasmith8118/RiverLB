# Accounts, management security, database and HTTPS

Use this guide to create or recover a local administrator, secure management
access and understand saved configuration. For a new appliance image, complete
[console setup](installer-experience.md) first; do not create its database ahead
of the wizard.

- [First sign-in](#upgrade-and-first-sign-in) and [HTTPS management](#https-management).
- [Local accounts and roles](#local-administrator-management).
- [MFA, session limits and API tokens](#management-security).
- [API authentication](#authentication-and-api).

## Upgrade and first sign-in

For a repository instance, stop its running daemon with Ctrl-C and allow up to
ten seconds to drain. Build and create an administrator:

```bash
# From the repository checkout:
cargo build --locked
cargo run -- admin --database examples/riverlb.db --username admin
# Enter a password of at least 12 bytes at the hidden prompt.
cargo run -- serve --config examples/riverlb.toml
```

Open <http://localhost:18090> and sign in. There is no default account or password. Password changes are available under System → Settings. Changing a password preserves the account's role/MFA enrollment and revokes its sessions and API tokens. Sign out revokes the current session.

By default, the database replaces the configuration file extension with `.db`; `examples/riverlb.toml` uses `examples/riverlb.db`. `serve --database PATH` selects another database. Use the same path with `admin`, `import` and `export`. Local database CLI commands require the daemon to be stopped and acquire an exclusive companion `.db.lock` file lock. Do not delete a lock file to bypass an active owner; the OS releases the lock when the process exits. A missing parent directory must be created before use.

On first startup, validated TOML is imported as revision 1. Subsequent starts load the latest database revision, and portal Save and apply commits a new configuration and audit event in one SQL transaction. TOML is no longer rewritten or reimported automatically. Failed validation or listener preparation preserves the prior database revision and runtime. A crash after database commit recovers the committed configuration on restart. Network changes still use compensating rollback and have separate crash-recovery limitations. The database also stores bounded aggregate traffic samples; see [traffic statistics](traffic-statistics.md).

To import changed TOML or recover a management port while stopped:

```bash
cargo run -- import --database examples/riverlb.db --config examples/riverlb.toml
cargo run -- export --database examples/riverlb.db > riverlb-config.json
```

Web JSON import/export includes configuration only. The private-backup web/CLI
workflow includes managed certificate keys, password hashes and ACME credentials;
keys are not encrypted at rest. See [backup and restore](home-features.md#private-backups-and-restore)
for consistent online snapshots, portal staging and offline transactional activation.
External PEM/CA files must be backed up separately. Do not copy only an open database
main file or use a second SQLite writer while RiverLB owns it. Schema versions 1–5
upgrade atomically to schema 6, retaining previous data and adding separate authentication metadata, security policy, session activity, and API token tables. Existing accounts retain administrator access unless their roles are changed. Legacy sessions without activity records require sign-in again. Unsupported versions are rejected. An older application requires a compatible database restore when rolling back.

## HTTPS management

Use a trusted certificate whose subject alternative names include the management hostname or IP. For local testing, generate a self-signed certificate and protect the key:

```bash
mkdir -p ~/.local/share/riverlb/tls
chmod 700 ~/.local/share/riverlb/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout ~/.local/share/riverlb/tls/key.pem \
  -out ~/.local/share/riverlb/tls/cert.pem \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 600 ~/.local/share/riverlb/tls/key.pem
```

On System → Settings, choose HTTP or HTTPS. For HTTPS select a certificate from the Device Certificates store, or use absolute certificate/key PEM paths. Save and apply, then follow the new portal link. Management protocol and certificate changes can reuse the same port. Self-signed certificates require client trust. Management can bind loopback or a specific network address. See [certificate management](certificates.md) for generation and external-CA signing requests.

For the initial TOML import:

```toml
management = "127.0.0.1:9443"
management_protocol = "https"
management_tls = { certificate = "/absolute/cert.pem", private_key = "/absolute/key.pem" }
```

Certificate paths are stored in the database. PEM private-key bytes stay in protected files and are not returned by the configuration API or JSON exports. Both paths are required; invalid PEM or mismatched certificates/keys reject validation/apply. TLS 1.2/1.3 use Rustls. Management certificate changes apply to new connections on the same port. Managed device certificates can use ACME renewal schedules.

## HTTPS virtual servers

Click a virtual server in Local Traffic → Virtual Servers and select its certificate or enter TLS certificate/key paths. Save and apply. This terminates client TLS and forwards application bytes to a plain backend or a verified Server TLS profile. Backends that require HTTPS need a matching verified Server TLS profile, or TLS passthrough if the virtual server does not terminate client TLS.

```toml
[[virtual_servers]]
name = "secure-web"
listen = "127.0.0.1:8443"
tls = { certificate = "/absolute/cert.pem", private_key = "/absolute/key.pem" }
members = ["127.0.0.1:8001"]
```

TLS handshake duration is bounded by `connect_timeout_ms`, and handshake failures close the connection. Traffic admission/reservations are held during handshake. Existing sessions keep their original TLS configuration during apply. HTTP mode parses configured application features; raw TCP mode does not. HTTP/2 and client mTLS are not implemented. Managed certificate import/assignment is available under System → Virtual Server Certificates; see [certificate management](certificates.md). Verified backend TLS uses [Server TLS profiles](server-tls.md). SNI, ACME, self-signed generation and external-CA CSR workflows are supported.

## Authentication and API

Passwords use salted Argon2id. Session cookies are HttpOnly, SameSite=Strict, have an eight-hour absolute lifetime, and use Secure over HTTPS. Only SHA-256 hashes of random 256-bit session tokens are stored. Login attempts are limited globally to ten per minute per process; account/security confirmation attempts share a thirty-per-minute process budget. Host/origin and mutation-header checks remain mandatory, including on login. Unauthenticated API and metrics requests receive 401; insufficient role/token scope receives 403. The portal redirects to `/login`. Login assets and `/healthz` are public within the configured management source restrictions.

`POST /api/v1/auth/login` accepts `{username,password,code?}` and sets a session cookie. `GET /api/v1/auth/me` returns the identity, role and token scope. `POST /api/v1/auth/logout` revokes the current session. `POST /api/v1/auth/password` accepts `{current_password,new_password,code?}`. MFA-enabled accounts must provide an unused authenticator or recovery code when confirming their password. Mutations require JSON and `X-RiverLB-Request: configure`. The login body limit is 4 KiB; other JSON endpoints use Axum's 2 MiB limit. API clients may retain a signed-in cookie or use a scoped bearer token. The HTTP loopback `status --session-stdin` command reads a session token from stdin; it currently does not connect to HTTPS management.

The database is sensitive even though passwords/tokens are hashed: enrolled TOTP secrets and managed certificate keys require protection. New files and journals use private permissions; place them on a filesystem that enforces Unix permissions. Database encryption at rest is not provided. Databases, PEM files and keys are Git-ignored. Audit retention/forwarding is configurable through operations; configuration history remains durable and contributes to disk use. Network ownership journals remain separate from the database.

Security integration tests verify login, CSRF rejection, password change, rate limiting, HTTPS/TLS traffic and stopped-database SQLite reads. Release authentication tests exercise real HTTP role/token restrictions, actual peer allowlists, TOTP/recovery single use, session/token revocation and durable idle expiration. Store tests inject SQL failures to check atomicity, concurrent replay rejection, reset races and schema/backup compatibility. These fixtures do not certify production firewall, fencing or SELinux behavior.

## Local administrator management

Open **System → Local Administrators** to list accounts, roles and MFA enrollment. Administrators can create accounts, change roles, reset passwords, revoke sessions or delete an account. Changes apply immediately and require the actor's current password plus an unused MFA code if enrolled. New passwords contain 12–1024 bytes. Account changes invalidate affected sessions and API tokens. You cannot delete your signed-in account or delete/demote the last administrator.

| Role | Allowed operations |
|---|---|
| Administrator | Full configuration, account, security and lifecycle management. |
| Operator | Nonsensitive reads, statistics reset, persistence clearing and HA operational actions. Configuration writes remain administrator-only. |
| Read-only | Nonsensitive reads and the user's own password/MFA actions. No traffic or system changes. |

Management middleware enforces these roles on direct API requests. GUI visibility is supplementary. Private backups, account inventories, audit administration, lifecycle settings and security policy require administrator access. The account-name API remains compatible; `GET /api/v1/administrators?details=true` returns role/MFA metadata.

Accounts/security policy are local and do not participate in HA traffic sync. Private backups include password hashes, role/policy metadata and MFA secrets/recovery hashes. API tokens and sessions are excluded/revoked on restore. Legacy backups without auth metadata restore administrator-only defaults. See [operations](operations.md) for scheduled encrypted backups; the original private backup download is plaintext.

The offline `riverlb admin --database PATH --username NAME` command provides initial setup and recovery while the daemon is stopped. It sets the password, restores administrator role, clears MFA/recovery codes, and revokes sessions/tokens. For an installed appliance use `/var/lib/riverlb/riverlb.db`; protect console/root access. Account mutations are audited without recording passwords or MFA secrets, and account APIs do not expose their stored hashes.

## Management Security

The Management Security page configures optional TOTP MFA, idle-session timeout, source allowlists and administrator-owned API tokens. These actions apply immediately, independently of the traffic draft.

For MFA, confirm the current password, enter the generated secret into an authenticator app, and verify a six-digit code within ten minutes. Confirmation shows ten recovery codes once and revokes existing sessions/tokens. Save recovery codes outside the appliance and sign in again using the next authenticator code or an unused recovery code; the enrollment code has already been consumed. TOTP uses RFC 6238 SHA-1 with 30-second periods and a one-period clock tolerance. Successful codes cannot be replayed, including concurrently. Recovery codes use random entropy, are hashed, and are consumed atomically. Keep appliance time accurate. Disabling MFA requires password/MFA confirmation and revokes sessions/tokens.

Idle timeout ranges from 60 to 28800 seconds and defaults to 1800 seconds. Explicit interactive activity extends an unexpired session; background polling does not. An activity header cannot revive an expired session. Source policy accepts up to 64 IPv4/IPv6 addresses or CIDRs and checks the actual connecting peer. Forwarded-IP headers are not trusted. An empty list permits all sources. A new allowlist must retain the actor's current source address; later network changes can still require console recovery.

Tokens expire after 60 seconds to one year and are displayed once. Their inventory contains metadata rather than credentials; storage contains only SHA-256 hashes. Token creation requires password/MFA confirmation. An issued token is an independent bearer credential and must be kept secret.

| Scope | Allowed requests |
|---|---|
| Monitoring | Read health/status, node health, statistics/history, appliance summary, metrics and operations health. |
| Read | Nonsensitive GET/HEAD requests, including configuration; excludes account, audit, backup, lifecycle and security endpoints. |
| Configure | Nonsensitive reads plus configuration validation/preview/apply/confirm/revert, statistics reset and persistence operations; excludes account/security administration and lifecycle updates. |

Permissions are intersected with the owning account's current role. Use `Authorization: Bearer rlb_...`; mutations still require `X-RiverLB-Request: configure`. Revocation and account changes take effect immediately.

Security endpoints include `GET/PUT /api/v1/security/settings`, `GET /api/v1/security/mfa`, `POST /api/v1/security/mfa/{enroll,confirm,disable}`, `GET/POST /api/v1/security/tokens`, and `DELETE /api/v1/security/tokens/{id}`. Password-confirmed actions include `current_password` and optional `code`; enrollment confirmation accepts the pending authenticator `code`.

Installed root services using the fixed appliance database expose `/run/riverlb/operations.sock` for lifecycle readiness. Systemd creates its private runtime directory; direct installed CLI startup can create the missing directory beneath a trusted `/run`. Existing directories with public permissions or incorrect ownership are rejected without adoption. This private Unix socket authenticates kernel peer UID 0 and accepts only a bounded status request. Its response excludes keys, accounts, tokens and raw configuration. Repository instances do not expose it. It provides no mutation commands or HTTP source-allowlist bypass.

See [configuration confirmation and recovery](configuration-recovery.md), [signed offline application updates](offline-updates.md), and [service hardening](service-hardening.md) for retained privileges and installed VM qualification limits.

## Database implementation

RiverLB uses the Rust-native **Turso 0.8.1** embedded database engine, with SQLite-compatible SQL and files. This is the new Rust engine, not the older C-based libSQL core. It runs locally without a cloud account. Accounts, hashed sessions, configuration revisions and an audit log live in this database. Member counters, scheduling, health state and live sockets stay in memory; no SQL runs per forwarded packet.

Upstream references: [Rust engine and compatibility scope](https://github.com/tursodatabase/turso), [Rust API](https://docs.rs/turso/0.8.1/turso/). This integration uses local basic SQL and verifies SQLite reads; it does not claim every SQLite extension or libSQL replication feature is supported.

