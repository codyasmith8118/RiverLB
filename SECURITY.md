# Security policy

RiverLB is experimental and production qualification is incomplete. Security fixes
are developed against the current source tree; there is no published long-term
support policy for older versions. Review the [release checklist](docs/release-readiness.md)
and [deployment boundaries](docs/security-and-database.md) before deployment.

## Management transport

Non-loopback management requires HTTPS. Plain HTTP is accepted only on loopback
for local development. Existing remote HTTP configurations must be migrated to
HTTPS before upgrading; the daemon rejects them at startup and configuration apply.
See [HTTPS setup](docs/security-and-database.md#https-management).

## Management resource limits

Management admits at most 64 connections across listener reconfiguration, including
TLS handshakes. Connections expire after 180 seconds; browsers and API clients
must reconnect. TLS handshakes and HTTP headers have 10-second deadlines, and
request bodies have an absolute 120-second deadline, including update uploads.
Disallowed source addresses are disconnected before HTTP or TLS processing;
existing connections are also checked against the current allowlist per request.

Concurrent request bodies reserve their route's maximum upload size against a
256 MiB admission budget. This bounds admitted body sizes rather than total process
memory; JSON parsing and application work need additional memory. Busy upload
capacity returns HTTP 503, and excess connections are closed.

Sign-in permits ten attempts per source IP per minute and at most four concurrent
password checks. Forwarding headers do not determine the source. Clients sharing
a NAT address share its allowance. The source table is bounded to 4096 entries,
expires entries after one minute and evicts the oldest entry when full. Busy or
rate-limited sign-ins return HTTP 429. These controls complement a restricted
management network and source allowlist.

## Reporting a vulnerability

Email **cody.a.smith@protonmail.com** privately with suspected vulnerabilities.
Include the affected commit or version, prerequisites, impact and a minimal
reproduction using synthetic data. Do not post vulnerability details in public
issues. GitHub private reporting, when enabled, is also available at
[Report a vulnerability](https://github.com/codyasmith8118/RiverLB/security/advisories/new).

Never send real credentials, private keys, database files, backups or private
appliance configurations. Request a secure exchange method for sensitive evidence.

Please coordinate disclosure with the maintainer so a fix and operator recovery
instructions can be prepared. No response time or security audit certification is
promised.
