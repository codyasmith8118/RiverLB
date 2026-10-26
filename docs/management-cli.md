# Online management CLI

`riverlb manage` uses the same revisioned API as the portal. It requires HTTPS
with CA and hostname/IP verification. Trust defaults to the system CA bundle;
`--ca FILE` selects a PEM trust bundle for a private appliance CA. The server's
existing management Host restrictions still apply: use its configured IP or a
supported localhost origin. There is no insecure mode, redirect following,
automatic mutation retry or automatic connectivity confirmation.

## Authentication

Create a scoped API token in the portal, then save it in an owner-only regular
file (mode `0600`). Alternatively, supply an existing session with
`--session-file FILE`. Symlinks and group/world-readable credential files are
rejected. Tokens, passwords and MFA codes are never command arguments or URLs.
Credential files belong to the invoking user. API token files contain the full
`rlb_...` token; session files contain the hexadecimal session value.

For example, using an already provisioned token file:

```sh
riverlb manage --url https://192.0.2.10:18090 --ca appliance-ca.pem \
  --token-file "$HOME/.riverlb-token" status
```

`login --output FILE` reads one JSON document from stdin with `username`,
`password` and optional `code` (TOTP or unused recovery code). Feed it through a
secret manager or an owner-only file redirected to stdin; do not type a secret
into a shell command or place it in shell history. Login creates a new mode-0600
session file and refuses to overwrite an existing file. The response contains
only `authenticated: true`. Server-side MFA, lockouts, session expiry, roles and
token scopes are unchanged. `logout` revokes the session at the server; remove
the local file separately. Scoped bearer tokens cannot call session logout.

```sh
riverlb manage --url https://192.0.2.10:18090 --ca appliance-ca.pem \
  login --output "$HOME/.riverlb-session" < /secure/login.json
```

Commands below assume the same `--url`, `--ca` and authentication options before
the command. Read-only/operator accounts and monitoring/read tokens cannot
perform configuration mutations; the server makes that decision on every call.

## Review and apply

| Command | Behavior |
|---|---|
| `status` | Live virtual-server/member status |
| `get` | Current configuration, revision, network mode and pending confirmation |
| `validate --input CONFIG.json` | Validate a complete raw configuration without activation |
| `diff --revision N --input CONFIG.json` | Server-generated diff and confirmation requirements |
| `apply --revision N --input CONFIG.json` | Apply at exactly the reviewed revision |
| `history` | Saved revision metadata |
| `rollback --target OLD --revision CURRENT` | Apply an old configuration as a new revision |
| `confirmation` | Current pending decision, deadline and previous management URL |
| `confirm --revision N` | Explicitly confirm pending revision N at the new management endpoint |
| `revert --revision N` | Explicitly restore the previous pending configuration |

Input files are raw configuration/object JSON, not the CLI output envelope.
For example, extract `.result.config` from `get` output using your JSON tool,
edit it, validate and review its diff, then apply with that same revision.
Mutations reject stale revisions. Object changes perform one read/modify/apply
transaction against that revision, and a racing API/GUI update still fails the
server's revision check. Never replace the revision with a newly fetched value
and retry a previously reviewed mutation without reviewing its diff again.

A successful apply can require connectivity confirmation. Inspect its
`confirmation` result, verify access using the reported management URL and your
trusted CA, and confirm explicitly. The CLI never follows a returned URL or
forwards credentials to it automatically. If the CLI is interrupted or the
request times out after submission, the outcome may be unknown: inspect current
configuration/history/confirmation before another mutation. Unconfirmed changes
retain the server's 120-second rollback deadline and restart recovery.

## Object CRUD

```sh
riverlb manage --token-file "$HOME/.riverlb-token" object pools list
riverlb manage --token-file "$HOME/.riverlb-token" object pools get web
riverlb manage --token-file "$HOME/.riverlb-token" object pools create --input pool.json --revision 4
riverlb manage --token-file "$HOME/.riverlb-token" object pools update web --input pool.json --revision 5
riverlb manage --token-file "$HOME/.riverlb-token" object pools delete web --revision 6
```

Supported kinds map to all named collections in the shared configuration model:
`virtual-servers`, `pools`, `nodes`, `domain-routes`, `health-monitors`,
`persistence-profiles`, `server-tls-profiles`, `river-rules`, `cookie-profiles`,
`http-profiles`, `vlans`, `self-ips` and `routes`. `update` replaces an entire
object and requires its name to match. Member lists, SNI mappings and other
nested settings are edited with their parent object. References and object
schemas follow the API/GUI model; invalid or referenced-object deletions fail
server validation. Atomic renames or multi-object edits use full-config apply.
Global settings use full-config apply too. Certificate/key stores, account and
appliance lifecycle operations remain their existing portal/API or offline
commands; they are not named collections in the traffic configuration model.

## Output and exit codes

Every successful JSON command writes exactly one JSON document to stdout:
`{"schema":1,"result":...}`. Whole-config/status/transaction/history results
preserve the API payload. Object list/get results include the observed
`revision` and `objects`/`object`. Fields may be added within schema 1; existing
field meanings and exit codes are stable. Errors write only a schema-1 JSON
error to stderr with a fixed `kind` and optional `http_status`; server error
bodies, credential values and underlying transport details are not echoed.
The online client does not initialize dependency trace logging, including when
`RUST_LOG=trace` is set.

| Exit | Meaning |
|---|---|
| 0 | Request succeeded; inspect whether apply still requires confirmation |
| 2 | Usage, local JSON/input, origin or credential-file error (Clap usage errors are plain text) |
| 3 | Authentication/authorization failure, including MFA, expired sessions or denied scopes |
| 4 | Invalid/missing object or server validation/not-found response |
| 5 | Stale revision, duplicate object or server transaction conflict |
| 6 | Other HTTP failure or invalid/oversized server response |
| 7 | Connection, timeout, TLS trust or certificate/hostname verification failure |

JSON input is limited to 2 MiB; responses to 8 MiB; each request, including TLS,
has a 15-second deadline. The client verifies every new connection and never
accesses a daemon database directly.

`riverlb manage --help` and nested help describe the command grammar.
`riverlb manage completion --shell bash` or `--shell zsh` prints static shell
completion without contacting management or opening credential files.

## Regression evidence

`python3 tests/management_cli.py` starts a disposable real HTTPS daemon and checks
all 13 object lifecycles, CLI/API response parity, valid/private trust and bad
hostname/CA cases, revisions, validation/diff/history/rollback, explicit
confirmation/revert, interrupted-confirmation restart recovery, roles/scopes,
MFA/recovery single use, durable idle expiry and credential-free output/help and
completion. It does not contact public services or modify host networking.
Existing portal browser and API suites continue to exercise the same shared
configuration model and authorization endpoints.
