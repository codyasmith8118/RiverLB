# 003: Online CLI through the revisioned HTTPS API

Task #20 adds `riverlb manage` to the existing binary without new dependencies.
The daemon owns authorization, validation, configuration revisions, transactions
and confirmation recovery. The CLI uses verified HTTPS and the same endpoints as
the portal; it does not open the database or implement a second configuration
schema. The existing offline recovery commands and loopback status command keep
their behavior.

The bounded command surface is live status, complete configuration get/validate/
diff/apply/history/rollback, explicit confirmation/revert, session login/logout
and CRUD for every named collection of `Config`, including network collections.
Nested members/settings are updated with their parent; multi-object changes use
one complete configuration transaction. Certificate/key stores and account/OS
lifecycle operations retain their existing portal/API/offline workflows.

Each mutation requires the user's explicit reviewed revision and never retries.
Rollback applies a historical configuration as a new revision. Connectivity
changes never auto-confirm, follow redirects or forward authentication to the
returned endpoint. The server's existing deadline and crash recovery protect
interrupted sessions. Transport failures after sending a mutation require
inspection before resubmission.

Credentials enter through owner-only regular files or login JSON on stdin.
Successful login writes a new private session file; secrets never appear in
arguments, output, diagnostics, help or completion. All requests have bounded
bodies/timeouts and verify both trust and hostname/IP. Schema-1 JSON output and
categorized exit codes are the automation contract documented in
[the CLI guide](../management-cli.md).

Real local HTTPS integration exercises the shared API/configuration model,
including role/scope denial, MFA, expiry and interrupted confirmation. Existing
browser/API tests provide the other sides of the parity contract. Qualification
claims must identify the tested source and evidence; the design alone does not
claim that tests have passed or that later binaries are qualified.
