# RiverLB 1.0.0

This release consolidates the RiverLB source into one initial release commit.
Existing deployments running the development version 1.1.9 must follow their
normal backup and migration process; the new version number is not a claim that
a downgrade from that development build has been qualified.

The installer includes the public Ed25519 update signing identity in
`/update-trust.json` and in the application RPM. The RPM installs it at
`/etc/riverlb-updater/update-trust.json` as root, mode 0644, preserving local
changes during upgrades. The private signing key is never distributed.

Public signing key ID:

```text
e0cedd0135e56bf30f0f0813eace94ade234198763a588ae9a30c59cf4a12019
```

Security changes include the patched TLS certificate verifier, independent
source IP login budgets, bounded concurrent password checks, management
connection and upload admission limits, and request-body deadlines. See
[security policy](../SECURITY.md) and the [audit](security-audit-2026-10-21.md).

The source includes the traffic manager, HTTPS management interface, HA helpers,
signed offline updates, backup/recovery, appliance packaging and installer.
The application update signing key authenticates `.rlbupdate` bundles. It does
not enable Secure Boot or add RPM/ISO signatures; release checksum signatures
are verified separately with the public Ed25519 key.

The appliance remains labelled **Pre-production**. Source, packaging and media
checks are distinct from booting and qualifying an installed appliance. Review
[release readiness](release-readiness.md) before production deployment.
