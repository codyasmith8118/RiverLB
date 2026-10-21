# Signed offline application updates

System → Updates verifies and stages publisher-signed `.rlbupdate` bundles. Activate staged update is a separate action and restarts traffic and management. This implementation supports installed **standalone AlmaLinux 10 x86-64 appliances**. Repository instances can verify bundles with the CLI. HA activation is blocked until rolling and mixed-version update qualification is implemented.

## Build and sign

Build and test the application RPM in the matching AlmaLinux environment using `scripts/build-rpm.sh` and `scripts/test-rpm.sh`. Sign the exact qualified binary from that package, rather than a different development build. The bundle contains only the application executable and signed metadata; it has no shell hooks or arbitrary installation paths. This does not update the OS, kernel, dependencies, service units or updater itself. Changes to those components require a qualified RPM/appliance maintenance release.

Keep the Ed25519 publisher private key on a controlled signing host. Create it once there, outside the repository:

```bash
openssl genpkey -algorithm ED25519 -out /secure/signing/riverlb-ed25519.pem
chmod 600 /secure/signing/riverlb-ed25519.pem
scripts/sign-update.py --binary /qualified/riverlb --key /secure/signing/riverlb-ed25519.pem \
  --version 0.1.0 --sequence 1 --output /release/riverlb-0.1.0.rlbupdate
```

Use the binary's actual version and a publisher-managed, strictly increasing sequence for every accepted release, including a reissue after rollback. The script also exports a public `.trust.json`. Provision only that public file on the appliance through the console, after verifying its fingerprint through an independent trusted channel:

```bash
sudo install -d -m 0755 /etc/riverlb-updater
sudo install -o root -g root -m 0644 riverlb-0.1.0.trust.json /etc/riverlb-updater/update-trust.json
```

The trust directory is outside the daemon's writable paths, including before a key has been provisioned. The GUI cannot set trust or sign updates. A trust store can contain up to sixteen explicitly trusted keys for a controlled transition; removing an old key revokes it. There is no automatic root-key rotation protocol. Do not ship private signing keys, sample passwords or appliance databases in release artifacts.

For build verification, `riverlb update-verify --bundle FILE --trust PUBLIC_FILE --sequence PREVIOUS` accepts an explicit public file owned by the current user. Installed GUI/helper activation always uses the fixed root-owned trust path. Verification checks Ed25519 signatures over the exact metadata bytes, payload length and SHA-256, ELF architecture, product/platform, schema compatibility, creation/expiry time and sequence. Set the appliance clock correctly; expiry verification has no bypass.

## Extract the packaged application

From the repository root, after building and testing the RPM, extract its executable
with `rpm2cpio` and `cpio`. Select the exact qualified RPM explicitly:

```bash
rpm_file=/absolute/path/to/riverlb-VERSION-RELEASE.x86_64.rpm
payload_dir=$(mktemp -d)
rpm2cpio "$rpm_file" | (cd "$payload_dir" && cpio -id ./usr/lib/riverlb/base/riverlb)
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
python3 scripts/sign-update.py \
  --binary "$payload_dir/usr/lib/riverlb/base/riverlb" \
  --key /secure/signing/riverlb-ed25519.pem \
  --version "$version" --sequence 1 --output "dist/riverlb-$version.rlbupdate"
```

Run this from the same source version used for the RPM and replace sequence `1`
with the next publisher sequence. Remove the temporary payload directory when
finished. Provision the exported public trust file as described above, then upload
the bundle under **System → Updates**, verify/stage it and select **Activate staged
update**. Back up first, schedule the restart and verify traffic afterward.

## Activation and recovery

The root helper copies the bundle into its protected updater directory, repeats signature verification, checks the decoded payload against the verified length and checksum, validates root-owned paths and the version reported by the executable, and captures readiness through root-only Unix IPC. The daemon cannot write this verification copy from its service sandbox. The helper stops the standalone service, checkpoints the database with the previous application, durably records recovery and the accepted sequence, then atomically changes the current version and starts the service.

Readiness checks version, revision, management identity, standalone role and the previously healthy virtual servers. A pool already down before activation does not cause an unrelated update rollback. The local IPC contains only allowlisted status fields and cannot change configuration or read keys. It does not depend on a browser session, management source allowlist, proxy settings, or a readiness-token authentication exception. End-to-end application traffic and public TLS access remain release-lab acceptance checks.

Failed readiness restores the previous executable **and its compatible database checkpoint**, including WAL state. Recovery uses the previous validated application's reader; it does not run an older binary against a migrated live database. Sessions and API tokens are revoked by restore. Configuration or statistics written during a failed candidate's readiness window may be discarded with that checkpoint. Backup files and external TLS/OS files are separate from database recovery.

Recovery runs before every standalone service start, including after interrupted activation on the same boot. The helper refuses replacing a live, locked database. Its separate privileged recovery journal and sequence record are outside the daemon's writable paths. A rollback still consumes the update sequence; recovery preserves it even if power loss occurs between journal and status writes. If restore fails, the journal stays and traffic remains stopped for console repair.

At the console, with the service stopped, `sudo /usr/libexec/riverlb/riverlb-update recover` retries an interrupted recovery. Preserve `/var/lib/riverlb-updater/checkpoint.json` as private recovery material. Do not delete lock files or edit the sequence to force a replay. History records the last hundred activation/rollback outcomes.

## Qualification

`tests/signed_updates.py` checks OpenSSL/Rust signature interoperability, tampering, expiry, replay and trust permissions. `tests/updates_helper.py` runs isolated state-machine fixtures for success, readiness failure, interrupted journal/highwater writes, compatible-reader rollback, database locks, path/FIFO rejection, payload substitution and durable recovery ordering. It does not control host services or touch a live database. The disposable installed-package smoke test verifies and stages the complete release executable, checks a bounded verification time, and exercises actual root-only IPC authorization.

Before production promotion, run cold-boot, interrupted-update, disk-full and actual traffic tests on the supported appliance image, with the final service policy and SELinux enforcing. Online channels, automatic fleet rollout, HA rolling updates and transactional OS rollback are separate future work. An online channel should use a complete metadata protocol such as [The Update Framework](https://theupdateframework.io/docs/overview/); this offline format is not a TUF implementation.
