# Build, share and install a software update

Use this for application and web-interface changes on an installed **standalone
AlmaLinux 10 x86-64 appliance**. You do not need to reinstall the appliance.

The process is: **build → sign → share a download → upload on the appliance → activate**.
RiverLB does not automatically download or push updates. HA activation is not supported.
OS, dependency, service-unit and updater changes need RPM/appliance maintenance;
the update file replaces only the application and its embedded web interface.

## 1. Prepare the build machine

Use an x86-64 Linux machine with internet access, working rootless Podman,
Python 3.11+, Git, OpenSSL, `flock`, `rpm2cpio` and `cpio`.
Run build commands as your normal user, from the RiverLB repository folder.

If you have not created signing keys yet, complete
[ISO README steps 2 and 3](ISO-BUILD-README.md#2-create-your-signing-key-once).
Keep using that same private key for future updates.

## 2. Build and test the updated software

Save your code changes, then run:

```bash
export RIVERLB_RPM_RELEASE=$(date -u +%Y%m%d%H%M%S)
./scripts/build-rpm.sh
./scripts/test-rpm.sh
```

Stop if either command fails. Build outputs are in `dist/rpm/`.
The build includes saved, uncommitted code changes. Avoid editing files during the build.

## 3. Extract the application from the new RPM

List the files:

```bash
ls dist/rpm/riverlb-*.rpm
```

Choose the **main** RPM, named `riverlb-VERSION-RELEASE.x86_64.rpm`.
Do not choose `riverlb-ha-...` or `riverlb-appliance-...`.
Replace the example path below with that exact filename:

```bash
set -euo pipefail
rpm_file=$(realpath dist/rpm/riverlb-VERSION-RELEASE.x86_64.rpm)
payload_dir=$(mktemp -d)
rpm2cpio "$rpm_file" | (cd "$payload_dir" && cpio -id ./usr/lib/riverlb/base/riverlb)
```

Keep this terminal open for the next step.

## 4. Sign the update

Set `sequence` to a number **higher than every update you previously issued**.
Use `1` only for your first update; use `2`, `3`, and so on afterward. A rollback
still consumes its number. Keep a release log of the numbers you issue.

```bash
sequence=1
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
update_file="dist/riverlb-${version}-${sequence}.rlbupdate"
python3 scripts/sign-update.py \
  --binary "$payload_dir/usr/lib/riverlb/base/riverlb" \
  --key "$HOME/.local/share/riverlb-signing/publisher.pem" \
  --version "$version" \
  --sequence "$sequence" \
  --output "$update_file"
sha256sum "$update_file" > "$update_file.sha256"
```

Use the same source version as the RPM you just built. The script creates the
`.rlbupdate` and a public `.trust.json` file. Do not reuse an existing output name.
Bundles expire after **30 days** by default. Add `--valid-days 90` when signing if
you need 90 days; the maximum is 366. Expired bundles must be reissued with a new sequence.

## 5. Make the update available to download

Create a release in this GitHub repository's **Releases** area, or use your normal
HTTPS file server. Attach these two files:

- `dist/riverlb-VERSION-SEQUENCE.rlbupdate`
- `dist/riverlb-VERSION-SEQUENCE.rlbupdate.sha256`

Include the version, sequence, expiry and a short description of the changes.
Test the bundle on a disposable standalone appliance before publishing it for others.
Never upload `publisher.pem`. The public trust file is installed separately,
through a trusted channel; downloading an update must not change the appliance's trust.

## 6. Install the update on the appliance

1. New release ISOs include the publisher public key. Verify trust using
   [ISO README step 6](ISO-BUILD-README.md#6-verify-the-embedded-public-update-key);
   older appliances may need the public key installed first.
2. Back up the appliance using **System → Backups & Recovery**. Keep the backup private.
3. Download the `.rlbupdate` file to the computer where you use the appliance web interface.
4. Sign in to the appliance as an administrator and open **System → Updates**.
5. Under **Update bundle**, choose the downloaded file.
6. Click **Verify and stage bundle**. Check the displayed version, sequence and expiry.
7. During a maintenance window, click **Activate staged update** and confirm.
8. Wait for the application to restart, then refresh and sign in again if needed.
9. Check the installed version, update history and actual traffic through your services.

Traffic and management restart during activation. Failed readiness checks trigger
application/database rollback. If verification fails, check the public trust key,
appliance clock, bundle expiry and sequence; do not bypass verification.

For recovery details, see [signed offline updates](docs/offline-updates.md).
