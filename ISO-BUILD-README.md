# Build a new installer ISO and prepare update signing keys

This creates a **new-installation ISO**, then configures the installed appliance
to accept your signed software updates.

The ISO includes `packaging/update/update-trust.json` in the application RPM.
Installation places this public update trust key at
`/etc/riverlb-updater/update-trust.json`, owned by root with mode 0644.
Keep the private signing key on the signing machine; it is never included in the
ISO, RPM or source repository. The release publisher public key is committed
to the repository so rebuilds use the same trust identity.
These keys sign application updates. They do not sign the ISO/RPM or enable Secure Boot.

## 1. Prepare the build machine

Use x86-64 Linux with internet access, working **rootless Podman**, Python 3.11+,
Git, OpenSSL and `flock`. Open a terminal in the RiverLB repository folder.
Run the build as your normal user, without `sudo`.

Check the main tools:

```bash
podman info
python3 -c 'import tomllib'
openssl version
```

## 2. Create your signing key once

Run this on the machine you will use to sign updates:

```bash
install -d -m 0700 "$HOME/.local/share/riverlb-signing"
if [ ! -e "$HOME/.local/share/riverlb-signing/publisher.pem" ]; then
  (umask 077; openssl genpkey -algorithm ED25519 \
    -out "$HOME/.local/share/riverlb-signing/publisher.pem")
fi
chmod 600 "$HOME/.local/share/riverlb-signing/publisher.pem"
```

The private key is `~/.local/share/riverlb-signing/publisher.pem`.
Back it up securely outside the repository. Reuse it for future builds and updates.
Do not put it in Git, an ISO, a release download or an appliance.

## 3. Export the public update trust file

Copy this whole block into the same terminal:

```bash
python3 - <<'PY'
import base64
import hashlib
import json
import subprocess
from pathlib import Path

folder = Path.home() / ".local/share/riverlb-signing"
der = subprocess.check_output([
    "openssl", "pkey", "-in", str(folder / "publisher.pem"),
    "-pubout", "-outform", "DER",
])
assert len(der) == 44 and der[:12].hex() == "302a300506032b6570032100", "Expected Ed25519 key"
public = der[12:]
trust = {"format": 1, "keys": [{
    "id": hashlib.sha256(public).hexdigest(),
    "public_key": base64.b64encode(public).decode(),
}]}
path = folder / "update-trust.json"
path.write_text(json.dumps(trust, indent=2) + "\n")
print("Public trust file:", path)
print("Public key ID:", trust["keys"][0]["id"])
PY
sha256sum "$HOME/.local/share/riverlb-signing/update-trust.json"
```

For your own signing identity, copy the exported public JSON into
`packaging/update/update-trust.json` before building. Never replace the release
public key unless you intend to change which publisher new appliances trust.

Save the checksum somewhere you trust. This JSON file contains only the public key
and can be copied to appliances. Keep the same file for all appliances that should
accept updates from this signing key.

## 4. Build the installer ISO

Save your code changes, then run from the repository root:

```bash
./scripts/build-appliance-iso.sh
```

This downloads the pinned AlmaLinux base media, builds and tests the RPMs, and
creates and checks the installer ISO. The first run can take a while.
Stop if the script reports a failure. Do not edit source files while it runs.

Your installer is:

```text
dist/iso/riverlb-installer.iso
```

Check its checksum:

```bash
(cd dist/iso && sha256sum -c riverlb-installer.iso.sha256)
```

Logs are in `dist/logs/`. Previous ISOs are in `dist/iso/archive/`.
Use the default installer mode. The separate `--mode image` option is unattended
media that clears a disposable builder disk.

## 5. Install and complete first boot

1. Test the ISO in a new VM with a blank disk, at least 4 GiB RAM and an
   x86-64-v3 compatible CPU.
2. Attach `riverlb-installer.iso` and boot it.
3. Choose the installation disk and review it before selecting **Begin Installation**.
4. When installation finishes, detach the ISO and reboot.
5. Complete the console wizard: hostname, management IP, administrator and root recovery password.
6. Open the HTTPS address shown by the wizard and sign in.

See the [installation guide](docs/installer-experience.md) for the detailed screens.
Installing a new ISO is not an in-place application update.

## 6. Verify the embedded public update key

New installations already contain the public trust file from the RPM. At the
appliance root console, verify it against your source/release copy:

```bash
sha256sum /etc/riverlb-updater/update-trust.json
stat -c '%U %a' /etc/riverlb-updater/update-trust.json
```

Expected ownership and mode: `root 644`. Open **System → Updates**; publisher
trust should already be configured. Upgrades preserve a locally modified trust
file with RPM's `%config(noreplace)` policy. Inspect any `.rpmnew` file before
changing existing publisher trust.

For an older appliance without the key, transfer only the public JSON through a
trusted channel and install it at `/etc/riverlb-updater/update-trust.json` with
root ownership and mode 0644. Never copy `publisher.pem` onto the appliance.

## 7. Build your first downloadable software update

Follow the [software update README](SOFTWARE-UPDATES-README.md).
Sign with the same `publisher.pem` whose public key is embedded in the ISO.
You do not need to rebuild the ISO for future application or GUI updates.

For release qualification and advanced build options, see the
[appliance build reference](appliance/README.md).
