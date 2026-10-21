#!/usr/bin/env bash
# Build an unsigned application candidate. This script does not install or publish it.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
commit=$(git rev-parse HEAD)
source_epoch=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
platform=$(rustc -vV | sed -n 's/^host: //p')
if [[ "$platform" != *linux* ]]; then
    echo "This candidate pipeline requires a Linux build host." >&2
    exit 1
fi
cargo build --release --locked
stage_dir=$(mktemp -d)
candidate_dir=""
trap 'rm -rf -- "$stage_dir"; if [[ -n "$candidate_dir" ]]; then rm -rf -- "$candidate_dir"; fi' EXIT
bundle_name="riverlb-${version}-${platform}-${commit:0:12}"
install -d "$stage_dir/$bundle_name/deploy/ha" dist
candidate_dir=$(mktemp -d "$project_dir/dist/.candidate.XXXXXX")
install -m 0755 "${CARGO_TARGET_DIR:-target}/release/riverlb" "$stage_dir/$bundle_name/riverlb"
install -m 0644 LICENSE "$stage_dir/$bundle_name/"
cat > "$stage_dir/$bundle_name/README.md" <<'README'
# RiverLB application candidate

This unsigned development archive contains the application binary and HA helpers.
It is not an installer ISO, RPM or signed offline update bundle. Its Linux ABI
matches the build host; test it on the intended operating system before use.

Run `./riverlb --help` for commands. A fresh standalone instance needs a TOML
configuration, an administrator created with `./riverlb admin --database PATH`,
and `./riverlb serve --config PATH --database PATH`. There is no default password.
Stop the daemon before local database commands. Use HTTPS for remote management.

HA requires Pacemaker/Corosync, operator-configured fencing and peer trust in
addition to these helper files. Do not deploy HA by copying helpers alone.

The source repository's docs/README.md indexes configuration and deployment guides.
manifest.json records build identity and the binary checksum. SHA256SUMS detects
corruption; it does not authenticate the publisher. This archive is not a
production-qualified release.
README
for file in riverlb-authority riverlb-cluster riverlb-traffic; do
    install -m 0755 "deploy/ha/$file" "$stage_dir/$bundle_name/deploy/ha/$file"
done
install -m 0644 deploy/ha/riverlb-ha.service "$stage_dir/$bundle_name/deploy/ha/"
python3 - "$stage_dir/$bundle_name/manifest.json" "$version" "$commit" "$platform" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
path, version, commit, platform = sys.argv[1:]
Path(path).write_text(json.dumps(dict(format_version=1, version=version,
    commit=commit, platform=platform, signed=False, purpose="build-candidate",
    dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'])),
    binary_sha256=hashlib.sha256(Path(path).with_name('riverlb').read_bytes()).hexdigest(),
    cargo_lock_sha256=hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest()), indent=2) + "\n")
PY
(cd "$stage_dir/$bundle_name"; find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$stage_dir" -cf - "$bundle_name" | gzip -n > "$candidate_dir/$bundle_name.tar.gz"
(cd "$candidate_dir"; sha256sum "$bundle_name.tar.gz" > "$bundle_name.tar.gz.sha256")
# Do not truncate a previous candidate if compression or checksum creation fails.
mv -- "$candidate_dir/$bundle_name.tar.gz" "dist/$bundle_name.tar.gz"
mv -- "$candidate_dir/$bundle_name.tar.gz.sha256" "dist/$bundle_name.tar.gz.sha256"
echo "Unsigned candidate: dist/$bundle_name.tar.gz"
