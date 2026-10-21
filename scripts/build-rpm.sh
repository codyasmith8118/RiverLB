#!/usr/bin/env bash
# Rootless Podman build; does not install packages or restart host services.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
if [[ $(uname -m) != x86_64 ]]; then
    echo 'The initial appliance package targets x86_64 only.' >&2; exit 1
fi
command -v podman >/dev/null
install -d dist
output_dir=${RIVERLB_RPM_OUTPUT_DIR:-dist/rpm}
mkdir -p -- "$(dirname -- "$output_dir")"
exec 9>dist/.rpm-build.lock
flock -n 9 || { echo "Another RPM build is running." >&2; exit 1; }
release=${RIVERLB_RPM_RELEASE:-1}
[[ "$release" =~ ^[1-9][0-9]*$ ]] || { echo 'RIVERLB_RPM_RELEASE must be a positive integer.' >&2; exit 1; }
inputs=$(python3 scripts/build-inputs.py prepare builder)
builder=$(python3 -c 'import json; print(json.load(open("packaging/build-inputs.lock.json"))["images"]["builder"]["id"])')
stage_dir=$(mktemp -d)
target_dir=$(mktemp -d)
trap 'rm -rf -- "$stage_dir" "$target_dir"' EXIT
# Explicit source allowlist avoids copying databases, keys, git metadata or build outputs.
for file in Cargo.toml Cargo.lock LICENSE README.md; do cp "$file" "$stage_dir/"; done
for folder in src web deploy/ha packaging docs appliance; do
    mkdir -p "$stage_dir/$(dirname "$folder")"
    cp -a "$folder" "$stage_dir/$folder"
done
# Examples also holds local databases and runtime settings during development.
# Only tracked TOML fixtures belong in the compiler/test source tree.
mkdir -p "$stage_dir/examples"
while IFS= read -r -d '' example; do
    mkdir -p "$stage_dir/$(dirname "$example")"
    cp -- "$example" "$stage_dir/$example"
done < <(git ls-files -z -- 'examples/*.toml')
install -d "$stage_dir/scripts"
install -m 0755 scripts/audit-appliance-security.py "$stage_dir/scripts/"
find "$stage_dir" -type d -name __pycache__ -prune -exec rm -rf -- {} +
commit=$(git rev-parse HEAD)
source_epoch=$(git show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$source_epoch}
python3 - "$stage_dir/build-manifest.json" "$commit" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys, tomllib
files = sorted(pathlib.Path(sys.argv[1]).parent.rglob('*'))
h = hashlib.sha256()
root = pathlib.Path(sys.argv[1]).parent
for path in files:
    if path.is_file():
        h.update(str(path.relative_to(root)).encode() + b'\0' +
                 str(path.stat().st_mode).encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
lock = json.loads(pathlib.Path("packaging/build-inputs.lock.json").read_text())
manifest = dict(format_version=2, build_inputs=lock, version=tomllib.load(open('Cargo.toml','rb'))['package']['version'],
    source_date_epoch=int(os.environ["SOURCE_DATE_EPOCH"]),
    release_stage=pathlib.Path('appliance/branding/release-stage').read_text().strip(),
    commit=sys.argv[2], dirty=bool(subprocess.check_output(['git','status','--porcelain'])),
    source_sha256=h.hexdigest(), cargo_lock_sha256=hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest(),
    os='AlmaLinux 10.2', architecture='x86_64', rust='1.92.0', signed=False,
    base_image=pathlib.Path('packaging/container/Containerfile').read_text().split('FROM ',1)[1].splitlines()[0])
pathlib.Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2)+'\n')
PY
cp "$inputs/inventory.json" "$stage_dir/build-inputs.json"
install -d "$stage_dir/output"
podman run --rm --pull=never --network=none --security-opt=no-new-privileges \
    -v "$stage_dir:/source:ro,Z" -v "$stage_dir/output:/output:Z" \
    -v "$inputs:/inputs:ro,z" -v "$target_dir:/build/target:Z" \
    -e SOURCE_DATE_EPOCH -e "RIVERLB_RPM_RELEASE=$release" "$builder"
# Replace the previous candidate set only after successful completion.
rm -rf -- "$output_dir.previous"
if [[ -d "$output_dir" ]]; then mv "$output_dir" "$output_dir.previous"; fi
mv "$stage_dir/output" "$output_dir"
echo "Unsigned appliance RPM candidates: $output_dir/"
