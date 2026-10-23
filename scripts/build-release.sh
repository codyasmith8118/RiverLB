#!/usr/bin/env bash
# Build an unsigned application candidate with reconstructible SBOM and notices.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
platform=$(rustc -vV | sed -n 's/^host: //p')
[[ "$platform" == x86_64-unknown-linux-gnu ]] || { echo 'The retained dependency inventory targets Linux x86_64 GNU.' >&2; exit 1; }
inputs=${RIVERLB_BUILD_INPUTS_DIR:-}
if [[ -z "$inputs" ]]; then inputs=$(python3 scripts/build-inputs.py prepare); fi
inputs=$(realpath -- "$inputs")
stage_dir=$(mktemp -d)
candidate_dir=""
trap 'rm -rf -- "$stage_dir"; if [[ -n "$candidate_dir" ]]; then rm -rf -- "$candidate_dir"; fi' EXIT
export CARGO_HOME="$stage_dir/cargo-home"
mkdir -p "$CARGO_HOME"
python3 - "$CARGO_HOME/config.toml" "$inputs/cargo-vendor" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text('[source.crates-io]\nreplace-with = "retained"\n[source.retained]\ndirectory = '+json.dumps(sys.argv[2])+'\n[net]\noffline = true\n')
PY
cargo build --release --offline --locked
cargo metadata --offline --locked --format-version 1 --filter-platform "$platform" > "$stage_dir/cargo-metadata.json"
rustc -vV > "$stage_dir/compiler.txt"
python3 - "$stage_dir/build-manifest.json" "$stage_dir/compiler.txt" <<'PY'
import hashlib,json,os,subprocess,sys,tomllib
from pathlib import Path
version=tomllib.loads(Path('Cargo.toml').read_text())['package']['version']
compiler=Path(sys.argv[2]).read_text()
manifest=dict(format_version=2,version=version,commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 dirty=bool(subprocess.check_output(['git','status','--porcelain'])),
 source_date_epoch=int(os.environ.get('SOURCE_DATE_EPOCH') or subprocess.check_output(['git','show','-s','--format=%ct','HEAD'],text=True)),
 cargo_lock_sha256=hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest(),
 build_inputs=json.loads(Path('packaging/build-inputs.lock.json').read_text()),rust=compiler.split()[1],
 builder_image='github-hosted:ubuntu-24.04@'+os.environ.get('ImageVersion','unknown') if os.environ.get('GITHUB_ACTIONS')=='true' else 'local-linux-compiler')
Path(sys.argv[1]).write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
PY
binary="${CARGO_TARGET_DIR:-target}/release/riverlb"
python3 scripts/software-inventory.py source --inputs "$inputs" --manifest "$stage_dir/build-manifest.json" \
    --binary "$binary" --metadata "$stage_dir/cargo-metadata.json" --output "$stage_dir/software"
python3 scripts/software-inventory.py verify-source --inputs "$inputs" --manifest "$stage_dir/build-manifest.json" \
    --binary "$binary" --metadata "$stage_dir/cargo-metadata.json" --output "$stage_dir/software"
install -d dist
candidate_dir=$(mktemp -d "$project_dir/dist/.candidate.XXXXXX")
python3 scripts/package-application.py --root "$project_dir" --binary "$binary" \
    --software "$stage_dir/software" --manifest "$stage_dir/build-manifest.json" \
    --compiler "$stage_dir/compiler.txt" --output "$candidate_dir"
for file in "$candidate_dir"/*; do mv -- "$file" dist/; done
echo 'Unsigned application candidate with SBOM, sources and notices: dist/riverlb-*.tar.gz'
