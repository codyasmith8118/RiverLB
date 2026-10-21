#!/usr/bin/env bash
# Two independent containers, empty Cargo homes and empty target directories.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
output=${RIVERLB_REPRO_OUTPUT_DIR:-$project_dir/dist/reproducibility}
[[ ! -e "$output" ]] || { echo "Preserve or remove existing evidence: $output" >&2; exit 1; }
mkdir -p "$output"
output=$(realpath "$output")
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
for attempt in first second; do
    RIVERLB_RPM_OUTPUT_DIR="$output/$attempt" scripts/build-rpm.sh 2>&1 | tee "$output/$attempt.log"
done
python3 scripts/compare-builds.py "$output/first" "$output/second" --output "$output/comparison.json"
