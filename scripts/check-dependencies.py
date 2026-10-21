#!/usr/bin/env python3
"""Check every Cargo.lock registry package against OSV; fail closed on API errors."""
import json
from pathlib import Path
import sys
import tomllib
import urllib.request

# This is a maintenance notice, not an ignored exploitable vulnerability.
# Replace rustls-pemfile when a supported migration is implemented and tested.
MAINTENANCE = {"RUSTSEC-2025-0134": "rustls-pemfile is unmaintained; migration remains tracked in the release checklist"}


def main():
    packages = [p for p in tomllib.loads(Path("Cargo.lock").read_text())["package"]
                if p.get("source", "").startswith("registry+")]
    findings = set()
    for offset in range(0, len(packages), 100):
        batch = packages[offset:offset + 100]
        body = {"queries": [{"package": {"ecosystem": "crates.io", "name": p["name"]},
                             "version": p["version"]} for p in batch]}
        request = urllib.request.Request("https://api.osv.dev/v1/querybatch",
            data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            results = json.load(response)["results"]
        if len(results) != len(batch):
            raise RuntimeError("Incomplete OSV response")
        for package, result in zip(batch, results):
            for advisory in result.get("vulns", []):
                identifier = advisory["id"]
                if identifier in MAINTENANCE and package["name"] == "rustls-pemfile":
                    print(f"MAINTENANCE {identifier}: {MAINTENANCE[identifier]}")
                else:
                    findings.add((package["name"], package["version"], identifier))
    for name, version, identifier in sorted(findings):
        print(f"FAIL {name} {version}: https://osv.dev/vulnerability/{identifier}")
    print(f"Checked {len(packages)} locked registry packages; {len(findings)} blocking advisory matches")
    return bool(findings)


if __name__ == "__main__":
    sys.exit(main())
