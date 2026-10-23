# Retained third-party metadata

These files supplement the hash-pinned dependency snapshot; normal builds never
resolve dependencies or fetch replacement metadata from upstream.

| File | Origin and check |
|---|---|
| `cargo/index.json`, `cargo/files/` | Missing crate notices from the exact recorded upstream VCS commits; crate archive and captured file hashes retained |
| `python-sources.lock.json` | Verified PyPI source distribution URLs, sizes and hashes for locked wheels and embedded distributions |
| `runtime-packages.lock.json` | Exact vendor-signed RPM metadata for base media, installer runtime and retained HA dependencies; source RPM URLs and notices |
| `runtime-notices.tar.gz` | Original RPM license file bytes, bound by the catalog and individual file hashes |

Capture scripts in `scripts/` are maintainer tools. Review any recapture with its
input/base-media change. Preserve original notice bytes and their own licenses.
No private appliance data belongs here. See
[software inventories and provenance](../../docs/software-supply-chain.md) for
coverage, source availability, capture limitations and verification commands.
