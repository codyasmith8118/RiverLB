# Offline CycloneDX validation schemas

`bom-1.6.schema.json` and `spdx.schema.json` are the original CycloneDX 1.6
schemas from the immutable upstream commit identified by `SOURCES.json`.
That file records each original URL and SHA-256. `LICENSE` is the original
Apache-2.0 license from the same source. Validation checks those schema hashes
and resolves references only through the local registry.
