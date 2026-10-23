#!/usr/bin/env python3
"""Prepare SLSA v1 predicate/subjects only after full qualification and cleanup."""
import argparse
from pathlib import Path
from software_provenance import prepare

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
p.add_argument('--evidence', type=Path, required=True)
p.add_argument('--report', type=Path, required=True)
p.add_argument('--source', required=True)
p.add_argument('--firmware', choices=['bios', 'uefi'], required=True)
a = p.parse_args()
prepare(a.root, a.evidence, a.report, a.source, a.firmware)
print('Bound qualified artifacts, complete inventory, compiler/builder and tests for signing')
