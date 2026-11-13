#!/usr/bin/env python3
"""Read-only verification of a downloaded materials asset; never executes it."""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("asset", type=Path)
p.add_argument("--materials", type=Path, default=Path(__file__).resolve().parents[1] / "materials.json")
a = p.parse_args()
m = json.loads(a.materials.read_text())
entries = [row for row in m["assets"] if row["fileName"] == a.asset.name]
if len(entries) != 1:
    raise SystemExit("Asset filename is not in materials.json")
expected = entries[0]
h = hashlib.sha256()
size = 0
with a.asset.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        h.update(block)
if size != expected["byteCount"] or h.hexdigest() != expected["sha256"]:
    raise SystemExit("Asset size/SHA-256 mismatch")
print(json.dumps({"verified": True, "fileName": a.asset.name, "byteCount": size, "sha256": h.hexdigest(), "sourceExecuted": False}))
