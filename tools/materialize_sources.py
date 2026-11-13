#!/usr/bin/env python3
"""Restore verified source blobs into a new directory without executing them."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat


def relative_path(value):
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or "\0" in value or value.startswith("/") or PureWindowsPath(value).drive
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("Invalid relative path: " + repr(value))
    return Path(value)


def no_symlinks(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError("Symbolic links are not allowed: " + str(item))


def regular_file(path):
    no_symlinks(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Expected a regular file: " + str(path))


def materialize(source, output, prefixes=()):
    source = Path(source).absolute()
    inventory = source / "inventory.json"
    regular_file(inventory)
    data = json.loads(inventory.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 1 or not isinstance(data.get("entries"), list):
        raise ValueError("Unsupported inventory")
    prefixes = tuple(p.rstrip("/") for p in prefixes)
    for prefix in prefixes:
        relative_path(prefix)
    names = set()
    declared_sizes = {}
    selected = []
    for row in data["entries"]:
        name = row["logicalPath"]
        relative_path(name)
        digest, size, mode = row["sha256"], row["size"], row["mode"]
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or row["object"] != "objects/" + digest
                or type(size) is not int or size < 0
                or type(mode) is not int or not 0 <= mode <= 0o777):
            raise ValueError("Invalid blob metadata: " + name)
        if name in names:
            raise ValueError("Duplicate logical path: " + name)
        if digest in declared_sizes and declared_sizes[digest] != size:
            raise ValueError("Conflicting sizes for one blob: " + name)
        declared_sizes[digest] = size
        names.add(name)
        if not prefixes or name.startswith(prefixes):
            selected.append(row)
    for name in names:
        if any(str(parent) in names for parent in PurePosixPath(name).parents):
            raise ValueError("File/directory collision: " + name)
    if not selected:
        raise ValueError("No files match the requested prefix")

    output = Path(output).expanduser().absolute()
    if ".." in output.parts:
        raise ValueError("Output must not contain '..'")
    no_symlinks(output)
    if output.exists():
        raise ValueError("Output already exists: " + str(output))
    if output == source or source in output.parents:
        raise ValueError("Output must be outside the source materials directory")
    if not output.parent.is_dir():
        raise ValueError("Output parent directory must already exist")

    # Check every selected unique input before creating the output directory.
    verified = set()
    for row in selected:
        if row["sha256"] in verified:
            continue
        blob = source / row["object"]
        regular_file(blob)
        digest = hashlib.sha256()
        size = 0
        with blob.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
        if digest.hexdigest() != row["sha256"] or size != row["size"]:
            raise ValueError("Blob hash/size mismatch: " + row["logicalPath"])
        verified.add(row["sha256"])

    output.mkdir()  # Exclusive: even an existing empty directory is rejected.
    total = 0
    for row in selected:
        target = output / row["logicalPath"]
        target.parent.mkdir(parents=True, exist_ok=True)
        no_symlinks(target)
        regular_file(source / row["object"])
        digest = hashlib.sha256()
        size = 0
        with (source / row["object"]).open("rb") as src, target.open("xb") as dst:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
                dst.write(block)
        if digest.hexdigest() != row["sha256"] or size != row["size"]:
            target.unlink()
            raise ValueError("Blob changed while copying: " + row["logicalPath"])
        os.chmod(target, row["mode"])
        total += size
    return {"files": len(selected), "bytes": total, "output": str(output), "sourceExecuted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="The unpacked Sources directory containing inventory.json and objects")
    parser.add_argument("--output", required=True, help="A new directory whose parent already exists")
    parser.add_argument("--prefix", action="append", default=[], help="Literal logicalPath prefix; repeat to select multiple prefixes")
    args = parser.parse_args()
    try:
        result = materialize(args.source, args.output, args.prefix)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, "materialize: " + str(error) + "\n")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
