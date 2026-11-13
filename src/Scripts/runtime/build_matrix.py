#!/usr/bin/env python3
"""Build missing pinned profiles one at a time and discard large inputs."""
import argparse
from pathlib import Path
import subprocess
import sys
import shutil

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ("7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.3.7", "8.4.1", "8.5.3")


def fetch(version):
    log = ROOT / "RuntimeKit/Validation" / ("fetch-" + version + ".log")
    with log.open("w") as output:
        subprocess.run([sys.executable, ROOT / "Scripts/runtime/fetch_official.py", "--version", version], stdout=output, stderr=subprocess.STDOUT, check=True)
    print("Verified " + version, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch-only", action="store_true")
    args = parser.parse_args()
    (ROOT / "RuntimeKit/Validation").mkdir(exist_ok=True)
    artifacts = ROOT / "RuntimeKit/Artifacts"
    missing = [v for v in VERSIONS if not ((artifacts / ("RRRuntime" + v.replace(".", "") + ".xcframework")).exists() and (artifacts / ("RenPy" + v.replace(".", "") + ".bundle/runtime-profile.json")).exists())]
    for version in missing:
        # Keep space for the host's Xcode build and simulator installation. A
        # stopped matrix is resumable; completed artifacts are never removed.
        free = shutil.disk_usage(ROOT).free
        if free < 2.0 * 1024 ** 3:
            print("Deferring " + version + ": need 2.0 GiB free before fetching the next SDK; current %.2f GiB" % (free / 1024 ** 3), flush=True)
            raise SystemExit(75)
        fetch(version)
        if not args.fetch_only:
            subprocess.run([sys.executable, ROOT / "Scripts/runtime/build_runtime.py", "--version", version, "--prune-cache"], check=True)


if __name__ == "__main__":
    main()
