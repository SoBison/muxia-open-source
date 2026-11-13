#!/usr/bin/env python3
"""Fetch and verify the pinned official Ren'Py SDK and iOS support archives."""

import concurrent.futures
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from functools import partial
import stat
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
NIGHTLY_INPUTS = ROOT / "RuntimeKit/Inputs/official-nightlies.json"
NIGHTLY_VERSIONS = {"7.8.8", "8.5.4"}
STABLE_853_SHA256 = {
    "renpy-8.5.3-sdk.zip": "ff57648f9c04f27e381c48af6d8e3ee3cdec296bed4d3831f47f09b0a71b505e",
    "renpy-8.5.3-renios.zip": "c4fae153e8276ed0faed5e84ea3e0b7c4bf337f0e3208e9130c6a41748a83b2b",
}


def source_configuration(version):
    if not re.fullmatch(r"[78]\.\d+\.\d+", version):
        raise ValueError("Expected a pinned logical Ren'Py version")
    if version in NIGHTLY_VERSIONS:
        raw = NIGHTLY_INPUTS.read_bytes()
        manifest = json.loads(raw)
        if manifest.get("schemaVersion") != 1:
            raise ValueError("Unknown official nightly input schema")
        source = manifest["versions"][version]
        build_id, base_url = source["buildID"], source["baseURL"]
        if not re.fullmatch(re.escape(version) + r"\.\d{8}\+nightly", build_id):
            raise ValueError("Nightly build ID does not match the logical version")
        if base_url not in (f"https://www.renpy.org/dl/{build_id}/", f"https://nightly.renpy.org/{build_id}/"):
            raise ValueError("Nightly input must use a fixed official build directory")
        names = [f"renpy-{build_id}-{kind}.zip" for kind in ("sdk", "renios")]
        if set(source["archives"]) != set(names):
            raise ValueError("Expected the exact nightly SDK and renios ZIP names")
        for entry in source["archives"].values():
            if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or type(entry["byteCount"]) is not int or entry["byteCount"] < 1:
                raise ValueError("Nightly ZIP requires a frozen SHA-256 and byte count")
        commits = source["sourceCommits"]
        if "renpy" not in commits or any(not re.fullmatch(r"[0-9a-f]{40}", value) for value in commits.values()):
            raise ValueError("Nightly input requires complete official source commits")
        return dict(source, sha256={name: source["archives"][name]["sha256"] for name in names},
                    inputManifestSHA256=hashlib.sha256(raw).hexdigest())
    base_url = f"https://www.renpy.org/dl/{version}/"
    if version == "8.5.3":
        archives = dict(STABLE_853_SHA256)
    else:
        checksums = urllib.request.urlopen(base_url + "checksums.txt", timeout=30).read().decode("utf-8")
        archives = {f"renpy-{version}-{kind}.zip": re.search(r"^([0-9a-f]{64})\s+" + re.escape(f"renpy-{version}-{kind}.zip") + r"$", checksums, re.M).group(1)
                    for kind in ("sdk", "renios")}
    return {"buildID": version, "baseURL": base_url, "sha256": archives}


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fetch(item, *, cache, source):
    name, expected = item
    target = cache / name
    expected_size = source.get("archives", {}).get(name, {}).get("byteCount")
    verified = target.exists() and digest(target) == expected
    if verified and expected_size is not None and target.stat().st_size != expected_size:
        raise RuntimeError("Pinned ZIP size disagrees with its verified SHA-256: " + name)
    if not verified:
        target.unlink(missing_ok=True)
        partial = target.with_suffix(target.suffix + ".part")
        url = source["baseURL"] + name
        print(f"Downloading {name}", flush=True)
        # Parallel, resumable HTTP ranges avoid restarting large official SDKs
        # after a transient connection failure. The final SHA-256 is mandatory.
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60) as response:
            total = int(response.headers["Content-Length"])
        if expected_size is not None and total != expected_size:
            raise RuntimeError("Pinned official nightly ZIP length changed: " + name)
        state_file = partial.with_suffix(".ranges.json")
        if state_file.exists():
            state = json.loads(state_file.read_text())
            if state["total"] != total:
                raise RuntimeError("Official archive length changed during download")
        else:
            prefix = partial.stat().st_size if partial.exists() else 0
            if prefix > total:
                partial.unlink()
                prefix = 0
            span = max(1, (total - prefix + 3) // 4)
            state = {"total": total, "prefix": prefix, "ranges": [[start, min(start + span, total) - 1] for start in range(prefix, total, span)]}
            state_file.write_text(json.dumps(state))

        def fetch_range(index_and_bounds):
            index, (start, end) = index_and_bounds
            chunk = partial.with_suffix(".range" + str(index))
            size = end - start + 1
            for attempt in range(3):
                done = chunk.stat().st_size if chunk.exists() else 0
                if done == size:
                    return chunk
                if done > size:
                    chunk.unlink()
                    done = 0
                request = urllib.request.Request(url, headers={"Range": "bytes=%d-%d" % (start + done, end)})
                try:
                    with urllib.request.urlopen(request, timeout=60) as source, chunk.open("ab") as output:
                        expected_range = "bytes %d-%d/%d" % (start + done, end, total)
                        if source.status != 206 or source.headers.get("Content-Range") != expected_range:
                            raise RuntimeError("Server did not honor the requested official archive range")
                        shutil.copyfileobj(source, output, 1024 * 1024)
                except (OSError, TimeoutError):
                    if attempt == 2:
                        raise
            if chunk.stat().st_size != size:
                raise RuntimeError("Incomplete official archive range")
            return chunk

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            chunks = list(pool.map(fetch_range, enumerate(state["ranges"])))
        with partial.open("ab") as output:
            output.truncate(state["prefix"])
            output.seek(state["prefix"])
            for chunk in chunks:
                with chunk.open("rb") as source:
                    shutil.copyfileobj(source, output, 1024 * 1024)
        if digest(partial) != expected:
            partial.unlink()
            for chunk in chunks:
                chunk.unlink(missing_ok=True)
            state_file.unlink(missing_ok=True)
            raise RuntimeError(f"Official SHA-256 mismatch: {name}")
        partial.replace(target)
        for chunk in chunks:
            chunk.unlink()
        state_file.unlink()
    print(f"Verified {name}", flush=True)
    return target


def extract(archive, destination, selected):
    marker = destination / f".{archive.name}.extracted"
    if marker.exists():
        return
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            if not selected(item.filename):
                continue
            target = (destination / item.filename).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise RuntimeError(f"Unsafe path in official archive: {item.filename}")
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                link = source.read(item).decode("utf-8")
                if not (target.parent / link).resolve().is_relative_to(destination.resolve()):
                    raise RuntimeError(f"Unsafe link in official archive: {item.filename}")
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    target.symlink_to(link)
            else:
                source.extract(item, destination)
                if target.is_file() and mode & 0o111:
                    target.chmod(target.stat().st_mode | (mode & 0o777))
                if target.suffix == ".a":
                    architectures = subprocess.check_output(["xcrun", "lipo", "-archs", target], text=True).split()
                    if "arm64" not in architectures:
                        raise RuntimeError("The official archive lacks the required arm64 slice: " + str(target))
                    if len(architectures) > 1:
                        thin = target.with_suffix(".arm64.a")
                        subprocess.run(["xcrun", "lipo", target, "-thin", "arm64", "-output", thin], check=True)
                        thin.replace(target)
    marker.write_text(digest(archive) + "\n")


def canonical_nightly_license(version, sdk, archive, expected_sha256):
    if version not in NIGHTLY_VERSIONS:
        return None
    if digest(archive) != expected_sha256:
        raise RuntimeError("Nightly license archive is not the pinned official SDK ZIP")
    prefix = sdk.name + "/"
    with zipfile.ZipFile(archive) as source:
        if prefix + "LICENSE.txt" in source.namelist():
            return None
        member = prefix + "doc/license.html"
        data = source.read(member)  # ZipFile verifies this member's CRC before returning.
    target = sdk / "LICENSE.txt"
    if target.is_symlink() or (target.exists() and target.read_bytes() != data):
        raise RuntimeError("Existing canonical nightly license differs from the official archive")
    if not target.exists():
        target.write_bytes(data)
    return {"path": "LICENSE.txt", "licenseArchiveMember": member, "sha256": hashlib.sha256(data).hexdigest(),
            "contentType": "text/html", "normalization": "byte-preserving archive member alias"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="8.5.3")
    version = parser.parse_args(argv).version
    official = source_configuration(version)
    build_id, archives = official["buildID"], official["sha256"]
    CACHE = ROOT / "RuntimeKit" / ".cache" / "official" / version
    CACHE.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        downloaded = list(pool.map(partial(fetch, cache=CACHE, source=official), archives.items()))
    # The full official downloads are hash-verified above. Extract only reader
    # build inputs, omitting other desktop platforms, docs, examples and tools.
    platform = ROOT / "RuntimeKit/Artifacts/RRPlatform.xcframework"
    platform_source = ROOT / "RuntimeKit/Native/RRPlatform.m"
    needs_platform = not platform.exists() or platform.stat().st_mtime < platform_source.stat().st_mtime
    with zipfile.ZipFile(downloaded[1]) as ios:
        pyvers = {re.search(r"libpython([0-9.]+)\.a$", name).group(1) for name in ios.namelist() if "/prebuilt/release/libpython" in name and name.endswith(".a")}
        if len(pyvers) != 1:
            raise RuntimeError("Expected one official Python ABI: " + repr(pyvers))
        pyver = pyvers.pop()
        project_name = next(name for name in ios.namelist() if name.endswith("prototype.xcodeproj/project.pbxproj"))
        project = ios.read(project_name).decode("utf-8")
        native_libraries = {"lib" + name + ".a" for name in re.findall(r'"-l([A-Za-z0-9_+.]+)"', project)} | {"libsharpyuv.a", "libbrotlicommon.a"}
        if not needs_platform or version != "8.5.3":
            native_libraries -= {"libSDL2.a", "libSDL2_image.a"}

    sdk_prefix = "renpy-" + build_id + "-sdk/"
    def sdk_selected(name):
        relative = name.removeprefix(sdk_prefix)
        return relative in ("renpy.py", "LICENSE.txt") or relative.startswith(("renpy/", "lib/python" + pyver + "/"))

    def ios_selected(name):
        if "/prebuilt/" in name:
            return Path(name).name in native_libraries
        if "/Frameworks/" in name:
            return needs_platform and version == "8.5.3" and "/MetalANGLE.xcframework/" in name
        return name.endswith("prototype.xcodeproj/project.pbxproj") or ("/prototype/" in name and Path(name).suffix in (".m", ".h", ".c"))

    selected_sets = [sdk_selected, ios_selected]
    uncompressed = 0
    for archive, selected in zip(downloaded, selected_sets):
        with zipfile.ZipFile(archive) as source:
            uncompressed += sum(item.file_size for item in source.infolist() if selected(item.filename))
    free = shutil.disk_usage(CACHE).free
    if free < uncompressed + 1.5 * 1024 ** 3:
        print("Verified archives retained; deferring extraction to preserve 1.5 GiB for the host. Need %.2f GiB, available %.2f GiB." % ((uncompressed + 1.5 * 1024 ** 3) / 1024 ** 3, free / 1024 ** 3), flush=True)
        raise SystemExit(75)
    sdk_parent = CACHE / "extracted"
    sdk = sdk_parent / f"renpy-{build_id}-sdk"
    extract(downloaded[0], sdk_parent, sdk_selected)
    extract(downloaded[1], sdk, ios_selected)
    canonical_license = canonical_nightly_license(version, sdk, downloaded[0], archives[downloaded[0].name])
    result = {"version": version, "sdk": str(sdk), "renios": str(sdk / "renios"), "sha256": archives, "extraction": "reader-build-inputs", "staticArchiveArchitectures": ["arm64"]}
    if canonical_license is not None:
        result["canonicalLicense"] = canonical_license
    if version in NIGHTLY_VERSIONS:
        result.update(buildID=build_id, channel="nightly", archiveURLs={name: official["baseURL"] + name for name in archives},
                      byteCounts={name: entry["byteCount"] for name, entry in official["archives"].items()},
                      sourceCommits=official["sourceCommits"], sourceIndexURL=official["sourceIndexURL"],
                      inputManifestSHA256=official["inputManifestSHA256"])
    (CACHE / "paths.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
