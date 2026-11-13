#!/usr/bin/env python3
"""Build the two pinned non-GC cslots deallocation fixes without changing SDKs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from fetch_legacy_mesh_inputs import CACHE as INPUT_CACHE, download, python_headers

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "RuntimeKit"
CACHE = KIT / ".cache/cslots-build"
PATCH = KIT / "Native/Cslots/cslots-deallocation.patch"
PATCH_SHA256 = "496fd6a4cd0ba62ff43a0daf022524b588dbcc49b2a22836f89b878844418868"
PROFILES = {
    "8.4.1": ("8.4.1.25072401", "ba401f82f1de176c1a34e86afe5f61eb87f151a4c0b762519b3a9374f6e9b9ba", "fc449c876989ce2afb5ddc618afa33e50b60d8078ba1ed84cd52159f171d1fe1"),
    "8.5.3": ("8.5.3.26051504", "ddde2eb88632a8212d700e509a75a335091557f8ec7c78703e5632c4bfeaae0b", "2cecfb8af69fcc218579d6bc3ba093ccdeea30adc3619d518462d0748872fb37"),
}
ARCHIVE_MEMBERS_SHA256 = {
    ("8.4.1", "iphoneos"): "76d4e218ab4c56b2f5528d9050339029588211ba5a825ea5e745f86354713575",
    ("8.4.1", "iphonesimulator"): "2e78611257d23d06e7243c8009e5006e80cc278d69b0619026032d70d8672339",
    ("8.5.3", "iphoneos"): "a4a2ec16315865201c3a3185c82e17ba77e243deaa7ad27f1ee2e9702c30fe8a",
    ("8.5.3", "iphonesimulator"): "27cd456bfe3a836fb751ac4097beacd0f324e25c71ec5c7df87568be3a3c1137",
}
PYTHON_SHA256 = "5978435c479a376648cb02854df3b892ace9ed7d32b1fead652712bee9d03a45"
CYTHON_SHA256 = "7146dd2af8682b4ca61331851e6aebce9fe5158e75300343f80c07ca80b1faff"
CYTHON_URL = "https://files.pythonhosted.org/packages/84/4d/b720d6000f4ca77f030bd70f12550820f0766b568e43f11af7f7ad9061aa/cython-3.0.11.tar.gz"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(arguments, **kwargs):
    print(" ".join(map(str, arguments)), flush=True)
    subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def archive_members(path):
    """Read BSD ar payloads, excluding the archive's generated symbol index."""
    data = Path(path).read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError("Expected a thin arm64 BSD archive")
    offset, result = 8, []
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("Invalid archive member header")
        size = int(header[48:58])
        payload = data[offset + 60:offset + 60 + size]
        if len(payload) != size:
            raise ValueError("Truncated archive member")
        name = header[:16].decode("ascii").strip()
        if name.startswith("#1/"):
            name_size = int(name[3:])
            name, payload = payload[:name_size].rstrip(b"\0").decode("utf-8"), payload[name_size:]
        if name not in ("__.SYMDEF", "__.SYMDEF SORTED"):
            result.append({"name": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        offset += 60 + size + (size & 1)
    if offset != len(data):
        raise ValueError("Invalid archive alignment")
    return result


def require_original_members(runtime_id, platform, members):
    digest = hashlib.sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != ARCHIVE_MEMBERS_SHA256[(runtime_id, platform)]:
        raise ValueError("Original arm64 archive members differ from the exact official profile")
    return digest


def _inputs():
    INPUT_CACHE.mkdir(parents=True, exist_ok=True)
    python_archive = INPUT_CACHE / "Python-3.12.8.tgz"
    download("https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz", python_archive, PYTHON_SHA256)
    python_headers("3.12.8")
    python = INPUT_CACHE / "Python-3.12.8"
    cython_archive = INPUT_CACHE / "cython-3.0.11.tar.gz"
    download(CYTHON_URL, cython_archive, CYTHON_SHA256)
    cython = INPUT_CACHE / "cython-3.0.11"
    with tarfile.open(cython_archive) as archive:
        files = [member for member in archive.getmembers() if member.isfile()]
        if any(Path(member.name).parts[0] != cython.name for member in files):
            raise ValueError("Unexpected Cython source root")
        if not cython.exists():
            archive.extractall(INPUT_CACHE, filter="data")
        # Reject changed cached compiler sources before executing them.
        expected = {str(Path(member.name).relative_to(cython.name)) for member in files}
        if any(str(path.relative_to(cython)) not in expected for path in cython.rglob("*") if path.is_file()):
            raise ValueError("Unexpected cached Cython file (including bytecode/native caches)")
        for member in files:
            if sha(INPUT_CACHE / member.name) != hashlib.sha256(archive.extractfile(member).read()).hexdigest():
                raise ValueError("Cached Cython source does not match pinned archive")
    python_record = json.loads((python / "source-record.json").read_text())
    if sha(python_archive) != PYTHON_SHA256 or python_record["sha256"] != PYTHON_SHA256:
        raise ValueError("Unexpected CPython header source")
    return python, cython, python_record


def static_names(ccode):
    # Same complete-name fixups as the exact tags' scripts/setuplib.py.
    ccode = ccode.replace("PyInit_cslots", "PyInit_renpy_cslots")
    ccode, count = re.subn(r'(PyModuleDef_HEAD_INIT,\n\s*)"cslots",', r'\1"renpy.cslots",', ccode)
    if count != 1:
        raise ValueError("Inspect generated cslots static-module definition")
    return ccode


def patched_archive(sdk, runtime_id, platform, mode):
    if runtime_id not in PROFILES:
        raise ValueError("No cslots patch for this exact runtime")
    if platform not in ("iphoneos", "iphonesimulator") or mode != ("debug" if platform == "iphonesimulator" else "release"):
        raise ValueError("Unexpected cslots platform/mode")
    if sha(PATCH) != PATCH_SHA256:
        raise ValueError("Unreviewed cslots patch")
    tag, original_sha, patched_sha = PROFILES[runtime_id]
    original_archive = Path(sdk) / "renios/prototype/prebuilt" / mode / "librenpy.a"
    if not original_archive.is_file():
        raise ValueError("Exact original librenpy.a is missing; restore this profile's official native inputs")
    python, cython, python_record = _inputs()
    source_root = CACHE / runtime_id / "source"
    original = CACHE / runtime_id / "upstream-cslots.pyx"
    original.parent.mkdir(parents=True, exist_ok=True)
    source_record = download("https://raw.githubusercontent.com/renpy/renpy/" + tag + "/renpy/cslots.pyx", original, original_sha)
    source = source_root / "renpy/cslots.pyx"
    if not source.exists():
        source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, source)
        run(["patch", "-F", "0", "-p1", "-i", PATCH], cwd=source_root)
    if sha(source) != patched_sha:
        raise ValueError("Patched cslots source does not match the reviewed result")
    work = CACHE / runtime_id / platform
    work.mkdir(parents=True, exist_ok=True)
    generated = work / "renpy.cslots.c"
    env = dict(os.environ, PYTHONPATH=str(cython), PYTHONDONTWRITEBYTECODE="1")
    run(["/usr/bin/python3", "-B", "-m", "cython", "--module-name", "renpy.cslots", "-o", generated, source], env=env)
    generated.write_text(static_names(generated.read_text()))
    archive = work / "librenpy.a"
    probe = subprocess.run(["ar", "-t", original_archive], capture_output=True)
    if probe.returncode == 0:
        shutil.copy2(original_archive, archive)
    else:
        run(["lipo", original_archive, "-thin", "arm64", "-output", archive])
    before = archive_members(archive)
    member_digest = require_original_members(runtime_id, platform, before)
    if sum(member["name"] == "renpy.cslots.o" for member in before) != 1:
        raise ValueError("Expected exactly one original cslots object")
    sysroot = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-path"], text=True).strip()
    deployment = "-mios-simulator-version-min=17.0" if platform == "iphonesimulator" else "-miphoneos-version-min=17.0"
    obj = work / "renpy.cslots.o"
    command = ["xcrun", "--sdk", platform, "clang", "-arch", "arm64", "-isysroot", sysroot, deployment, "-O2", "-fPIC", "-fvisibility=hidden", "-Wno-deprecated-declarations", "-I", python, "-I", python / "Include", "-c", generated, "-o", obj]
    run(command)
    run(["ar", "-r", archive, obj])
    run(["ranlib", archive])
    after = archive_members(archive)
    if [item for item in before if item["name"] != "renpy.cslots.o"] != [item for item in after if item["name"] != "renpy.cslots.o"]:
        raise ValueError("A non-cslots archive member changed")
    record = {"runtimeID": runtime_id, "platform": platform, "upstream": source_record, "patchSHA256": PATCH_SHA256, "patchedSourceSHA256": sha(source), "generatedCSHA256": sha(generated), "objectSHA256": sha(obj), "archiveSHA256": sha(archive), "originalArchiveSHA256": sha(original_archive), "originalArm64MembersSHA256": member_digest, "otherArchiveMembersEqual": True, "archiveMembersBefore": before, "archiveMembersAfter": after, "compileArguments": list(map(str, command)), "compilerVersion": subprocess.check_output(["xcrun", "--sdk", platform, "clang", "--version"], text=True), "cythonVersion": "3.0.11", "cythonSourceSHA256": CYTHON_SHA256, "pythonHeaders": python_record, "pythonIncludeSHA256": {str(path.relative_to(python / "Include")): sha(path) for path in sorted((python / "Include").rglob("*.h"))}, "layoutAndGCFlagsUnchanged": True, "sourceLicense": "MIT retained in upstream source", "builderSHA256": sha(Path(__file__))}
    provenance = work / "cslots-deallocation-provenance.json"
    provenance.write_text(json.dumps(record, indent=2) + "\n")
    return archive, provenance
