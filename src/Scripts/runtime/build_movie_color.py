#!/usr/bin/env python3
"""Compose the pinned853 VP8 color fix after the existing cslots archive step."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

from build_cslots import archive_members, require_original_members
from fetch_legacy_mesh_inputs import download

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "RuntimeKit"
MATERIALS = KIT / "Native/MovieColor"
INPUTS = KIT / ".cache/movie-color-inputs"
CACHE = KIT / ".cache/movie-color-build"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(arguments, **kwargs):
    subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def contract():
    value = json.loads((MATERIALS / "inputs.json").read_text())
    if value["schemaVersion"] != 1 or value["runtimeID"] != "8.5.3":
        raise ValueError("Unknown Movie color source contract")
    for name in ("upstream", "patch", "avconfig", "renpyLicense"):
        item = value[name]
        path = MATERIALS / item["file"]
        if path.is_symlink() or not path.is_file() or sha(path) != item["sha256"]:
            raise ValueError("Movie color material mismatch: " + name)
    return value


def headers(value):
    """Extract only pinned original headers/licenses; execute no configure/build."""
    destination = INPUTS / "headers" / sha(MATERIALS / "inputs.json")
    expected = {}
    for name in ("ffmpeg", "sdl"):
        item = value[name]
        archive = INPUTS / item["file"]
        download(item["url"], archive, item["sha256"])
        with tarfile.open(archive) as source:
            for member in source.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != item["root"] or ".." in parts:
                    raise ValueError("Unexpected pinned header archive path")
                relative = Path(*parts[1:])
                if not member.isfile():
                    continue
                if name == "sdl":
                    if relative.parts[:1] == ("include",) and relative.suffix == ".h":
                        target = Path("SDL2", *relative.parts[1:])
                    elif str(relative) == "LICENSE.txt":
                        target = Path("SDL2/LICENSE.txt")
                    else:
                        continue
                elif relative.suffix == ".h" or str(relative).startswith("COPYING."):
                    target = Path("ffmpeg") / relative
                else:
                    continue
                expected[str(target)] = source.extractfile(member).read()
    expected["ffmpeg/libavutil/avconfig.h"] = (MATERIALS / value["avconfig"]["file"]).read_bytes()
    destination.mkdir(parents=True, exist_ok=True)
    existing = {str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file() or p.is_symlink()}
    if existing - set(expected):
        raise ValueError("Unexpected cached Movie color header")
    for relative, data in expected.items():
        path = destination / relative
        if path.is_symlink() or (path.exists() and path.read_bytes() != data):
            raise ValueError("Modified cached Movie color header: " + relative)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    return destination, {name: hashlib.sha256(data).hexdigest() for name, data in expected.items()}


def source_file(value):
    directory = CACHE / "source" / value["patch"]["resultSHA256"]
    source = directory / "ffmedia.c"
    if not source.exists():
        directory.mkdir(parents=True, exist_ok=True)
        shutil.copy2(MATERIALS / value["upstream"]["file"], source)
        run(["patch", "-F", "0", "-p1", "-i", MATERIALS / value["patch"]["file"]], cwd=directory)
    if source.is_symlink() or sha(source) != value["patch"]["resultSHA256"]:
        raise ValueError("Patched Movie color source mismatch")
    return source


def validate_parent(original, incoming, platform, raw_sha, incoming_sha, parent=None):
    """The sole permitted earlier change is the exact recorded cslots member."""
    require_original_members("8.5.3", platform, original)
    if [m["name"] for m in original] != [m["name"] for m in incoming]:
        raise ValueError("Movie color parent archive member order changed")
    if sum(m["name"] == "ffmedia.o" for m in original) != 1:
        raise ValueError("Expected exactly one ffmedia member")
    if parent is None:
        if original != incoming:
            raise ValueError("Unrecorded parent archive modification")
    elif (parent["runtimeID"] != "8.5.3" or parent["platform"] != platform
          or parent["originalArchiveSHA256"] != raw_sha or parent["archiveSHA256"] != incoming_sha
          or parent["archiveMembersBefore"] != original or parent["archiveMembersAfter"] != incoming
          or [m for m in original if m["name"] != "renpy.cslots.o"] != [m for m in incoming if m["name"] != "renpy.cslots.o"]):
        raise ValueError("Movie color parent does not match the cslots build record")


def validate_result(before, after, object_sha):
    if [m["name"] for m in before] != [m["name"] for m in after]:
        raise ValueError("Movie color archive member order changed")
    if [m for m in before if m["name"] != "ffmedia.o"] != [m for m in after if m["name"] != "ffmedia.o"]:
        raise ValueError("Movie color changed a non-ffmedia member")
    if next(m["sha256"] for m in after if m["name"] == "ffmedia.o") != object_sha:
        raise ValueError("Movie color object was not installed")


def patched_archive(sdk, runtime_id, platform, mode, source_archive, cslots_provenance=None):
    value = contract()
    if runtime_id != value["runtimeID"] or platform not in value["platforms"] or mode != value["platforms"][platform]["mode"]:
        raise ValueError("No Movie color patch for this exact runtime/platform")
    raw = Path(sdk) / "renios/prototype/prebuilt" / mode / "librenpy.a"
    if sha(raw) != value["platforms"][platform]["extractedOfficialArchiveSHA256"]:
        raise ValueError("Unknown official Movie color archive")
    for name, expected in value["platforms"][platform]["ffmpegLibrarySHA256"].items():
        if sha(raw.parent / name) != expected:
            raise ValueError("Movie color FFmpeg library differs from the pinned header ABI: " + name)
    original = CACHE / "original" / platform / "librenpy.a"
    original.parent.mkdir(parents=True, exist_ok=True)
    if raw.read_bytes()[:8] == b"!<arch>\n":
        shutil.copy2(raw, original)
    else:
        run(["xcrun", "lipo", raw, "-thin", "arm64", "-output", original])
    before = archive_members(original)
    incoming = original if Path(source_archive).resolve() == raw.resolve() else Path(source_archive)
    parent = json.loads(Path(cslots_provenance).read_text()) if cslots_provenance else None
    incoming_members = archive_members(incoming)
    validate_parent(before, incoming_members, platform, sha(raw), sha(incoming), parent)
    if next(m["sha256"] for m in before if m["name"] == "ffmedia.o") != value["platforms"][platform]["originalFFMediaMemberSHA256"]:
        raise ValueError("Unknown original ffmedia member")
    include, header_hashes = headers(value)
    source = source_file(value)
    sysroot = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-path"], text=True).strip()
    compiler = subprocess.check_output(["xcrun", "--sdk", platform, "clang", "--version"], text=True)
    sdk_version = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-version"], text=True).strip()
    flags = ["-arch", "arm64", "-isysroot", sysroot,
             "-mios-simulator-version-min=17.0" if platform == "iphonesimulator" else "-miphoneos-version-min=17.0",
             "-std=gnu11", "-O2", "-fPIC", "-fvisibility=hidden", "-Wno-deprecated-declarations",
             "-I", str(include), "-I", str(include / "ffmpeg")]
    binding = {"builderSHA256": sha(Path(__file__)), "contractSHA256": sha(MATERIALS / "inputs.json"),
               "sourceSHA256": sha(source), "inputArchiveSHA256": sha(incoming),
               "parentCslotsProvenanceSHA256": sha(cslots_provenance) if cslots_provenance else None,
               "platform": platform, "flags": flags, "compilerVersion": compiler, "sdkVersion": sdk_version,
               "sdkSettingsSHA256": sha(Path(sysroot) / "SDKSettings.json"),
               "headerSHA256": header_hashes}
    key = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
    work = CACHE / platform / key
    archive, obj, provenance = work / "librenpy.a", work / "ffmedia.o", work / "movie-color-provenance.json"
    if provenance.exists():
        record = json.loads(provenance.read_text())
        if record["binding"] != binding or sha(archive) != record["archiveSHA256"] or sha(obj) != record["objectSHA256"]:
            raise ValueError("Modified cached Movie color build")
        validate_result(incoming_members, archive_members(archive), sha(obj))
        return archive, provenance
    work.mkdir(parents=True, exist_ok=True)
    original_obj = work / "ffmedia-original.o"
    with original_obj.open("wb") as output:
        run(["xcrun", "ar", "-p", incoming, "ffmedia.o"], stdout=output)
    command = ["xcrun", "clang", *flags, "-MMD", "-MF", work / "ffmedia.d", "-c", source, "-o", obj]
    run(command)
    def exports(path):
        return sorted(line.split()[-1] for line in subprocess.check_output(["xcrun", "nm", "-gU", path], text=True).splitlines() if line.strip())
    if exports(original_obj) != exports(obj):
        raise ValueError("Movie color object public symbols changed")
    shutil.copy2(incoming, archive)
    run(["xcrun", "ar", "-r", archive, obj])
    run(["xcrun", "ranlib", archive])
    after = archive_members(archive)
    validate_result(incoming_members, after, sha(obj))
    record = {"schemaVersion": 1, "runtimeID": runtime_id, "platform": platform, "binding": binding,
              "sourceMaterials": value, "inputArchiveSHA256": sha(incoming), "originalSDKArchiveSHA256": sha(raw),
              "parentCslotsProvenanceSHA256": sha(cslots_provenance) if cslots_provenance else None,
              "objectSHA256": sha(obj), "archiveSHA256": sha(archive), "membersBefore": incoming_members, "membersAfter": after,
              "compileArguments": list(map(str, command)), "unchangedNonFFMediaMembers": True,
              "sourceBoundary": "New version-matched official-source replacement; not a byte-for-byte reconstruction of the original SDK ffmedia object."}
    provenance.write_text(json.dumps(record, indent=2) + "\n")
    return archive, provenance
