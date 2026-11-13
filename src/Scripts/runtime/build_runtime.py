#!/usr/bin/env python3
"""Build pinned official ABI images plus one shared SDL/UIKit platform image."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
from privacy_manifests import write_framework_manifest, patch_existing
from build_sdl_gate import compile_gate
from audit_renderer_candidate import native_identity

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "RuntimeKit"
ARTIFACTS = KIT / "Artifacts"
CACHE = KIT / ".cache"
VERSIONS = ("7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.3.7", "8.4.1", "8.5.3")
PLATFORMS = (("iphoneos", "release"), ("iphonesimulator", "debug"))
SYSTEM_FRAMEWORKS = ("UIKit", "Foundation", "CoreGraphics", "AudioToolbox", "QuartzCore", "ImageIO", "CoreMotion", "GameController", "CoreServices", "StoreKit", "AVFoundation", "CoreBluetooth", "Metal")


def run(args):
    print(" ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), check=True)


def fetch(version, native=False):
    marker = CACHE / "official" / version / "paths.json"
    sdk = Path(json.loads(marker.read_text())["sdk"]) if marker.exists() else None
    if sdk is None or (native and not (sdk / "renios/prototype/prebuilt/release").exists()):
        run([sys.executable, ROOT / "Scripts/runtime/fetch_official.py", "--version", version])
    return Path(json.loads(marker.read_text())["sdk"])


def python_version(sdk):
    choices = [p.name.removeprefix("libpython").removesuffix(".a") for p in (sdk / "renios/prototype/prebuilt/release").glob("libpython*.a")]
    if len(choices) != 1:
        version = sdk.name.removeprefix("renpy-").removesuffix("-sdk")
        profile = ARTIFACTS / ("RenPy" + version.replace(".", "") + ".bundle/runtime-profile.json")
        if not choices and profile.exists():
            return json.loads(profile.read_text())["pythonVersion"]
        raise RuntimeError("Expected exactly one CPython ABI: " + repr(choices))
    return choices[0]


def libraries(sdk, pyver):
    project = (sdk / "renios/prototype/prototype.xcodeproj/project.pbxproj").read_text()
    groups = re.findall(r"OTHER_LDFLAGS = \((.*?)\);", project, re.S)
    selected = next((g for g in groups if "-lpython" + pyver in g), None)
    if selected is None:
        raise RuntimeError("No official link group matches " + pyver)
    result = re.findall(r'"(-l[^\"]+)"', selected)
    available = sdk / "renios/prototype/prebuilt/release"
    for name in ("sharpyuv", "brotlicommon"):
        if (available / ("lib" + name + ".a")).exists() and "-l" + name not in result:
            result.append("-l" + name)
    if "-lstdc++" not in result:
        result.append("-lstdc++")
    return result


def patch_embedded_view_size(text):
    marker = "    if size[0] >= 256 and size[1] >= 256:\n"
    if text.count(marker) != 1:
        raise RuntimeError("Inspect upstream display/core.py get_size minimum guard")
    patch = '''    # An embedded iOS view can legitimately be smaller than the desktop window
    # minimum. Inflating physical height changes GL viewport padding and clips
    # pixels against the actual smaller drawable. Preserve the zero-size guard.
    host = sys.modules.get("rr_host")
    if renpy.ios and host is not None and host.has_embedded_session() and size[0] > 0 and size[1] > 0:
        return size

'''
    if patch in text:
        return text
    return text.replace(marker, patch + marker)


def native_packaging_records(version):
    records = {}
    for name in ("RRRuntime" + version.replace(".", ""), "RRPlatform"):
        package = ARTIFACTS / (name + ".xcframework")
        if not (package / "Info.plist").exists():
            continue
        libraries = plistlib.loads((package / "Info.plist").read_bytes())["AvailableLibraries"]
        slices = {}
        for library in libraries:
            framework = package / library["LibraryIdentifier"] / library["LibraryPath"]
            binary = framework / name
            if not binary.exists():
                continue
            slices[library["LibraryIdentifier"]] = {
                "image": native_identity(binary),
                "minimumOS": plistlib.loads((framework / "Info.plist").read_bytes()).get("MinimumOSVersion"),
                "embeddedBuildRecordSHA256": {record.name: hashlib.sha256(record.read_bytes()).hexdigest()
                    for record in framework.glob("*.json") if record.name in ("input-gate-provenance.json", "mesh-backport-provenance.json", "retained-mesh-backport-provenance.json", "bytecode-policy-provenance.json", "retained-bytecode-policy-provenance.json", "cslots-deallocation-provenance.json", "movie-color-provenance.json")},
            }
        records[name] = slices
    return attach_platform_supplement(records)


def attach_platform_supplement(records):
    """Bind the retained SDL supplement only to the exact native slices it describes."""
    names = ("sdl-virtual-joystick-provenance.json", "sdl-virtual-joystick-owner.patch")
    paths = [KIT / "Notices" / name for name in names]
    if not any(path.exists() or path.is_symlink() for path in paths):
        return records
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise RuntimeError("SDL platform supplement is incomplete or linked")
    payloads = [path.read_bytes() for path in paths]
    delta = json.loads(payloads[0])
    expected_slices = {"ios-arm64", "ios-arm64-simulator"}
    if (delta.get("schemaVersion") != 1 or delta.get("kind") != "sdlVirtualJoystickOwnerRepair"
            or delta.get("patch") != {"fileName": names[1], "byteCount": len(payloads[1]),
                                      "sha256": hashlib.sha256(payloads[1]).hexdigest()}
            or set(delta.get("slices", {})) != expected_slices
            or set(records.get("RRPlatform", {})) != expected_slices):
        raise RuntimeError("Invalid SDL platform supplement or missing native slices")
    resources = {name: {"sourcePath": "RuntimeKit/Notices/" + name,
                        "packagedPath": "LegalResources/" + name,
                        "sha256": hashlib.sha256(payload).hexdigest(), "byteCount": len(payload)}
                 for name, payload in zip(names, payloads)}
    for identifier in sorted(expected_slices):
        framework = ARTIFACTS / "RRPlatform.xcframework" / identifier / "RRPlatform.framework"
        binary = framework / "RRPlatform"
        embedded = framework / "input-gate-provenance.json"
        if (framework.is_symlink() or binary.is_symlink() or embedded.is_symlink()
                or not binary.is_file() or not embedded.is_file()):
            raise RuntimeError("SDL platform slice or embedded record is missing or linked")
        declared = delta["slices"][identifier]
        record = records["RRPlatform"][identifier]
        if (declared.get("nativeSHA256") != hashlib.sha256(binary.read_bytes()).hexdigest()
                or declared.get("baseEmbeddedRecordSHA256") != hashlib.sha256(embedded.read_bytes()).hexdigest()
                or declared.get("nativeIdentity") != record.get("image")
                or declared.get("baseEmbeddedRecordSHA256") != record.get("embeddedBuildRecordSHA256", {}).get("input-gate-provenance.json")):
            raise RuntimeError("SDL platform supplement does not describe this native slice: " + identifier)
    for identifier in sorted(expected_slices):
        records["RRPlatform"][identifier]["virtualJoystickOverride"] = {
            "kind": delta["kind"],
            "baseEmbeddedRecordRole": "Unchanged Clean base build; final member replacement is described by the external supplement",
            "resources": resources,
        }
    return records


def validate_retained_platform_supplement(version):
    """Fail before resource changes if existing platform provenance cannot be preserved."""
    bundle = ARTIFACTS / ("RenPy" + version.replace(".", "") + ".bundle")
    provenance = bundle / "provenance.json"
    prior_override = False
    if provenance.exists() or provenance.is_symlink():
        if provenance.is_symlink() or not provenance.is_file():
            raise RuntimeError("Runtime provenance must be a regular file")
        previous = json.loads(provenance.read_bytes())
        if previous.get("runtimeID") != version:
            raise RuntimeError("Runtime provenance identity mismatch: " + version)
        platform = previous.get("nativeArtifacts", {}).get("RRPlatform", {})
        prior_override = any("virtualJoystickOverride" in value for value in platform.values())
    paths = [KIT / "Notices" / name for name in ("sdl-virtual-joystick-provenance.json", "sdl-virtual-joystick-owner.patch")]
    if prior_override and not any(path.exists() or path.is_symlink() for path in paths):
        raise RuntimeError("Existing SDL platform supplement notices are missing")
    if prior_override or any(path.exists() or path.is_symlink() for path in paths):
        native_packaging_records(version)  # Also validates both present notices and exact native slices.


def refresh_native_provenance(version):
    """Record the newly built frameworks, rather than the ones present before linking."""
    bundle = ARTIFACTS / ("RenPy" + version.replace(".", "") + ".bundle")
    provenance_path = bundle / "provenance.json"
    provenance = json.loads(provenance_path.read_text())
    if provenance.get("runtimeID") != version:
        raise RuntimeError("Runtime provenance identity mismatch: " + version)
    records = native_packaging_records(version)
    runtime = records.get("RRRuntime" + version.replace(".", ""), {})
    if set(runtime) != {"ios-arm64", "ios-arm64-simulator"}:
        raise RuntimeError("New runtime package is missing a native slice: " + version)
    provenance["nativeArtifacts"] = records
    provenance["nativeArtifactsRecordedAfterBuild"] = True
    encoded = json.dumps(provenance, indent=2) + "\n"
    provenance_path.write_text(encoded)
    (KIT / "Notices" / ("renpy-" + version + "-provenance.json")).write_text(encoded)


def flatten_bytecode_caches(base, pyver):
    # Match the target interpreter, never the Python running this build script.
    magic = {"2.7": b"\x03\xf3\r\n", "3.9": b"a\r\r\n", "3.12": b"\xcb\r\r\n"}[pyver]
    pattern = re.compile(r"(.+)\.cpython-" + re.escape(pyver.replace(".", "")) + r"(?:\.opt-[0-2])?\.pyc")
    pending = []
    for source in sorted(base.rglob("__pycache__/*.pyc")):
        match = pattern.fullmatch(source.name)
        with source.open("rb") as file:
            header = file.read(4)
        if match is None or header != magic:
            raise RuntimeError("Bytecode cache does not match Python " + pyver + ": " + str(source))
        pending.append((source, source.parent.parent / (match.group(1) + ".pyc")))
    # Validate the complete set before replacing any previously packaged file.
    for source, target in pending:
        source.replace(target)


def validate_loader_packaging(sdk, version, pyver):
    """Fail before modifying a bundle if an unapproved loader or cache is present."""
    if version not in VERSIONS or sdk.name != "renpy-" + version + "-sdk":
        raise RuntimeError("Unknown loader build identity: " + version)
    validate_retained_platform_supplement(version)
    materials = {
        "rpa-prefix-return.json": "41a2473c018a50291f499c90863bd9be23e2599740ddc7468e66bbf96f57b9bb",
        "legacy7411-subfile-binary-empty.json": "351b00f4e127a16084d0f6e9b8c7769b269ad0cd0b5898bef5c590c05c0aa1b6",
        "official-loader-bytecode.json": "6e458f893328810431199d8fe85bf988eeab90999219b5723afcbbb084143827",
    }
    contracts = {}
    for name, digest in materials.items():
        path = KIT / "Patches" / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Loader build contract missing or changed: " + str(path))
        contracts[name] = json.loads(path.read_bytes())
    stock = contracts["rpa-prefix-return.json"]["versions"][version]
    bytecode = contracts["official-loader-bytecode.json"]["versions"][version]
    legacy = contracts["legacy7411-subfile-binary-empty.json"]["versions"]["7.4.11"]
    if version == "7.4.11":
        patch = KIT / "Patches/legacy7411-subfile-binary-empty.patch"
        expected = contracts["legacy7411-subfile-binary-empty.json"]["patchSHA256"]
        if patch.is_symlink() or not patch.is_file() or hashlib.sha256(patch.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Legacy loader patch missing or changed: " + str(patch))
    if stock["affected"]:
        patch = KIT / "Patches/rpa-prefix-return.patch"
        expected = contracts["rpa-prefix-return.json"]["patchSHA256"]
        if patch.is_symlink() or not patch.is_file() or hashlib.sha256(patch.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Archive loader patch missing or changed: " + str(patch))
    if stock["pythonVersion"] != pyver or bytecode["pythonVersion"] != pyver:
        raise RuntimeError("Loader ABI does not match runtime " + version)

    def caches_in(directory):
        cache_dir = directory / "__pycache__"
        if cache_dir.is_symlink() or (cache_dir.exists() and not cache_dir.is_dir()):
            raise RuntimeError("Loader bytecode cache directory is not regular: " + str(cache_dir))
        candidates = [p for p in directory.iterdir() if re.fullmatch(r"loader(?:\..+)?\.py[co]", p.name)]
        if cache_dir.is_dir():
            candidates += [p for p in cache_dir.iterdir() if re.fullmatch(r"loader(?:\..+)?\.py[co]", p.name)]
        return candidates

    def check(directory, *, upstream):
        source = directory / "loader.py"
        if directory.is_symlink() or not directory.is_dir() or source.is_symlink() or not source.is_file():
            raise RuntimeError("Loader must be a regular file in a regular directory: " + str(directory))
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        allowed = {stock["sourceSHA256"]}
        if version == "7.4.11" and not upstream:
            allowed.add(legacy["outputSHA256"])
        if stock["affected"] and not upstream:
            allowed.add(stock["outputSHA256"])
        if digest not in allowed:
            raise RuntimeError("Unapproved loader source for " + version + ": " + str(source))
        cache_dir = directory / "__pycache__"
        candidates = caches_in(directory)
        for cache in candidates:
            name_ok = cache.parent == directory and cache.name == bytecode["cacheName"]
            if cache.parent == cache_dir and pyver != "2.7":
                name_ok = bool(re.fullmatch(r"loader\.cpython-" + re.escape(pyver.replace(".", "")) + r"(?:\.opt-[0-2])?\.pyc", cache.name))
            if (not name_ok or cache.is_symlink() or not cache.is_file()
                    or hashlib.sha256(cache.read_bytes()).hexdigest() != bytecode["sha256"]
                    or (version == "7.4.11" and digest == legacy["outputSHA256"])
                    or (stock["affected"] and digest == stock["outputSHA256"])):
                raise RuntimeError("Unapproved loader bytecode for " + version + ": " + str(cache))

    bundle = ARTIFACTS / ("RenPy" + version.replace(".", "") + ".bundle")
    base = bundle / "base"
    for directory in (bundle, base):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RuntimeError("Runtime bundle path is not a regular directory: " + str(directory))
    packaged = base / "renpy"
    upstream = sdk / "renpy"
    if sdk.is_symlink() or upstream.is_symlink():
        raise RuntimeError("SDK loader directory must not be linked")
    if packaged.exists() or packaged.is_symlink():
        check(packaged, upstream=False)
    elif base.exists():
        raise RuntimeError("Existing runtime base has no loader directory: " + str(base))
    if upstream.exists() or upstream.is_symlink():
        if not upstream.is_dir():
            raise RuntimeError("SDK loader directory is not regular: " + str(upstream))
        upstream_source = upstream / "loader.py"
        if upstream_source.exists() or upstream_source.is_symlink():
            check(upstream, upstream=True)
        elif not packaged.is_dir() or caches_in(upstream):
            raise RuntimeError("Pruned SDK has orphaned loader cache or no packaged loader: " + str(upstream))
    elif not packaged.is_dir():
        raise RuntimeError("No exact packaged or official loader for " + version)


def patch_archive_prefix_return(base, sdk, version):
    """Apply only the hash-pinned RPA prefix fix; never compile with host Python."""
    directory = KIT / "Patches"
    manifest_path = directory / "rpa-prefix-return.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schemaVersion") != 1 or version not in manifest.get("versions", {}):
        raise RuntimeError("No exact archive-loader source contract for " + version)
    contract = manifest["versions"][version]
    patch_path = directory / manifest["patchFile"]
    if hashlib.sha256(patch_path.read_bytes()).hexdigest() != manifest["patchSHA256"]:
        raise RuntimeError("Archive-loader patch material hash mismatch")
    if sdk.name != "renpy-" + version + "-sdk":
        raise RuntimeError("Archive-loader SDK version mismatch: " + str(sdk))
    target = base / "renpy/loader.py"
    upstream = sdk / "renpy/loader.py"
    if (target.is_symlink() or not target.is_file() or upstream.is_symlink()
            or (upstream.exists() and not upstream.is_file())):
        raise RuntimeError("Archive-loader source must be a regular exact-version file")
    current = target.read_bytes()
    current_sha = hashlib.sha256(current).hexdigest()
    if current_sha not in (contract["sourceSHA256"], contract["outputSHA256"]):
        raise RuntimeError("Packaged archive-loader source hash mismatch for " + version)
    source = upstream.read_bytes() if upstream.is_file() else current
    source_sha = hashlib.sha256(source).hexdigest()
    allowed = (contract["sourceSHA256"],) if upstream.is_file() else (contract["sourceSHA256"], contract["outputSHA256"])
    if source_sha not in allowed:
        raise RuntimeError("Upstream archive-loader source hash mismatch for " + version)
    if not contract["affected"]:
        return None  # These five exact sources and all their caches stay byte-identical.
    if source_sha == contract["sourceSHA256"]:
        old = b"                rv = io.BufferedReader(rv)\n\n        # Compatibility path."
        new = b"                rv = io.BufferedReader(rv)\n                return rv\n\n        # Compatibility path."
        if source.count(old) != 1:
            raise RuntimeError("Inspect exact archive-loader prefix return site for " + version)
        output = source.replace(old, new, 1)
    else:
        output = source  # Idempotent resource refresh with a pruned official SDK.
    if hashlib.sha256(output).hexdigest() != contract["outputSHA256"]:
        raise RuntimeError("Archive-loader patched output hash mismatch for " + version)
    cache_directory = target.parent / "__pycache__"
    if cache_directory.is_symlink():
        raise RuntimeError("Archive-loader bytecode cache must not be a symlink")
    caches = [target.with_suffix(".pyc"), target.with_suffix(".pyo"), *cache_directory.glob("loader.*.py[co]")]
    removed = []
    for cache in caches:
        if cache.is_symlink() or (cache.exists() and not cache.is_file()):
            raise RuntimeError("Archive-loader bytecode is not a regular file")
        if cache.is_file():
            data = cache.read_bytes()
            removed.append({"path": str(cache.relative_to(base)), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    # Validate every input before changing the source or removing stale caches.
    # CPython must compile this source in the target interpreter; host Python's
    # magic/ABI and the original flat loader.pyc cannot select the old function.
    if current != output:
        target.write_bytes(output)
    for cache in caches:
        cache.unlink(missing_ok=True)
    return {"id": manifest["id"], "runtimeID": version, "sourceRelativePath": manifest["sourceRelativePath"],
            "officialSDKURL": contract["officialSDKURL"], "originalSourceSHA256": contract["sourceSHA256"],
            "outputSourceSHA256": contract["outputSHA256"], "readSourceSHA256": source_sha,
            "sourceOrigin": "officialSDK" if upstream.is_file() else "packagedExactSource",
            "patchSHA256": manifest["patchSHA256"], "contractSHA256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "removedBytecode": removed, "bytecodePolicy": "sourceOnly; no host compilation; target dont_write_bytecode retained"}


def patch_legacy_subfile_binary_read(base, sdk, version):
    """Preserve 7411 total-length semantics while returning bytes inside its prefix."""
    directory = KIT / "Patches"
    manifest_path = directory / "legacy7411-subfile-binary-empty.json"
    manifest = json.loads(manifest_path.read_text())
    if (version != "7.4.11" or manifest.get("schemaVersion") != 1
            or set(manifest.get("versions", {})) != {"7.4.11"}
            or manifest.get("sourceRelativePath") != "renpy/loader.py"
            or manifest.get("patchFile") != "legacy7411-subfile-binary-empty.patch"):
        raise RuntimeError("No exact legacy SubFile binary-read contract for " + version)
    contract = manifest["versions"][version]
    patch_path = directory / manifest["patchFile"]
    if hashlib.sha256(patch_path.read_bytes()).hexdigest() != manifest["patchSHA256"]:
        raise RuntimeError("Legacy SubFile patch material hash mismatch")
    if sdk.name != "renpy-" + version + "-sdk":
        raise RuntimeError("Legacy SubFile SDK version mismatch: " + str(sdk))
    target = base / "renpy/loader.py"
    upstream = sdk / "renpy/loader.py"
    if (target.is_symlink() or not target.is_file() or upstream.is_symlink()
            or (upstream.exists() and not upstream.is_file())):
        raise RuntimeError("Legacy SubFile source must be a regular exact-version file")
    current = target.read_bytes()
    current_sha = hashlib.sha256(current).hexdigest()
    if current_sha not in (contract["sourceSHA256"], contract["outputSHA256"]):
        raise RuntimeError("Packaged legacy SubFile source hash mismatch")
    source = upstream.read_bytes() if upstream.is_file() else current
    source_sha = hashlib.sha256(source).hexdigest()
    allowed = (contract["sourceSHA256"],) if upstream.is_file() else (contract["sourceSHA256"], contract["outputSHA256"])
    if source_sha not in allowed:
        raise RuntimeError("Upstream legacy SubFile source hash mismatch")
    if source_sha == contract["sourceSHA256"]:
        old = b'            rv2 = ""\n'
        new = b'            rv2 = b""\n'
        if source.count(old) != 1:
            raise RuntimeError("Inspect exact legacy SubFile binary empty-string site")
        output = source.replace(old, new, 1)
    else:
        output = source
    if hashlib.sha256(output).hexdigest() != contract["outputSHA256"]:
        raise RuntimeError("Legacy SubFile patched output hash mismatch")
    cache_directory = target.parent / "__pycache__"
    if cache_directory.is_symlink() or (cache_directory.exists() and not cache_directory.is_dir()):
        raise RuntimeError("Legacy SubFile bytecode cache must be a regular directory")
    caches = [target.with_suffix(".pyc"), target.with_suffix(".pyo"), *cache_directory.glob("loader.*.py[co]")]
    removed = []
    for cache in caches:
        if cache.is_symlink() or (cache.exists() and not cache.is_file()):
            raise RuntimeError("Legacy SubFile bytecode is not a regular file")
        if cache.is_file():
            data = cache.read_bytes()
            removed.append({"path": str(cache.relative_to(base)), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    # Stage all checks before touching source/caches. Only the target interpreter
    # may compile this source; the old loader.pyo must never select the old read.
    if current != output:
        target.write_bytes(output)
    for cache in caches:
        cache.unlink(missing_ok=True)
    return {"id": manifest["id"], "runtimeID": version, "sourceRelativePath": manifest["sourceRelativePath"],
            "officialSDKURL": contract["officialSDKURL"], "originalSourceSHA256": contract["sourceSHA256"],
            "outputSourceSHA256": contract["outputSHA256"], "readSourceSHA256": source_sha,
            "sourceOrigin": "officialSDK" if upstream.is_file() else "packagedExactSource",
            "patchSHA256": manifest["patchSHA256"], "contractSHA256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "removedBytecode": removed, "bytecodePolicy": "sourceOnly; no host compilation; target dont_write_bytecode retained"}


def validate_qualified_overlay_rebuild(version="8.5.3"):
    """Keep an advertised engine build intact until a replacement is qualified."""
    profile = ARTIFACTS / ("RenPy" + version.replace(".", "") + ".bundle/runtime-profile.json")
    catalog = ARTIFACTS / "runtime-catalog.json"
    for path in (profile, catalog):
        if path.is_symlink():
            raise RuntimeError("Linked capability metadata cannot be rebuilt safely: " + str(path))
    try:
        profile_data = json.loads(profile.read_text()) if profile.exists() else {}
        catalog_data = json.loads(catalog.read_text()) if catalog.exists() else {}
        if not isinstance(profile_data, dict) or not isinstance(catalog_data, dict):
            raise ValueError("invalid metadata")
        entries = catalog_data.get("profiles", [])
        if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
            raise ValueError("invalid catalog profiles")
    except (OSError, ValueError) as error:
        raise RuntimeError("Cannot safely inspect capability metadata before rebuilding") from error
    if ("engineOverlaySchemaVersion" in profile_data or
            any(entry.get("runtimeID") == version and "engineOverlaySchemaVersion" in entry for entry in entries)):
        raise RuntimeError("Qualified " + version + " artifacts must be rebuilt in an isolated destination and requalified before promotion")


def select_resource_host(version):
    if version == "8.5.3":
        source = KIT / "Candidates/DialogueVisibleSegments/host_modern.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e":
            raise RuntimeError("The promoted 8.5.3 dialogue segment host changed; review it before rebuilding")
        return source
    if version in ("7.4.11", "7.5.3", "8.0.3", "8.1.3", "7.7.3", "7.8.7", "8.2.3", "8.4.1"):
        legacy = version in ("7.4.11", "7.5.3", "8.0.3", "8.1.3")
        source = KIT / ("Candidates/DialogueVisibleSegments/host_legacy.py" if legacy else "Candidates/DialogueVisibleSegments/host_modern.py")
        expected = "d2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74" if legacy else "e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e"
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise RuntimeError("The promoted " + version + " dialogue segment host changed; review it before rebuilding")
        return source
    if version in ("8.4.1", "8.2.3", "7.8.7", "7.7.3"):
        source = KIT / "Candidates/GallerySeenUnlocker/host_modern.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "6b7d3ba3d4992d4b5c8415fa73d89caa98c52763c642b48f398bc16da7ea68d5":
            raise RuntimeError("The promoted 8.4.1 gallery seen host changed; review it before rebuilding")
        return source
    if version == "8.3.7":
        source = KIT / "Candidates/DialogueVisibleSegments/host_modern.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "e5e066c103d506d9b919e936461804683b1660b9f2f1b09546fec79eeee80c5e":
            raise RuntimeError("The promoted " + version + " dialogue segment host changed; review it before rebuilding")
        return source
    if version == "7.6.3":
        source = KIT / "Candidates/DialogueVisibleSegments/host_legacy.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "d2f606abbe8850d0cf05f8003a1ba598ad9a6a04c18422e27af0c1c00e293c74":
            raise RuntimeError("The promoted 7.6.3 dialogue segment host changed; review it before rebuilding")
        return source
    if version in ("7.6.3", "8.1.3", "8.0.3", "7.5.3", "7.4.11"):
        source = KIT / "Candidates/GallerySeenUnlocker/host_legacy.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "37d4812691918653801221c31ef7bbc7a1199bc8854508419fa84e38b4f89d29":
            raise RuntimeError("The promoted 7.6.3 gallery host changed; review it before rebuilding")
        return source
    if version in ("7.4.11", "7.5.3", "7.6.3", "8.0.3", "8.1.3"):
        source = KIT / "Candidates/InlineTranslation/host_legacy.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "5c0c7edacd74a410a1fd038a69c429dad78bd2ef9ff1e00bbcfbb9c5f23232c0":
            raise RuntimeError("The promoted 7.6.3 inline translation host changed; review it before rebuilding")
        return source
    if version in ("7.7.3", "7.8.7", "8.2.3", "8.3.7", "8.4.1", "8.5.3"):
        source = KIT / "Candidates/InlineTranslation/host_modern.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "b0f0c94c8449dd7d007434b374cb9de625528807968e49cd2506a05da2a942ff":
            raise RuntimeError("The promoted 8.5.3 inline translation host changed; review it before rebuilding")
        return source
    if version in VERSIONS:
        source = KIT / "Candidates/SessionVariableUTF8Pairs/rr_host.py"
        if hashlib.sha256(source.read_bytes()).hexdigest() != "9afa69699c061bf5354d659fa988289a88f1110be79be4c44c1f084cadc05202":
            raise RuntimeError("The promoted variable compatibility host changed; review it before rebuilding")
        return source
    return KIT / "Python/rr_host.py"


def patch_traceback_utf8_853(base, sdk, version="8.5.3"):
    """Apply the pinned error-file writer patch for a validated runtime."""
    upstream = sdk / "renpy/error.py"
    identities = {
        "8.5.3": ("7d1c0c77c40ad8fae8a7d4833891a237b541a71a32716a676a071cbf6a5fbf6b", "daa5e4c16e5f659386d8a3a118cb741b02024ed8423d4e3c63c0f00bad7efb82"),
        "8.3.7": ("dfa364e74c6bebce6612e7028b311d4f122f5b27a8c5d8542eb697192c7c8e38", "8a6cc45b0c71f1525b1a0ba664ed32df2fd9b43807bc0383fcb614459f8785c7"),
    }
    expected_upstream, expected_candidate = identities[version]
    candidate = KIT / ("Candidates/TracebackUTF8/error" + version.replace(".", "") + ".py")
    if hashlib.sha256(upstream.read_bytes()).hexdigest() != expected_upstream or hashlib.sha256(candidate.read_bytes()).hexdigest() != expected_candidate:
        raise RuntimeError("The pinned traceback writer changed; review before rebuilding")
    target = base / "renpy/error.py"
    bytecode = base / "renpy/error.pyc"
    removed = []
    if bytecode.exists():
        removed.append({"path": "renpy/error.pyc", "sha256": hashlib.sha256(bytecode.read_bytes()).hexdigest(), "bytes": bytecode.stat().st_size})
        bytecode.unlink()
    shutil.copy2(candidate, target)
    return {"id": "renpy-traceback-utf8-v1", "sourceRelativePath": "renpy/error.py",
            "originalSourceSHA256": expected_upstream, "outputSourceSHA256": expected_candidate,
            "removedBytecode": removed, "sourceOrigin": "officialSDK", "bytecodePolicy": "sourceOnly"}


def validate_no_sdk_entry(source):
    """Reject historical SDK loaders before copying an entry into a new bundle."""
    data = source.read_bytes()
    for marker in (b"live2DCoreInfoJSON", b"inspectLive2DMocJSON", b"createLive2DEffectsJSON",
                   b"stepLive2DEffectsJSON", b"live2DEffectsStatsJSON", b"clearLive2DEffects",
                   b"rr_legacy_live2d", b"rr_live2d_effects", b"rr_live2d_renderer",
                   b"rr_live2d_motion", b"rr_live2d_mesh"):
        if marker in data:
            raise RuntimeError("Excluded SDK entry requires review: " + str(source))


def resources(sdk, version, pyver, notices_directory=None, *, loader_validator=None, archive_patcher=None, host_source=None):
    if version in VERSIONS:
        validate_qualified_overlay_rebuild(version)
    suffix = version.replace(".", "")
    bundle = ARTIFACTS / ("RenPy" + suffix + ".bundle")
    base = bundle / "base"
    resource_host = host_source or select_resource_host(version)
    python_sources = [source for source in (KIT / "Python").glob("*.py")
                      if source.name != "rr_legacy_live2d.py" and
                      (not source.name.startswith("rr_live2d_") or source.name == "rr_live2d_backend.py")]
    for source in [resource_host, *python_sources]:
        validate_no_sdk_entry(source)
    (loader_validator or validate_loader_packaging)(sdk, version, pyver)
    base.mkdir(parents=True, exist_ok=True)
    for name in ("renpy", "lib/python" + pyver):
        source, target = sdk / name, base / name
        if not target.exists():
            shutil.copytree(source, target)
    shutil.copy2(sdk / "renpy.py", base / "renpy.py")
    for source in python_sources:
        shutil.copy2(source, base / source.name)
    shutil.copy2(resource_host, base / "rr_host.py")
    shutil.copy2(KIT / "Fonts" / "renreader-trust-7e42.ttf",
                 base / "renpy/common/renreader-trust-7e42.ttf")
    flatten_bytecode_caches(base, pyver)
    traceback_patch = patch_traceback_utf8_853(base, sdk, version) if version in ("8.3.7", "8.5.3") else None
    archive_patch = (patch_legacy_subfile_binary_read(base, sdk, version) if version == "7.4.11"
                     else (archive_patcher or patch_archive_prefix_return)(base, sdk, version))
    display_core = base / "renpy/display/core.py"
    upstream_display_core = sdk / "renpy/display/core.py"
    # Resource-only refreshes also support pruned official caches; preserve the
    # exact already-packaged version and apply this narrow patch idempotently.
    display_core.write_text(patch_embedded_view_size((upstream_display_core if upstream_display_core.exists() else display_core).read_text()))
    for extension in (".pyc", ".pyo"):
        display_core.with_suffix(extension).unlink(missing_ok=True)
    bootstrap = base / "renpy/bootstrap.py"
    text = (sdk / "renpy/bootstrap.py").read_text()
    if text.count("    renpy.import_all()") != 1:
        raise RuntimeError("Inspect upstream engine import hook")
    text = text.replace("    renpy.import_all()", "    __import__('rr_host').ensure_engine_imported()")
    if "basedir = get_alternate_base(" not in text:
        # 7.4–7.6 bootstrap predates alternate-base restarts. Its process-level
        # game-directory search must be replaced at the per-session loop edge.
        marker = "                renpy.game.args = args"
        if text.count(marker) != 1:
            raise RuntimeError("Inspect upstream legacy session loop")
        text = text.replace(marker, "                basedir = __import__('rr_host')._next_base(basedir)\n                gamedir = __import__('rr_host').game_directory()\n" + marker)
        text = text.replace("renpy.config.logdir = basedir", "renpy.config.logdir = __import__('rr_host').log_directory()")
    old = "                renpy.reload_all()\n\n                exit_status = None"
    new = """                renpy.reload_all()
                if __import__("rr_host").should_return_to_host():
                    __import__("rr_host").session_did_reset()
                    exit_status = 0
                else:
                    exit_status = None"""
    if text.count(old) != 1:
        raise RuntimeError("Inspect upstream utter restart hook")
    text = text.replace(old, new)
    series_boundary = "            except renpy.game.UtterRestartException:"
    if text.count(series_boundary) != 1:
        raise RuntimeError("Inspect upstream series state failure boundary")
    text = text.replace(series_boundary, '''            except __import__("rr_series_state").SeriesStateFailure as error:
                __import__("rr_host").emit("seriesStateFailed", message=__import__("rr_series_state").diagnostics().get("failure") or "MultiPersistent I/O failed")
                __import__("rr_host").emit("willStop")
                renpy.reload_all()
                __import__("rr_host").session_did_reset()
                exit_status = 0

''' + series_boundary)
    pattern = r"            except renpy\.game\.QuitException as e:\n.*?(?=            except renpy\.game\.ParseErrorException:)"
    text, count = re.subn(pattern, '''            except renpy.game.QuitException as e:
                # RenReader owns the process; title Quit returns to the shelf.
                renpy.reload_all()
                __import__("rr_host").session_did_reset()
                exit_status = 0

''', text, flags=re.S)
    if count != 1 or text.count("        sys.exit(exit_status)") != 1:
        raise RuntimeError("Inspect upstream quit/return hook")
    text = text.replace("        sys.exit(exit_status)", "        return exit_status")
    head, shutdown = text.rsplit("    finally:\n", 1)
    text = head + "    finally:\n        if not __import__('rr_host').host_returned():\n" + "".join("    " + line if line.strip() else line for line in shutdown.splitlines(True))
    bootstrap.write_text(text)
    bootstrap.with_suffix(".pyc").unlink(missing_ok=True)
    bootstrap.with_suffix(".pyo").unlink(missing_ok=True)
    initializer = base / "renpy/__init__.py"
    upstream_initializer = sdk / "renpy/__init__.py"
    if not upstream_initializer.exists():
        upstream_initializer.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(initializer, upstream_initializer)
    original = upstream_initializer.read_text()
    patched = original
    disabled = '    if mobile:\n        raise Exception("Reloading is not supported on mobile platforms.")'
    if disabled in original:
        # Old SDKs disable the desktop snapshot/reset path on mobile. The host
        # retains the interpreter and uses that same path between title sessions.
        patched = original.replace("        if mobile:\n            return\n", "")
        patched = patched.replace("    if not mobile:\n        backup = Backup()", "    backup = Backup()")
        patched = patched.replace(disabled, "")
        # This iOS-only Pyobjus class proxy is process-lifetime native state,
        # not pickleable game state. Audio quit stops its channel instances.
        patched = patched.replace("name_blacklist = {", "name_blacklist = {\n    'renpy.audio.ioshw.VideoPlayer',")
    renderer_quit = '    if not renpy.session.get("_keep_renderer", False):'
    if patched.count(renderer_quit) != 1:
        raise RuntimeError("Inspect upstream renderer cleanup boundary")
    patched = patched.replace(renderer_quit, '    if renpy.display.draw is not None and not renpy.session.get("_keep_renderer", False):')
    initializer.write_text(patched)
    initializer.with_suffix(".pyc").unlink(missing_ok=True)
    initializer.with_suffix(".pyo").unlink(missing_ok=True)
    exports_name = "renpy/exports/displayexports.py" if (base / "renpy/exports/displayexports.py").exists() else "renpy/exports.py"
    exports = base / exports_name
    upstream_exports = sdk / exports_name
    if not upstream_exports.exists():
        upstream_exports.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(exports, upstream_exports)
    text = upstream_exports.read_text()
    interface_cleanup = "    force_full_redraw()\n    renpy.display.interface.kill_textures()\n    renpy.display.interface.kill_surfaces()"
    if text.count(interface_cleanup) != 1:
        raise RuntimeError("Inspect upstream pre-interface memory cleanup boundary")
    text = text.replace(interface_cleanup, "    if renpy.display.interface is not None and renpy.game.interface is not None:\n" + "\n".join("    " + line for line in interface_cleanup.splitlines()))
    exports.write_text(text)
    exports.with_suffix(".pyc").unlink(missing_ok=True)
    exports.with_suffix(".pyo").unlink(missing_ok=True)
    rollback_name = "renpy/rollback.py" if (base / "renpy/rollback.py").exists() else "renpy/python.py"
    rollback = base / rollback_name
    upstream_rollback = sdk / rollback_name
    if not upstream_rollback.exists():
        shutil.copy2(rollback, upstream_rollback)
    text = upstream_rollback.read_text()
    pattern = r"renpy\.game\.contexts\s*=\s*renpy\.game\.contexts\[:-1\]\s*\+\s*\[\s*self\.context\s*\]"
    text, count = re.subn(pattern, "renpy.game.contexts = renpy.game.contexts[:-1] + [self.context.rollback_copy()]", text)
    if count == 0:
        legacy = "        renpy.game.contexts.pop()\n        renpy.game.contexts.append(self.context)"
        if text.count(legacy) in (1, 2):
            text = text.replace(legacy, "        renpy.game.contexts.pop()\n        renpy.game.contexts.append(self.context.rollback_copy())")
            count = 1
    if count != 1:
        raise RuntimeError("Inspect upstream rollback context restore: expected one frozen-context assignment")
    if version in ("7.6.3", "8.1.3"):
        # Backport the next official release's stop at retained records. Without
        # it, greedy load rolls data back past a tool edit after a hard checkpoint.
        marker = "            if rb.not_greedy:\n                break\n\n            revlog.append(self.log.pop())"
        if text.count(marker) != 1:
            raise RuntimeError("Inspect legacy retained-statement rollback boundary")
        text = text.replace(marker, "            if rb.not_greedy:\n                break\n\n            if rb.retain_after_load:\n                break\n\n            revlog.append(self.log.pop())", 1)
    # A rollback record must remain a frozen snapshot. Reusing it as the live
    # interaction context makes a later same-statement save serialize transient
    # interacting=True, breaking the next cold load. The SDK's own copy helper
    # resets that transient flag and also loads already affected saves in memory.
    rollback.write_text(text)
    rollback.with_suffix(".pyc").unlink(missing_ok=True)
    rollback.with_suffix(".pyo").unlink(missing_ok=True)
    (bundle / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.renreader.resources" + suffix, "CFBundleName": "RenPy" + suffix, "CFBundlePackageType": "BNDL", "CFBundleVersion": "1"}))
    shutil.copy2(sdk / "LICENSE.txt", bundle / "LICENSE.txt")
    shared_sdk = fetch("8.5.3")
    shutil.copy2(shared_sdk / "LICENSE.txt", bundle / "SharedPlatform-LICENSE.txt")
    notices = notices_directory or KIT / "Notices"
    notices.mkdir(exist_ok=True)
    shutil.copy2(sdk / "LICENSE.txt", notices / ("renpy-" + version + "-LICENSE.txt"))
    archive_data = json.loads((CACHE / "official" / version / "paths.json").read_text())
    provenance = {"runtimeID": version, "pythonVersion": pyver, "officialArchives": [{"url": "https://www.renpy.org/dl/" + version + "/" + name, "sha256": sha} for name, sha in archive_data["sha256"].items()], "sources": ["https://github.com/renpy/renpy", "https://github.com/renpy/renpy-build", "https://github.com/renpy/pygame_sdl2"], "hostSourceSHA256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [KIT / "Native/RRRuntime.m", KIT / "Native/RRPlatform.m", KIT / "Native/RRInputGate.c", KIT / "Native/RRInputGate.h", ROOT / "Scripts/runtime/build_sdl_gate.py", ROOT / "Scripts/runtime/prepare_sdl_gate.py", *python_sources, *(KIT / "Bridge").glob("*.[hm]"), ROOT / "Scripts/runtime/build_runtime.py", ROOT / "Scripts/runtime/fetch_official.py", ROOT / "Scripts/runtime/privacy_manifests.py"]}}
    # Assembly hashes describe the source tree at resource generation. The
    # retained shared platform may deliberately precede an unrelated candidate
    # source edit; never label such an edit as its compiled input.
    provenance["hostSourceSHA256Role"] = "Resource assembly source state; native compilation inputs are the embedded build records of nativeArtifacts"
    provenance["resourceHost"] = {"path": str(resource_host.relative_to(ROOT)),
                                  "sha256": hashlib.sha256(resource_host.read_bytes()).hexdigest()}
    provenance["nativeArtifacts"] = native_packaging_records(version)
    provenance["resourcePatches"] = [patch for patch in (archive_patch, traceback_patch) if patch]
    if traceback_patch:
        provenance["hostSourceSHA256"]["RuntimeKit/Candidates/TracebackUTF8/error" + suffix + ".py"] = traceback_patch["outputSourceSHA256"]
    provenance["hostSourceSHA256"]["RuntimeKit/Patches/official-loader-bytecode.json"] = hashlib.sha256((KIT / "Patches/official-loader-bytecode.json").read_bytes()).hexdigest()
    if archive_patch and version == "7.4.11":
        for name in ("legacy7411-subfile-binary-empty.json", "legacy7411-subfile-binary-empty.patch"):
            provenance["hostSourceSHA256"]["RuntimeKit/Patches/" + name] = hashlib.sha256((KIT / "Patches" / name).read_bytes()).hexdigest()
        shutil.copy2(KIT / "Patches/legacy7411-subfile-binary-empty.patch", notices / ("renpy-" + version + "-legacy7411-subfile-binary-empty.patch"))
        shutil.copy2(KIT / "Patches/legacy7411-subfile-binary-empty.patch", bundle / "legacy7411-subfile-binary-empty.patch")
    elif archive_patch:
        for name in ("rpa-prefix-return.json", "rpa-prefix-return.patch"):
            provenance["hostSourceSHA256"]["RuntimeKit/Patches/" + name] = hashlib.sha256((KIT / "Patches" / name).read_bytes()).hexdigest()
        shutil.copy2(KIT / "Patches/rpa-prefix-return.patch", notices / ("renpy-" + version + "-rpa-prefix-return.patch"))
        shutil.copy2(KIT / "Patches/rpa-prefix-return.patch", bundle / "rpa-prefix-return.patch")
    encoded_provenance = json.dumps(provenance, indent=2) + "\n"
    (bundle / "provenance.json").write_text(encoded_provenance)
    (notices / ("renpy-" + version + "-provenance.json")).write_text(encoded_provenance)
    shutil.copy2(KIT / "NOTICE.md", bundle / "NOTICE.md")
    (bundle / "runtime-profile.json").write_text(json.dumps({"runtimeID": version, "pythonVersion": pyver, "patchedBootstrap": True, "live2D": {"available": False, "reason": "notIncluded"}}, indent=2) + "\n")
    return bundle


def clang_args(platform, name):
    sysroot = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-path"], text=True).strip()
    deployment = "-mios-simulator-version-min=17.0" if platform == "iphonesimulator" else "-miphoneos-version-min=17.0"
    return ["xcrun", "--sdk", platform, "clang", "-arch", "arm64", "-isysroot", sysroot, deployment, "-fobjc-arc", "-fmodules", "-dynamiclib", "-fvisibility=hidden", "-Wl,-install_name,@rpath/" + name + ".framework/" + name]


def finish_framework(path, name, version, platform):
    (path / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.renreader." + name.lower(), "CFBundleName": name, "CFBundleExecutable": name, "CFBundlePackageType": "FMWK", "CFBundleVersion": "1", "CFBundleShortVersionString": version, "MinimumOSVersion": "17.0", "CFBundleSupportedPlatforms": ["iPhoneSimulator" if platform == "iphonesimulator" else "iPhoneOS"]}))
    write_framework_manifest(path, name)


def package(name, frameworks):
    target = ARTIFACTS / (name + ".xcframework")
    if target.exists():
        shutil.rmtree(target)
    args = ["xcodebuild", "-create-xcframework"]
    for path in frameworks:
        args += ["-framework", path]
    run(args + ["-output", target])


def angle_path(sdk, platform):
    root = sdk / "renios/prototype/Frameworks/MetalANGLE.xcframework"
    if not root.exists():
        root = ARTIFACTS / "MetalANGLE.xcframework"
    return next(p for p in root.iterdir() if p.is_dir() and p.name.startswith("ios-arm64") and ("simulator" in p.name) == (platform == "iphonesimulator"))


def platform_inputs():
    return [KIT / "Native" / name for name in ("RRPlatform.m", "RRInputGate.c", "RRInputGate.h", "RRAuxiliaryInput.c", "RRAuxiliaryInput.h")] + [ROOT / "Scripts/runtime/prepare_sdl_gate.py", ROOT / "Scripts/runtime/build_sdl_gate.py", Path(__file__)]


def validate_platform_rebuild_safety():
    """Do not overwrite an existing platform whose retained provenance would become stale."""
    target = ARTIFACTS / "RRPlatform.xcframework"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise RuntimeError("Existing RRPlatform package must be a regular directory")
    if target.exists() and target.stat().st_mtime < max(path.stat().st_mtime for path in platform_inputs()):
        raise RuntimeError("RRPlatform inputs changed; rebuild in an isolated destination and verify its provenance before promotion")


def build_platform(sdk, destination=None, probe_source=None):
    name = "RRPlatform"
    source = KIT / "Native/RRPlatform.m"
    target = (destination or ARTIFACTS) / (name + ".xcframework")
    inputs = platform_inputs()
    if destination is not None and target.resolve() == (ARTIFACTS / (name + ".xcframework")).resolve():
        raise RuntimeError("Explicit platform build destination must be isolated from the formal package")
    if destination is None:
        validate_platform_rebuild_safety()
        if target.exists():
            return
    prototype = sdk / "renios/prototype"
    frameworks = []
    for platform, mode in PLATFORMS:
        output = (destination or (CACHE / "build")) / platform / (name + ".framework")
        output.mkdir(parents=True, exist_ok=True)
        prebuilt = prototype / ("prebuilt/" + mode)
        gated_archive, gate_object, patched = compile_gate(prebuilt / "libSDL2.a", platform)
        deps = [x for x in libraries(sdk, "3.12") if x not in ("-lrenpy", "-lrenpython", "-lpython3.12", "-lSDL2", "-lSDL2_image")]
        args = clang_args(platform, name) + ["-Wl,-exported_symbol,_SDL_*", "-Wl,-exported_symbol,_IMG_*", "-Wl,-exported_symbol,_renpy_IMG_*", "-Wl,-exported_symbol,_RRPlatform*", "-I", patched / "include", "-I", KIT / "Native", "-Wl,-alias,_RRPlatformDlsym,_dlsym", "-L", prebuilt, "-F", angle_path(sdk, platform), source]
        # Only pull supported platform entry points used by a bundled ABI.
        # Force-loading all of SDL would also pull disabled HID backend stubs.
        symbols = set()
        for archive in (CACHE / "official").glob("*/extracted/*/renios/prototype/prebuilt/" + mode + "/librenpy.a"):
            nm = subprocess.check_output(["nm", "-g", archive], text=True)
            symbols.update(re.findall(r" U (_(?:SDL_|IMG_)[A-Za-z0-9_]+)", nm))
        # Preserve the supported symbol surface already used by all 11 ABIs,
        # even when their original archives were pruned after packaging.
        baseline = ARTIFACTS / "RRPlatform.xcframework" / ("ios-arm64-simulator" if platform == "iphonesimulator" else "ios-arm64") / "RRPlatform.framework/RRPlatform"
        if baseline.exists():
            nm = subprocess.check_output(["nm", "-gU", baseline], text=True)
            symbols.update(re.findall(r" (_(?:SDL_|IMG_|renpy_IMG_)[A-Za-z0-9_]+)", nm))
        args += ["-Wl,-u," + symbol for symbol in sorted(symbols)]
        args += ["-lSDL2_image", gated_archive, gate_object]
        if probe_source is not None:
            args += ["-I", patched / "src", probe_source]
        args += [prototype / f for f in ("IAPHelper.m", "Log.m", "VideoPlayer.m")]
        args += deps
        for framework in SYSTEM_FRAMEWORKS + ("MetalANGLE",):
            args += ["-framework", framework]
        run(args + ["-o", output / name])
        finish_framework(output, name, "1.0", platform)
        shutil.copy2(sdk / "LICENSE.txt", output / "LICENSE.txt")
        shutil.copy2(patched / "LICENSE.txt", output / "SDL-LICENSE.txt")
        shutil.copy2(patched / "RenReader-input-gate.patch", output / "RenReader-input-gate.patch")
        shutil.copy2(gated_archive.parent / "provenance.json", output / "input-gate-provenance.json")
        frameworks.append(output)
    if destination is None:
        package(name, frameworks)
    else:
        if target.exists():
            shutil.rmtree(target)
        run(["xcodebuild", "-create-xcframework", *[part for f in frameworks for part in ("-framework", f)], "-output", target])
    angle_target = ARTIFACTS / "MetalANGLE.xcframework"
    if not angle_target.exists():
        shutil.copytree(prototype / "Frameworks/MetalANGLE.xcframework", angle_target)


def build_core(sdk, version, pyver, destination=None):
    suffix = version.replace(".", "")
    name = "RRRuntime" + suffix
    frameworks = []
    for platform, mode in PLATFORMS:
        output = (destination.parent / "Build" if destination is not None else CACHE / "build") / platform / (name + ".framework")
        output.mkdir(parents=True, exist_ok=True)
        prebuilt = sdk / ("renios/prototype/prebuilt/" + mode)
        platform_framework = ARTIFACTS / "RRPlatform.xcframework" / ("ios-arm64-simulator" if platform == "iphonesimulator" else "ios-arm64")
        deps = [x for x in libraries(sdk, pyver) if x not in ("-lrenpython", "-lSDL2", "-lSDL2_image")]
        cslots_provenance = None
        movie_provenance = None
        archive = prebuilt / "librenpy.a"
        archive_search = []
        if version in ("8.4.1", "8.5.3"):
            from build_cslots import patched_archive
            archive, cslots_provenance = patched_archive(sdk, version, platform, mode)
            archive_search = ["-L", archive.parent]
        if version == "8.5.3":
            from build_movie_color import patched_archive as movie_color_archive
            archive, movie_provenance = movie_color_archive(sdk, version, platform, mode, archive, cslots_provenance)
            archive_search = ["-L", archive.parent]
        args = clang_args(platform, name) + ["-Wl,-exported_symbol,_RR" + suffix + "Run", "-DRR_RUNTIME_RUN=RR" + suffix + "Run", "-DRR_PYTHON_MAJOR=" + pyver[0], '-DRR_PYTHON_VERSION="' + pyver + '"', *archive_search, "-L", prebuilt, "-F", platform_framework, KIT / "Native/RRRuntime.m", *deps, "-framework", "RRPlatform"]
        for framework in SYSTEM_FRAMEWORKS:
            args += ["-framework", framework]
        run(args + ["-o", output / name])
        finish_framework(output, name, version, platform)
        if cslots_provenance is not None:
            record = json.loads(cslots_provenance.read_text())
            record.update(binarySHA256=hashlib.sha256((output / name).read_bytes()).hexdigest(),
                          runtimeHostSourceSHA256=hashlib.sha256((KIT / "Native/RRRuntime.m").read_bytes()).hexdigest(),
                          linkArguments=list(map(str, args)))
            (output / "cslots-deallocation-provenance.json").write_text(json.dumps(record, indent=2) + "\n")
            shutil.copy2(KIT / "Native/Cslots/cslots-deallocation.patch", output / "cslots-deallocation.patch")
        if movie_provenance is not None:
            record = json.loads(movie_provenance.read_text())
            record.update(binarySHA256=hashlib.sha256((output / name).read_bytes()).hexdigest(),
                          runtimeHostSourceSHA256=hashlib.sha256((KIT / "Native/RRRuntime.m").read_bytes()).hexdigest(),
                          linkArguments=list(map(str, args)))
            record["embeddedParentCslotsRecordSHA256"] = hashlib.sha256((output / "cslots-deallocation-provenance.json").read_bytes()).hexdigest()
            record["linkedArchivesSHA256"] = {dep: hashlib.sha256(path.read_bytes()).hexdigest()
                for dep in deps if dep.startswith("-l")
                for path in [archive if dep == "-lrenpy" else prebuilt / ("lib" + dep[2:] + ".a")] if path.is_file()}
            record["sharedPlatformBinarySHA256"] = hashlib.sha256((platform_framework / "RRPlatform.framework/RRPlatform").read_bytes()).hexdigest()
            (output / "movie-color-provenance.json").write_text(json.dumps(record, indent=2) + "\n")
            shutil.copy2(KIT / "Native/MovieColor/ffmedia-vp8-container.patch", output / "movie-color.patch")
        frameworks.append(output)
    if destination is None:
        package(name, frameworks)
    else:
        target = destination / (name + ".xcframework")
        if target.exists():
            shutil.rmtree(target)
        run(["xcodebuild", "-create-xcframework", *[part for framework in frameworks for part in ("-framework", framework)], "-output", target])


def enable_verified_overlay_853_after_build():
    """Only advertise an accepted 853 capability after final native identity is known."""
    from overlay_capability_guard import accepted
    path = ARTIFACTS / "RenPy853.bundle/runtime-profile.json"
    profile = json.loads(path.read_bytes())
    if "engineOverlaySchemaVersion" in profile:
        raise RuntimeError("Resource assembly must start with overlay capability disabled")
    contract_path = KIT / "Patches/overlay-capability-853.json"
    if not contract_path.is_file() or contract_path.is_symlink():
        raise RuntimeError("Missing 853 capability contract")
    contract = json.loads(contract_path.read_bytes())
    if contract.get("qualification", {}).get("accepted") is not True:
        return
    try:
        accepted(ROOT, contract)
    except ValueError as error:
        # Keep capability off on any source, ABI, provenance or native mismatch.
        print("853 engine overlay remains disabled:", error)
        return
    profile["engineOverlaySchemaVersion"] = 1
    temporary = path.with_name(path.name + ".overlay-pending")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("Stale overlay profile staging file")
    try:
        temporary.write_text(json.dumps(profile, indent=2) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_catalog():
    profiles = []
    for version in VERSIONS:
        suffix = version.replace(".", "")
        profile = ARTIFACTS / ("RenPy" + suffix + ".bundle/runtime-profile.json")
        ready = profile.exists() and (ARTIFACTS / ("RRRuntime" + suffix + ".xcframework")).exists()
        data = json.loads(profile.read_text()) if profile.exists() else {"runtimeID": version}
        data.update(framework="RRRuntime" + suffix, resourceBundle="RenPy" + suffix, artifactsPresent=ready)
        profiles.append(data)
    (ARTIFACTS / "runtime-catalog.json").write_text(json.dumps({"schemaVersion": 1, "sharedPlatform": "RRPlatform", "profiles": profiles}, indent=2) + "\n")


def prune_inputs(version):
    """Keep reproducible provenance and tiny patch inputs after artifact creation."""
    directory = CACHE / "official" / version
    sdk = Path(json.loads((directory / "paths.json").read_text())["sdk"])
    names = ["renpy/bootstrap.py", "renpy/__init__.py", "renpy.py", "LICENSE.txt"]
    names.append("renpy/gl2/live2d.py")
    names.append("renpy/display/core.py")
    names.append("renpy/rollback.py" if (sdk / "renpy/rollback.py").exists() else "renpy/python.py")
    retained = {name: (sdk / name).read_bytes() for name in names}
    shutil.rmtree(sdk)
    for name, data in retained.items():
        target = sdk / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for archive in directory.glob("*.zip"):
        archive.unlink()
    for marker in (directory / "extracted").glob(".*.extracted"):
        marker.unlink()
    for platform, mode in PLATFORMS:
        shutil.rmtree(CACHE / "build" / platform / ("RRRuntime" + version.replace(".", "") + ".framework"), ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="append", choices=VERSIONS)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--resources-only", action="store_true")
    parser.add_argument("--prune-cache", action="store_true")
    args = parser.parse_args()
    versions = VERSIONS if args.all else args.version or ("8.5.3",)
    # Even a different runtime invokes patch_existing on every framework and
    # rewrites the shared catalog. Reject before fetch or any artifact writes.
    validate_qualified_overlay_rebuild()
    inputs = []
    for version in versions:
        sdk = fetch(version, native=not args.resources_only)
        pyver = python_version(sdk)
        validate_loader_packaging(sdk, version, pyver)
        inputs.append((version, sdk, pyver))
    if not args.resources_only:
        validate_platform_rebuild_safety()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    if not args.resources_only:
        platform_is_current = (ARTIFACTS / "RRPlatform.xcframework").exists() and (ARTIFACTS / "RRPlatform.xcframework").stat().st_mtime >= max(path.stat().st_mtime for path in platform_inputs())
        build_platform(fetch("8.5.3", native=not platform_is_current))
    for version, sdk, pyver in inputs:
        resources(sdk, version, pyver)
        if not args.resources_only:
            build_core(sdk, version, pyver)
            refresh_native_provenance(version)
        if args.prune_cache:
            prune_inputs(version)
    patch_existing()
    if "8.5.3" in versions:
        enable_verified_overlay_853_after_build()
    write_catalog()
    from overlay_capability_guard import check as check_overlay_capability
    check_overlay_capability(ROOT, json.loads((KIT / "Patches/overlay-capability-853.json").read_bytes()))


if __name__ == "__main__":
    main()
