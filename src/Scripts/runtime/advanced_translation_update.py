#!/usr/bin/env python3
"""Stage and verify an additive host update without weakening prior runtime seals."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ("7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.3.7", "8.4.1", "8.5.3")
RELATIVE = Path("RuntimeKit/Validation/SparkParity20261104/AdvancedTranslation")
HELPER = Path("RuntimeKit/Candidates/SparkParity20261104/rr_advanced_translation.py")
BUILD_HOST_BYTECODE = {"8.5.3": {"__pycache__/rr_script_identity.cpython-314.pyc"}}
EVIDENCE_HASHES = {'verification.json': '0efb21ed970c5fe393dcae1d032fb26d31bd4813957b6a6ba519f2cb08dfe56f', 'inputs.json': '1caf11dfbdf4869b035ce1c61c6e5079636eda83cfc6a2b2938aba1b2e248330', 'warm.events.ndjson': '3ce0a44d3d8077a15edefdec12e03a6a7e929e20dbccf65e9a88b5cc5c655815', 'cold.events.ndjson': '9ae315f743b803a744914cb43a348ae375e1f007eff8eec8d6e3762669a364bc'}


def verify_evidence(root, version, bundle):
    directory = root / RELATIVE / "RuntimeFrozenHelper"
    if set(EVIDENCE_HASHES) != {"verification.json", "inputs.json", "warm.events.ndjson", "cold.events.ndjson"}:
        raise ValueError("Final translation matrix has not been registered")
    for name, value in EVIDENCE_HASHES.items():
        if sha(directory / name) != value:
            raise ValueError("Final translation matrix evidence changed")
    inputs = json.loads((directory / "inputs.json").read_bytes())
    resource = inputs["resources"][version]
    for relative, value in resource.items():
        path = {"hostSHA256": "base/rr_host.py", "helperSHA256": "base/rr_advanced_translation.py", "profileSHA256": "runtime-profile.json"}[relative]
        if sha(bundle / path) != value:
            raise ValueError("Translation matrix used another host or helper")
    for relative, value in inputs["sources"].items():
        if sha(root / relative) != value:
            if __package__:
                from .advanced_translation17_update import SOURCE_PREDECESSORS, verify_source_successor
            else:
                from advanced_translation17_update import SOURCE_PREDECESSORS, verify_source_successor
            if relative in SOURCE_PREDECESSORS:
                verify_source_successor(root, relative, value)
                continue
            if relative != "RuntimeKit/Bridge/RRRuntimeBridge.m":
                raise ValueError("Translation matrix input source changed: " + relative)
            if __package__:
                from .story_repair_update import verify_bridge
            else:
                from story_repair_update import verify_bridge
            verify_bridge(root, expected_previous=value)
    report = json.loads((directory / "verification.json").read_bytes())
    results = report.get("results", [])
    if report.get("passed") is not True or len(results) != 2 or len({r.get("processID") for r in results}) != 2:
        raise ValueError("Translation matrix lacks an independent cold process")
    expected = {(v, mode) for v in VERSIONS for mode in ("enhanced", "minimal", "nativeCompatibility")}
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in (directory / (phase + ".events.ndjson")).read_text().splitlines() if line]
        validated = [r for r in rows if r.get("type") == "translationProbeValidated"]
        ocr = [r for r in rows if r.get("type") == "nativeOCRPassed"]
        passed = [r for r in rows if r.get("type") == "translationProbePassed"]
        if len(validated) != 33 or {(r["runtime"], r["mode"]) for r in validated} != expected or len(ocr) != 22:
            raise ValueError("Translation matrix or OCR coverage is incomplete")
        if len(passed) != 1 or passed[0].get("sessions") != 33 or passed[0].get("failures") != 0:
            raise ValueError("Translation matrix did not pass")
        if any(r.get("type") in {"probeFailure", "translationProbeFailed", "gameError", "saveFailed"} for r in rows):
            raise ValueError("Translation matrix contains an execution failure")


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or linked translation input: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_bytes(previous):
    source = previous.decode("utf-8")
    if '"advancedTranslation"' in source or '__import__("rr_advanced_translation")' in source:
        raise ValueError("Advanced translation is already installed")
    marker = '    if kind == "galleryUnlock":\n'
    dispatch = '    if kind in ("captureTranslationFrame", "collectTranslationScript"):\n        _advanced_translation_handle(request, renpy, emit)\n        return\n'
    capability = '"inlineTranslation": enabled,'
    imports = 'from pyobjus import autoclass\n'
    if source.count(marker) != 1 or source.count(capability) != 1 or source.count(imports) != 1:
        raise ValueError("Host dispatch or capability boundary changed")
    return source.replace(imports, 'from rr_advanced_translation import handle as _advanced_translation_handle\n' + imports, 1).replace(marker, dispatch + marker, 1).replace(capability, capability + ' "advancedTranslation": enabled,', 1).encode("utf-8")


def files(base):
    result = {}
    for path in base.rglob("*"):
        if path.is_symlink():
            raise ValueError("Linked translation resource")
        if path.is_file():
            result[path.relative_to(base).as_posix()] = (path.stat().st_size, sha(path))
    return result


def fingerprint(base):
    digest = hashlib.sha256()
    for name, (size, value) in sorted(files(base).items()):
        digest.update(("%d:%s:%d:%s\n" % (len(name.encode()), name, size, value)).encode())
    return digest.hexdigest()


def bundle_metadata(directory):
    result = {}
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if not relative.startswith("base/") and relative not in ("runtime-profile.json", "provenance.json") and path.is_file():
            result[relative] = (path.stat().st_size, sha(path))
    return result


def verify(root, version, bundle):
    if json.loads((bundle / "runtime-profile.json").read_bytes()).get("scriptTranslationPagingSchemaVersion") == 1:
        if __package__:
            from .advanced_translation17_update import verify_runtime_successor
        else:
            from advanced_translation17_update import verify_runtime_successor
        baseline, modules = verify_runtime_successor(root, version, bundle)
        if version in modules['prior_advanced']:
            return modules['prior_advanced'][version]
        previous = baseline / "RuntimeKit/Artifacts" / bundle.name
        return previous, json.loads((previous / "runtime-profile.json").read_bytes())
    if version == "8.5.3" and json.loads((bundle / "runtime-profile.json").read_bytes()).get("storySessionPatchSchemaVersion") == 2:
        if __package__:
            from .story_repair_update import verify as verify_story_repair
        else:
            from story_repair_update import verify as verify_story_repair
        bundle = verify_story_repair(root, bundle)
    record_path = root / RELATIVE / "identity.json"
    record = json.loads(record_path.read_bytes())
    item = record["runtimes"][version]
    previous = root / RELATIVE / "previous" / bundle.name
    if sha(record_path) != EXPECTED_IDENTITY_SHA256 or sha(root / HELPER) != record["helperSHA256"]:
        raise ValueError("Advanced translation acceptance inputs changed")
    predecessors = item.get("compatibleAdvancedPredecessors", [])
    if predecessors:
        retained = root / RELATIVE / ("provenance" + version.replace(".", "") + "-before-cache-removal.json")
        if version != "8.5.3" or predecessors != [sha(retained)]:
            raise ValueError("Unverified intermediate translation predecessor")
    for name in ("provenance.json", "runtime-profile.json"):
        if sha(previous / name) != item["previous"][name]:
            raise ValueError("Previous runtime metadata changed")
    before = files(previous / "base")
    after = files(bundle / "base")
    expected = dict(before)
    new_host = host_bytes((previous / "base/rr_host.py").read_bytes())
    expected["rr_host.py"] = (len(new_host), hashlib.sha256(new_host).hexdigest())
    helper = root / HELPER
    expected[helper.name] = (helper.stat().st_size, sha(helper))
    removed = item.get("removedBuildHostBytecode", {})
    if set(removed) - BUILD_HOST_BYTECODE.get(version, set()):
        raise ValueError("Unapproved runtime resource removal")
    for relative, identity in removed.items():
        if before.get(relative) != tuple(identity) or (previous / "base" / relative).read_bytes()[:4] == b"\xcb\r\r\n":
            raise ValueError("Removed cache does not match the retained wrong-ABI input")
        expected.pop(relative)
    if before != item["previousFiles"] and {k: list(v) for k, v in before.items()} != item["previousFiles"]:
        raise ValueError("Previous resource tree changed")
    if after != expected or sha(bundle / "provenance.json") != item["current"]["provenance.json"]:
        raise ValueError("Advanced translation modified an unrelated runtime file")
    directories = lambda directory: {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_dir()}
    expected_directories = directories(previous)
    if removed and not any(k.startswith("__pycache__/") for k in expected): expected_directories.discard("base/__pycache__")
    if bundle_metadata(bundle) != bundle_metadata(previous) or directories(bundle) != expected_directories:
        raise ValueError("Advanced translation modified runtime packaging")
    profile = json.loads((bundle / "runtime-profile.json").read_bytes())
    baseline = json.loads((previous / "runtime-profile.json").read_bytes())
    if profile != dict(baseline, advancedTranslationSchemaVersion=1):
        raise ValueError("Advanced translation changed another capability")
    verify_evidence(root, version, bundle)
    return previous, baseline


EXPECTED_IDENTITY_SHA256 = "5858abc00b0456a635bfd6abb7ab9cd4ad287cc20f28601e175ddc3d478c7b0d"


def stage():
    folder = ROOT / RELATIVE
    previous, staged = folder / "previous", folder / "stage"
    record = {"schemaVersion": 1, "status": "candidate", "helperSHA256": sha(ROOT / HELPER), "runtimes": {}}
    for version in VERSIONS:
        name = "RenPy" + version.replace(".", "") + ".bundle"
        source = ROOT / "RuntimeKit/Artifacts" / name
        old, new = previous / name, staged / name
        if new.exists():
            raise ValueError("Staging already exists; preserve its evidence: " + name)
        for target in (old, new):
            if target == old and old.exists():
                if files(old / "base") != files(source / "base") or any(sha(old / n) != sha(source / n) for n in ("provenance.json", "runtime-profile.json")):
                    raise ValueError("Retained predecessor is not the current production runtime")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["cp", "-cR", str(source), str(target)], check=True)
        (new / "base/rr_host.py").write_bytes(host_bytes((old / "base/rr_host.py").read_bytes()))
        shutil.copy2(ROOT / HELPER, new / "base/rr_advanced_translation.py")
        profile = json.loads((old / "runtime-profile.json").read_bytes())
        profile["advancedTranslationSchemaVersion"] = 1
        (new / "runtime-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
        provenance = json.loads((old / "provenance.json").read_bytes())
        provenance["advancedTranslation"] = {"schemaVersion": 1, "previousProvenanceSHA256": sha(old / "provenance.json"),
            "helperSHA256": sha(ROOT / HELPER), "hostSHA256": sha(new / "base/rr_host.py"), "status": "simulator-validation-pending"}
        (new / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
        record["runtimes"][version] = {"previous": {n: sha(old / n) for n in ("provenance.json", "runtime-profile.json")},
            "current": {n: sha(new / n) for n in ("provenance.json", "runtime-profile.json")},
            "previousFiles": files(old / "base"), "currentBaseFingerprint": fingerprint(new / "base")}
    (folder / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("Staged all eleven runtimes; no production resources changed.")


def refresh_stage():
    folder = ROOT / RELATIVE
    record_path = folder / "identity.json"
    record = json.loads(record_path.read_bytes())
    backup = folder / ("prior-stage-" + sha(record_path)[:12])
    backup.mkdir(exist_ok=False)
    shutil.copy2(record_path, backup / record_path.name)
    record["helperSHA256"] = sha(ROOT / HELPER)
    for version, item in record["runtimes"].items():
        name = "RenPy" + version.replace(".", "") + ".bundle"
        previous, target = folder / "previous" / name, folder / "stage" / name
        saved = backup / name; saved.mkdir()
        for path in ("provenance.json", "runtime-profile.json", "base/rr_host.py", "base/rr_advanced_translation.py"):
            destination = saved / path; destination.parent.mkdir(exist_ok=True)
            shutil.copy2(target / path, destination)
        if sha(target / "provenance.json") != item["current"]["provenance.json"]:
            raise ValueError("Existing staged provenance changed")
        host = host_bytes((previous / "base/rr_host.py").read_bytes())
        (target / "base/rr_host.py").write_bytes(host)
        shutil.copy2(ROOT / HELPER, target / "base/rr_advanced_translation.py")
        provenance = json.loads((target / "provenance.json").read_bytes())
        provenance["advancedTranslation"].update(helperSHA256=record["helperSHA256"], hostSHA256=sha(target / "base/rr_host.py"))
        (target / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
        item["current"]["provenance.json"] = sha(target / "provenance.json")
        entries = dict(item["previousFiles"])
        entries["rr_host.py"] = [len(host), sha(target / "base/rr_host.py")]
        helper = target / "base/rr_advanced_translation.py"
        entries[helper.name] = [helper.stat().st_size, sha(helper)]
        digest = hashlib.sha256()
        for path, (size, value) in sorted(entries.items()):
            digest.update(("%d:%s:%d:%s\n" % (len(path.encode()), path, size, value)).encode())
        item["currentBaseFingerprint"] = digest.hexdigest()
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("Refreshed staged host/helper; previous candidate metadata retained.")


def promote():
    folder = ROOT / RELATIVE
    record = json.loads((folder / "identity.json").read_bytes())
    catalog_path = ROOT / "RuntimeKit/Artifacts/runtime-catalog.json"
    catalog = json.loads(catalog_path.read_bytes())
    if any(p.get("storySessionPatchSchemaVersion") == 2 for p in catalog["profiles"]):
        raise ValueError("A qualified story successor is installed; do not overwrite it with its translation predecessor")
    service_path = ROOT / "App/Services/Import/EngineOverlayService.swift"
    service = service_path.read_text()
    pattern = r'\.init\(runtimeID:\s*"([^"]+)",\s*previousProvenanceSHA256:\s*"([a-f0-9]+)",\s*currentProvenanceSHA256:\s*"([a-f0-9]+)",\s*currentBaseFingerprint:\s*"([a-f0-9]+)"\)'
    prior_updates = re.findall(pattern, service)
    mapped = r'\[\s*((?:"[a-f0-9]{64}"\s*,?\s*)+)\]\.map\s*\{\s*\.init\(runtimeID:\s*"([^"]+)",\s*previousProvenanceSHA256:\s*\$0,\s*currentProvenanceSHA256:\s*"([a-f0-9]+)",\s*currentBaseFingerprint:\s*"([a-f0-9]+)"\)'
    for values, runtime, current, base in re.findall(mapped, service):
        prior_updates.extend((runtime, old, current, base) for old in re.findall(r'"([a-f0-9]{64})"', values))
    tuples = r'\(runtime:\s*"([^"]+)",\s*previous:\s*\[([^\]]+)\],\s*current:\s*"([a-f0-9]+)",\s*base:\s*"([a-f0-9]+)"\)'
    for runtime, values, current, base in re.findall(tuples, service):
        prior_updates.extend((runtime, old, current, base) for old in re.findall(r'"([a-f0-9]{64})"', values))
    updates = []
    for version in VERSIONS:
        item = record["runtimes"][version]
        name = "RenPy" + version.replace(".", "") + ".bundle"
        candidate = folder / "stage" / name
        verify(ROOT, version, candidate)
        previous_hash = item["previous"]["provenance.json"]
        accepted = {previous_hash} | set(item.get("compatibleAdvancedPredecessors", [])) | {old for runtime, old, current, _ in prior_updates if runtime == "renpy-" + version and current == previous_hash}
        for old in sorted(accepted):
            updates.append('        .init(runtimeID: "renpy-%s", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' %
                (version, old, item["current"]["provenance.json"], item["currentBaseFingerprint"]))
    generated = '// Generated from the verified additive host delta and its predecessor acceptances.\nimport Foundation\n\nenum SparkParityEngineUpdates {\n    static let values: [EngineOverlayCompatibleUpdate] = [\n' + ',\n'.join(updates) + '\n    ]\n}\n'
    (ROOT / "App/Services/Import/SparkParityEngineUpdates.swift").write_text(generated)
    # The published table is a composition of literals and mapped history.
    # Append once to that table, never to one of its private sub-tables.
    service = service.replace('] + SparkParityEngineUpdates.values\n}', ']\n}')
    marker = '    } + progressRemaining + dialogueSegmentsRemaining'
    if marker not in service:
        raise ValueError("Engine update registry boundary changed")
    if marker + ' + SparkParityEngineUpdates.values' not in service:
        service = service.replace(marker, marker + ' + SparkParityEngineUpdates.values', 1)
    service_path.write_text(service)
    backup = folder / "previous-notices"; backup.mkdir(exist_ok=True)
    for version in VERSIONS:
        name = "RenPy" + version.replace(".", "") + ".bundle"
        candidate, target = folder / "stage" / name, ROOT / "RuntimeKit/Artifacts" / name
        for relative in ("base/rr_host.py", "base/rr_advanced_translation.py", "runtime-profile.json", "provenance.json"):
            temporary = (target / relative).with_name((target / relative).name + ".parity-pending")
            shutil.copy2(candidate / relative, temporary); temporary.replace(target / relative)
        for relative, identity in record["runtimes"][version].get("removedBuildHostBytecode", {}).items():
            cache = target / "base" / relative
            if cache.exists():
                if (cache.stat().st_size, sha(cache)) != tuple(identity): raise ValueError("Cache changed before removal")
                cache.unlink()
                if not any(cache.parent.iterdir()): cache.parent.rmdir()
        notice = ROOT / "RuntimeKit/Notices" / ("renpy-" + version + "-provenance.json")
        if notice.exists() and not (backup / notice.name).exists(): shutil.copy2(notice, backup / notice.name)
        shutil.copy2(target / "provenance.json", notice)
        profile = json.loads((target / "runtime-profile.json").read_bytes())
        for row in catalog["profiles"]:
            if row["runtimeID"] == version: row.update(profile)
    temporary = catalog_path.with_name(catalog_path.name + ".parity-pending")
    temporary.write_text(json.dumps(catalog, indent=2) + "\n"); temporary.replace(catalog_path)
    print("Promoted the verified additive translation host in eleven runtimes; retained all other catalog entries.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--stage", action="store_true"); parser.add_argument("--refresh-stage", action="store_true"); parser.add_argument("--promote", action="store_true")
    options = parser.parse_args()
    if options.stage:
        stage()
    elif options.refresh_stage:
        refresh_stage()
    elif options.promote:
        promote()
