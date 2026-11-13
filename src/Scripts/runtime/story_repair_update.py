"""A separately qualified successor to the frozen advanced-translation host.

Only this small host/bootstrap/hook delta and the exact bridge admission block
can change. Prior runtime/translation certificates remain mandatory.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path("RuntimeKit/Candidates/BuiltinStoryCompiledEdition20261104")
RELATIVE = Path("RuntimeKit/Validation/BuiltinStoryCompiledEdition20261104")
CERTIFICATE = Path("RuntimeKit/Patches/story-repair-edition-20261104.json")
# The successor stays closed until its new warm/cold matrices are accepted.
CERTIFICATE_SHA256 = "f6d3671ecb6b4093a19b1721ef39287e4f7346f06468db20f4f4df0f4fa4911e"
INITIAL_RELATIVE = Path("RuntimeKit/Validation/BuiltinStoryCompiledEditionInitialLoadAdapter20261104")
INITIAL_CERTIFICATE_SHA256 = "e320c6baef2cc240f60596ef7550c34735458eaff089b87abdaee612d3dc4e43"
INITIAL_GUARD_SHA256 = "fe9123b001ac5efbb95c332c693e981565c835743c5d1fb4bc19fdde6520dcb6"
INITIAL_RETENTION_SHA256 = "ef4d5f024789b20add8cd5e847def9b0db27391d6bb821551d914eda0bd49c26"
BUNDLE = "RenPy853.bundle"
FILES = {"rr_host.py": "base/rr_host.py", "rr_story_patch.py": "base/rr_story_patch.py",
         "bootstrap853.py": "base/renpy/bootstrap.py", "rr_advanced_translation.py": "base/rr_advanced_translation.py"}


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or linked story repair input: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(directory):
    result = {}
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("Linked story repair resource")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = [path.stat().st_size, sha(path)]
    return result


def fingerprint(directory):
    digest = hashlib.sha256()
    for name, (size, value) in sorted(files(directory).items()):
        digest.update(("%d:%s:%d:%s\n" % (len(name.encode()), name, size, value)).encode())
    return digest.hexdigest()


def initial_state(root):
    """Replay the exact old proof against its own immutable relative root."""
    history = root / INITIAL_RELATIVE
    path = history / "Scripts/runtime/story_repair_update.py"
    summary_path = history / "retention-summary.json"
    if (sha(path) != INITIAL_GUARD_SHA256 or sha(history / CERTIFICATE) != INITIAL_CERTIFICATE_SHA256
            or sha(summary_path) != INITIAL_RETENTION_SHA256):
        raise ValueError("Initial load adapter qualification changed")
    summary = json.loads(summary_path.read_bytes())
    if sha(history / "App/Services/Import/SparkParityEngineUpdates.swift") != summary["registry76SHA256"]:
        raise ValueError("Initial load adapter registry changed")
    spec = importlib.util.spec_from_file_location("initial_load_adapter_frozen_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, history, module.certificate(history)


def certificate(root):
    path = root / CERTIFICATE
    if CERTIFICATE_SHA256 is None or sha(path) != CERTIFICATE_SHA256:
        raise ValueError("Compiled story repair certificate is missing or changed")
    value = json.loads(path.read_bytes())
    if value.get("schemaVersion") != 2 or value.get("status") != "simulatorWarmColdPassed":
        raise ValueError("Compiled story repair has not passed qualification")
    _, history, initial = initial_state(root)
    expected_initial = {"certificateSHA256": INITIAL_CERTIFICATE_SHA256,
        "provenanceSHA256": initial["currentFiles"]["provenance.json"][1],
        "registrySHA256": sha(history / "App/Services/Import/SparkParityEngineUpdates.swift")}
    if value.get("initialLoadAdapter") != expected_initial or value["previousFiles"] != initial["previousFiles"]:
        raise ValueError("Story successor changed its qualified predecessor")
    for relative, expected in value["inputs"].items():
        if sha(root / relative) != expected:
            if __package__:
                from .advanced_translation17_update import SOURCE_PREDECESSORS, verify_source_successor
            else:
                from advanced_translation17_update import SOURCE_PREDECESSORS, verify_source_successor
            if relative in SOURCE_PREDECESSORS:
                verify_source_successor(root, relative, expected)
                continue
            raise ValueError("Compiled story repair input changed: " + relative)
    for item in value["evidence"].values():
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or sha(root / relative) != item["sha256"]:
            raise ValueError("Compiled story repair evidence changed")
    verify_evidence(root, value)
    return value


def evidence_json(root, record, name):
    return json.loads((root / record["evidence"][name]["path"]).read_bytes())


def evidence_rows(root, record, name):
    return [json.loads(line) for line in (root / record["evidence"][name]["path"]).read_text().splitlines() if line]


def verify_menu_evidence(rows, expected, phase):
    def key(row):
        return row.get("sessionID"), row.get("epoch"), row.get("fingerprint"), row.get("mode")
    ready = [r for r in rows if r.get("type") == "ready"]
    keys = {key(r) for r in ready}
    if (len(ready) != 24 or len(keys) != 24 or any(not isinstance(k[0], str) or not k[0]
            or type(k[1]) is not int or k[1] < 1 for k in keys)
            or Counter((r.get("fingerprint"), r.get("mode")) for r in ready) != expected
            or any(r.get("capabilities", {}).get("titlePatches") is not (r.get("mode") == "enhanced") for r in ready)):
        raise ValueError("Compiled edition native menu capability coverage changed")
    hooks = [r for r in rows if r.get("type") == "freshStoryHooks"]
    fields = ("menuPrepared", "callbackRegistered", "mainMenuLabel", "saveScreenLabel", "loadScreenLabel", "showMenuSensitive")
    # Start/load can legitimately invoke after_default again in one session.
    if {key(r) for r in hooks} != keys or any(r.get(field) is not (r.get("mode") == "enhanced") for r in hooks for field in fields):
        raise ValueError("Compiled edition menu initialization or mode isolation changed")
    entered = [r for r in rows if r.get("type") == "compiledReadingEntered"]
    if len(entered) != 24 or {key(r) for r in entered} != keys or any(r.get("mainMenu") is not False or r.get("sayVisible") is not True for r in entered):
        raise ValueError("Compiled edition did not reach each actual reading screen")
    starts = [r for r in rows if r.get("type") == "compiledMenuStartRequested"]
    fingerprints = {fp for fp, _ in expected}
    if (len(starts) != (6 if phase == "warm" else 0)
            or (phase == "warm" and {r.get("fingerprint") for r in starts} != fingerprints)
            or any(key(r) not in keys or r.get("mode") != "enhanced" or r.get("mainMenuVisible") is not True or r.get("actionSensitive") is not True for r in starts)):
        raise ValueError("Compiled edition native Start action was not exercised")
    closed = [r for r in rows if r.get("type") == "freshStoryLeaseClosed"]
    if ({key(r) for r in closed} != keys or any(r.get(field) is not True for r in closed
            for field in ("menuPreparationAbsent", "menuCallbackAbsent", "menuCallbackReferenceReleased"))):
        raise ValueError("Compiled edition retained its menu initialization callback")


def verify_evidence(root, record):
    identity = json.loads((root / CANDIDATE / "identity.json").read_bytes())
    expected = Counter({(fp, mode): 2 if mode == "enhanced" else 1
                        for fp in identity["fingerprints"].values()
                        for mode in ("enhanced", "minimal", "nativeCompatibility")})
    report = evidence_json(root, record, "compiledVerification")
    if report.get("passed") is not True or report.get("realProductionHelperAndIdentityCallback") is not True or report.get("sameNameGameHelperDidNotExecute") is not True:
        raise ValueError("Compiled edition default-path matrix is incomplete")
    processes = []
    for phase in ("warm", "cold"):
        rows = evidence_rows(root, record, "compiled" + phase.title())
        passed = [row for row in rows if row.get("type") == "compiledProbePassed"]
        validated = [row for row in rows if row.get("type") == "compiledSessionValidated"]
        identities = [row for row in rows if row.get("type") == "compiledIdentityVerified"]
        actions = [row for row in rows if row.get("type") == "freshStoryActionReadback"]
        if len(passed) != 1 or passed[0].get("failures") != 0 or passed[0].get("sessions") != 24 or Counter((r.get("fingerprint"), r.get("mode")) for r in validated) != expected:
            raise ValueError("Compiled edition warm/cold session coverage changed")
        if any(r.get("value") != 73 or r.get("patchActive") is not (r.get("mode") == "enhanced") or (phase == "cold" and r.get("restored") != 1) for r in validated):
            raise ValueError("Compiled edition failed save recovery or mode isolation")
        if len(identities) != 24 or any(r.get("sidecarAbsent") is not True or r.get("captureCount", 0) < 1 for r in identities):
            raise ValueError("Compiled-only original identity was not verified")
        if len(actions) != 24 or any(r.get("patchActive") is not (r.get("mode") == "enhanced") or r.get("quickAvailable") is not (r.get("mode") == "enhanced") or r.get("regularAvailable") is not (r.get("mode") == "enhanced") or r.get("quickSlot") != ("quick-1" if r.get("mode") == "enhanced" else "quick") for r in actions):
            raise ValueError("Compiled edition changed authored load action semantics")
        audits = [r for r in rows if r.get("type") == "threadAudit"]
        queues = [r for r in rows if r.get("type") == "eventQueueCleanupSummary"]
        closed = [r for r in rows if r.get("type") == "freshStoryLeaseClosed"]
        if len(audits) != 24 or any(r.get("remaining") != [] for r in audits) or len(queues) != 24 or any(r.get("succeeded") is not True or r.get("errors") != [] for r in queues) or len(closed) < 24 or any(r.get("leaseAbsent") is not True or r.get("queryOwnerAbsent") is not True for r in closed):
            raise ValueError("Compiled edition did not release its session state")
        verify_menu_evidence(rows, expected, phase)
        processes.append(passed[0].get("processID"))
    if None in processes or len(set(processes)) != 2:
        raise ValueError("Compiled edition cold matrix reused a process")
    cache = evidence_json(root, record, "compiledCacheRebuild")
    if cache.get("removedReconstructibleWorkspaces") != 24 or cache.get("profilesAndCompiledInstallationsUnchanged") is not True:
        raise ValueError("Compiled edition cache deletion was not independent of progress")
    negative = evidence_json(root, record, "negativeVerification")
    old_rows = evidence_rows(root, record, "negativeEvents")
    old = [r for r in old_rows if r.get("type") == "oldSourceTokenChecked"]
    if negative.get("passed") is not True or negative.get("interpreterStarted") is not False or negative.get("final", {}).get("positivePreparationAccepted") is not True or len(old) != 6 or {r.get("fingerprint") for r in old} != set(identity["fingerprints"]) or any(r.get("rejectedByIdentityGate") is not True for r in old) or any(r.get("type") in {"ready", "firstFrameDrawn", "threadBaseline"} for r in old_rows):
        raise ValueError("Old source namespaces were not independently rejected")
    versions = {"7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.3.7", "8.4.1", "8.5.3"}
    expected_advanced = {(version, mode) for version in versions for mode in ("enhanced", "minimal", "nativeCompatibility")}
    advanced_processes = []
    for phase in ("warm", "cold"):
        rows = evidence_rows(root, record, "advanced" + phase.title())
        validated = [r for r in rows if r.get("type") == "translationProbeValidated"]
        passed = [r for r in rows if r.get("type") == "translationProbePassed"]
        ready = [r for r in rows if r.get("type") == "ready"]
        if len(validated) != 33 or {(r.get("runtime"), r.get("mode")) for r in validated} != expected_advanced or len([r for r in rows if r.get("type") == "nativeOCRPassed"]) != 22 or len(passed) != 1 or passed[0].get("failures") != 0:
            raise ValueError("Successor host failed the advanced translation regression")
        if (len(ready) != 33 or {(r.get("runtime"), r.get("mode")) for r in ready} != expected_advanced
                or any(r.get("capabilities", {}).get("titlePatches") is not False for r in ready)
                or any(r.get("type") == "freshStoryHooks" for r in rows)):
            raise ValueError("Ordinary translation sessions acquired a story menu hook")
        if any(r.get("type") in {"probeFailure", "translationProbeFailed", "gameError", "saveFailed"} for r in rows):
            raise ValueError("Successor host regression contains a failure")
        advanced_processes.append(passed[0].get("processID"))
    if None in advanced_processes or len(set(advanced_processes)) != 2:
        raise ValueError("Translation regression did not use independent processes")
    advanced_report = evidence_json(root, record, "advancedVerification")
    if advanced_report.get("passed") is not True:
        raise ValueError("Successor advanced regression did not finish")
    for name in ("compiledInputs", "advancedInputs"):
        observed = evidence_json(root, record, name)
        for relative, expected_sha in observed["sources"].items():
            if sha(root / relative) != expected_sha:
                if __package__:
                    from .advanced_translation17_update import SOURCE_PREDECESSORS, verify_source_successor
                else:
                    from advanced_translation17_update import SOURCE_PREDECESSORS, verify_source_successor
                if relative in SOURCE_PREDECESSORS:
                    verify_source_successor(root, relative, expected_sha)
                    continue
                if relative != "App/Services/Import/CompiledScriptValidation.swift":
                    raise ValueError("Observed compiled source changed: " + relative)
                if __package__:
                    from .nightly_profile_guard import verify_compiler_validation_delta
                else:
                    from nightly_profile_guard import verify_compiler_validation_delta
                verify_compiler_validation_delta(root, expected_sha)
    observed = evidence_json(root, record, "compiledInputs")
    if observed["candidateIdentity"] != identity or observed["privateBridgeSHA256"] != record["bridgeSHA256"]:
        raise ValueError("Matrix used another repair candidate")
    advanced = evidence_json(root, record, "advancedInputs")["resources"]["8.5.3"]
    if advanced != {"hostSHA256": identity["candidateSHA256"]["rr_host.py"],
                    "helperSHA256": identity["candidateSHA256"]["rr_advanced_translation.py"],
                    "rr_story_patch.pySHA256": identity["candidateSHA256"]["rr_story_patch.py"],
                    "profileSHA256": record["currentFiles"]["runtime-profile.json"][1]}:
        raise ValueError("Advanced regression used another successor host")
    negative_inputs = evidence_json(root, record, "negativeInputs")
    for relative, expected_sha in negative_inputs["source"].items():
        if sha(root / relative) != expected_sha:
            raise ValueError("Old namespace negative source changed")
    if negative_inputs["nativeBridgeSourceSHA256"] != record["bridgeSHA256"] or negative_inputs["matrixInputsSHA256"] != record["evidence"]["compiledInputs"]["sha256"]:
        raise ValueError("Old namespace negative used another native admission block")


def verify_bridge(root, expected_previous=None, *, bridge=None):
    # Menu preparation changes no native byte. Retain the old narrow admission
    # proof instead of letting a new host certificate bless another Bridge.
    frozen, history, _ = initial_state(root)
    actual = bridge or root / "RuntimeKit/Bridge/RRRuntimeBridge.m"
    if __package__:
        from .nightly_profile_guard import PREVIOUS_BRIDGE_SHA256, previous_bridge, successor_bridge_bytes, verify_bridge_delta
    else:
        from nightly_profile_guard import PREVIOUS_BRIDGE_SHA256, previous_bridge, successor_bridge_bytes, verify_bridge_delta
    if sha(actual) == PREVIOUS_BRIDGE_SHA256:
        frozen.verify_bridge(history, expected_previous, bridge=actual)
        return
    predecessor = previous_bridge(root)
    if actual.read_bytes() != successor_bridge_bytes(predecessor.read_bytes()):
        # Preserve the exact historical failure for every unrelated change.
        frozen.verify_bridge(history, expected_previous, bridge=actual)
        return
    frozen.verify_bridge(history, expected_previous, bridge=predecessor)
    verify_bridge_delta(root, actual)


def verify(root, bundle, *, bridge=None):
    if json.loads((bundle / "runtime-profile.json").read_bytes()).get("scriptTranslationPagingSchemaVersion") == 1:
        if __package__:
            from .advanced_translation17_update import verify_runtime_successor
        else:
            from advanced_translation17_update import verify_runtime_successor
        baseline, _, = verify_runtime_successor(root, "8.5.3", bundle, bridge=bridge)
        return baseline / "RuntimeKit/Validation/BuiltinStoryCompiledEdition20261104/previous/RenPy853.bundle"
    frozen, history, initial = initial_state(root)
    if sha(bundle / "provenance.json") == initial["currentFiles"]["provenance.json"][1]:
        frozen.verify(history, bundle, bridge=bridge or root / "RuntimeKit/Bridge/RRRuntimeBridge.m")
        if bridge is None and (root / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes() != (history / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes():
            raise ValueError("Initial load adapter registry changed")
        previous = root / RELATIVE / "previous" / BUNDLE
        if files(previous) != initial["previousFiles"]:
            raise ValueError("Initial load adapter translation predecessor changed")
        return previous
    record = certificate(root)
    verify_bridge(root, bridge=bridge)
    previous = root / RELATIVE / "previous" / BUNDLE
    if files(previous) != record["previousFiles"]:
        raise ValueError("Story repair predecessor changed")
    expected = files(previous)
    for name, relative in FILES.items():
        source = root / CANDIDATE / name
        expected[relative] = [source.stat().st_size, sha(source)]
    expected["runtime-profile.json"] = record["currentFiles"]["runtime-profile.json"]
    expected["provenance.json"] = record["currentFiles"]["provenance.json"]
    if files(bundle) != expected:
        raise ValueError("Story repair modified an unrelated runtime resource")
    directories = lambda p: {item.relative_to(p).as_posix() for item in p.rglob("*") if item.is_dir()}
    if directories(bundle) != directories(previous) or fingerprint(bundle / "base") != record["currentBaseFingerprint"]:
        raise ValueError("Story repair changed runtime packaging")
    old_profile = json.loads((previous / "runtime-profile.json").read_bytes())
    actual_profile = json.loads((bundle / "runtime-profile.json").read_bytes())
    if json.dumps(actual_profile, sort_keys=True) != json.dumps(dict(old_profile, storySessionPatchSchemaVersion=2), sort_keys=True):
        raise ValueError("Story repair changed another runtime capability")
    if bridge is None:
        retained = root / RELATIVE / "previous-SparkParityEngineUpdates.swift"
        current = root / "App/Services/Import/SparkParityEngineUpdates.swift"
        if current.read_bytes() != registry_bytes(root, retained.read_bytes(), record):
            raise ValueError("Story successor engine-overlay migration registry differs")
    return previous


def registry_bytes(root, previous, record):
    frozen, history, initial = initial_state(root)
    retained = history / RELATIVE / "previous-SparkParityEngineUpdates.swift"
    if previous != retained.read_bytes() or record["previousFiles"] != initial["previousFiles"]:
        raise ValueError("Story registry must retain the exact 75-row translation baseline")
    generated = frozen.registry_bytes(history, previous, record).decode("utf-8")
    before = initial["currentFiles"]["provenance.json"][1]
    after = record["currentFiles"]["provenance.json"][1]
    base = record["currentBaseFingerprint"]
    if before == after:
        raise ValueError("Story successor must differ from its initial load adapter")
    row = '        .init(runtimeID: "renpy-8.5.3", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' % (before, after, base)
    return generated.replace("\n    ]\n}\n", ",\n" + row + "\n    ]\n}\n", 1).encode()


def accept_evidence():
    folder = ROOT / RELATIVE
    stage_record = json.loads((folder / "stage-identity.json").read_bytes())
    identity = json.loads((ROOT / CANDIDATE / "identity.json").read_bytes())
    destination = ROOT / "RuntimeKit/Patches/StoryRepairEdition20261104Evidence"
    destination.mkdir(parents=True, exist_ok=True)
    source_paths = {
        "compiledVerification": folder / "verification.json", "compiledInputs": folder / "inputs.json",
        "compiledWarm": folder / "warm.events.ndjson", "compiledCold": folder / "cold.events.ndjson",
        "compiledCacheRebuild": folder / "cache-rebuild.json",
        "negativeVerification": folder / "NegativeOldSix/verification.json", "negativeInputs": folder / "NegativeOldSix/inputs.json",
        "negativeEvents": folder / "NegativeOldSix/events.ndjson",
        "advancedVerification": folder / "AdvancedRegression/verification.json", "advancedInputs": folder / "AdvancedRegression/inputs.json",
        "advancedWarm": folder / "AdvancedRegression/warm.events.ndjson", "advancedCold": folder / "AdvancedRegression/cold.events.ndjson",
        "advancedAudit": folder / "AdvancedRegression/regression-audit.json"}
    record = dict(stage_record, schemaVersion=2, status="simulatorWarmColdPassed", bridgeSHA256=identity["bridgeSHA256"], evidence={}, inputs={})
    for name, source in source_paths.items():
        target = destination / (name + source.suffix)
        shutil.copy2(source, target)
        record["evidence"][name] = {"path": target.relative_to(ROOT).as_posix(), "sha256": sha(target)}
    paths = [ROOT / CANDIDATE / name for name in ("build_candidate.py", "identity.json", "previous-RRRuntimeBridge.m", "RRRuntimeBridge.m", *FILES)]
    registry = folder / "previous-SparkParityEngineUpdates.swift"
    if not registry.exists(): shutil.copy2(ROOT / "App/Services/Import/SparkParityEngineUpdates.swift", registry)
    paths += [registry, folder / "initial-SparkParityEngineUpdates.swift"]
    paths += [ROOT / "App/Services/Import/BuiltinStoryRepairEdition.swift", ROOT / "App/Services/Import/BuiltinStoryRepairRuntime.swift"]
    paths += [p for p in (ROOT / "App/StoryAssets/RepairSeeds").rglob("*") if p.is_file()]
    for path in paths:
        record["inputs"][path.relative_to(ROOT).as_posix()] = sha(path)
    verify_evidence(ROOT, record)
    target = ROOT / CERTIFICATE
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("Reviewed evidence certificate SHA256=" + sha(target))


def promote():
    record = certificate(ROOT)
    folder = ROOT / RELATIVE
    candidate = folder / "stage" / BUNDLE
    verify(ROOT, candidate, bridge=ROOT / CANDIDATE / "RRRuntimeBridge.m")
    registry = ROOT / "App/Services/Import/SparkParityEngineUpdates.swift"
    previous_registry = (folder / "previous-SparkParityEngineUpdates.swift").read_bytes()
    updated_registry = registry_bytes(ROOT, previous_registry, record)
    frozen, history, initial = initial_state(ROOT)
    initial_registry = (history / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes()
    if registry.read_bytes() not in (initial_registry, updated_registry):
        raise ValueError("Engine-overlay registry changed before story promotion")
    current = ROOT / "RuntimeKit/Artifacts" / BUNDLE
    actual = files(current)
    if actual == initial["currentFiles"]:
        frozen.verify(history, current, bridge=ROOT / "RuntimeKit/Bridge/RRRuntimeBridge.m")
    elif actual != record["currentFiles"]:
        raise ValueError("Runtime changed before story promotion; expected complete qualified initial or successor tree")
    else:
        verify(ROOT, current, bridge=ROOT / "RuntimeKit/Bridge/RRRuntimeBridge.m")
    bridge = ROOT / "RuntimeKit/Bridge/RRRuntimeBridge.m"
    verify_bridge(ROOT, bridge=bridge)
    notice = ROOT / "RuntimeKit/Notices/renpy-8.5.3-provenance.json"
    if sha(notice) not in {initial["currentFiles"]["provenance.json"][1], record["currentFiles"]["provenance.json"][1]}:
        raise ValueError("Runtime notice changed before story promotion")
    for relative in [*FILES.values(), "runtime-profile.json", "provenance.json"]:
        temporary = (current / relative).with_name((current / relative).name + ".story-pending")
        shutil.copy2(candidate / relative, temporary)
        temporary.replace(current / relative)
    # This host-only successor never rewrites the native image it just verified.
    # A separately certified nightly whitelist successor must remain intact.
    temporary = registry.with_name(registry.name + ".story-pending")
    temporary.write_bytes(updated_registry); temporary.replace(registry)
    retained_notice = folder / "previous-notice.json"
    if not retained_notice.exists(): shutil.copy2(notice, retained_notice)
    shutil.copy2(current / "provenance.json", notice)
    catalog_path = ROOT / "RuntimeKit/Artifacts/runtime-catalog.json"
    catalog = json.loads(catalog_path.read_bytes())
    for row in catalog["profiles"]:
        if row["runtimeID"] == "8.5.3": row.update(json.loads((current / "runtime-profile.json").read_bytes()))
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    verify(ROOT, current)
    print("Promoted only the qualified compiled-edition host and exact native admission block.")


def stage():
    folder = ROOT / RELATIVE
    previous, target = folder / "previous" / BUNDLE, folder / "stage" / BUNDLE
    if previous.exists() or target.exists():
        raise ValueError("Story staging exists; preserve its evidence before preparing another generation")
    candidate = ROOT / CANDIDATE
    identity = json.loads((candidate / "identity.json").read_bytes())
    frozen, history, initial = initial_state(ROOT)
    frozen.verify(history, ROOT / "RuntimeKit/Artifacts" / BUNDLE, bridge=ROOT / "RuntimeKit/Bridge/RRRuntimeBridge.m")
    if (ROOT / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes() != (history / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes():
        raise ValueError("Production registry differs from the qualified initial adapter")
    verify_bridge(ROOT)
    if sha(candidate / "RRRuntimeBridge.m") != identity["bridgeSHA256"] or identity["bridgeSHA256"] != initial["bridgeSHA256"]:
        raise ValueError("Menu initialization cannot change native admission")
    source = history / RELATIVE / "previous" / BUNDLE
    if files(source) != initial["previousFiles"]:
        raise ValueError("Frozen translation predecessor tree changed")
    if sha(source / "base/rr_host.py") != "1afde8561f76633e24c2230d09b684ba109bca8ef30452618d1067a66c2829b1":
        raise ValueError("Story repair requires the frozen translation predecessor")
    for destination in (previous, target):
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "-cR", str(source), str(destination)], check=True)
    for name, relative in FILES.items():
        if sha(candidate / name) != identity["candidateSHA256"][name]:
            raise ValueError("Story candidate changed")
        shutil.copy2(candidate / name, target / relative)
    profile = json.loads((target / "runtime-profile.json").read_bytes())
    profile["storySessionPatchSchemaVersion"] = 2
    (target / "runtime-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
    provenance = json.loads((target / "provenance.json").read_bytes())
    provenance["compiledStoryRepair"] = {"schemaVersion": 2, "patchID": identity["patchID"],
        "previousProvenanceSHA256": sha(previous / "provenance.json"),
        "hostSHA256": sha(target / "base/rr_host.py"), "hookSHA256": sha(target / "base/rr_story_patch.py"),
        "compiledFingerprints": sorted(identity["fingerprints"].values()),
        "menuInitialization": "official-layout-defaults-enhanced"}
    (target / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    saved = {"previousFiles": files(previous), "currentFiles": files(target), "currentBaseFingerprint": fingerprint(target / "base"),
             "bridgeSHA256": identity["bridgeSHA256"], "status": "candidate",
             "initialLoadAdapter": {"certificateSHA256": INITIAL_CERTIFICATE_SHA256,
                 "provenanceSHA256": initial["currentFiles"]["provenance.json"][1],
                 "registrySHA256": sha(history / "App/Services/Import/SparkParityEngineUpdates.swift")}}
    shutil.copy2(history / RELATIVE / "previous-SparkParityEngineUpdates.swift", folder / "previous-SparkParityEngineUpdates.swift")
    shutil.copy2(history / "App/Services/Import/SparkParityEngineUpdates.swift", folder / "initial-SparkParityEngineUpdates.swift")
    (folder / "stage-identity.json").write_text(json.dumps(saved, indent=2, sort_keys=True) + "\n")
    print("Staged compiled-only story repair; production resources and native gate unchanged.")


def refresh_stage():
    """Preserve an unqualified stage before replacing only its four named files."""
    if CERTIFICATE_SHA256 is not None and sha(ROOT / CERTIFICATE) == CERTIFICATE_SHA256:
        raise ValueError("Qualified story resources require a separately retained successor")
    folder = ROOT / RELATIVE
    record_path = folder / "stage-identity.json"
    record = json.loads(record_path.read_bytes())
    target = folder / "stage" / BUNDLE
    _, _, initial = initial_state(ROOT)
    if files(target) != record["currentFiles"] or files(folder / "previous" / BUNDLE) != initial["previousFiles"]:
        raise ValueError("Existing staged resources changed outside their recorded identity")
    candidate = ROOT / CANDIDATE
    identity = json.loads((candidate / "identity.json").read_bytes())
    if sha(candidate / "RRRuntimeBridge.m") != initial["bridgeSHA256"] or identity["bridgeSHA256"] != initial["bridgeSHA256"]:
        raise ValueError("Stage refresh cannot change native admission")
    for name in FILES:
        if sha(candidate / name) != identity["candidateSHA256"][name]:
            raise ValueError("Refreshed candidate input changed")
    retained = folder / ("prior-stage-" + sha(record_path)[:12])
    retained.mkdir(exist_ok=False)
    subprocess.run(["cp", "-cR", str(target), str(retained / BUNDLE)], check=True)
    shutil.copy2(record_path, retained / record_path.name)
    for name, relative in FILES.items():
        shutil.copy2(candidate / name, target / relative)
    provenance = json.loads((target / "provenance.json").read_bytes())
    provenance["compiledStoryRepair"].update(hostSHA256=sha(target / "base/rr_host.py"), hookSHA256=sha(target / "base/rr_story_patch.py"))
    (target / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    record.update(currentFiles=files(target), currentBaseFingerprint=fingerprint(target / "base"))
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("Refreshed exact staged host/hook; previous stage retained at " + str(retained))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", action="store_true")
    parser.add_argument("--accept-evidence", action="store_true")
    parser.add_argument("--refresh-stage", action="store_true")
    parser.add_argument("--promote", action="store_true")
    args = parser.parse_args()
    if args.stage:
        stage()
    elif args.accept_evidence:
        accept_evidence()
    elif args.refresh_stage:
        refresh_stage()
    elif args.promote:
        promote()
