"""Independent six-profile Live2D/engine successor; prior proofs stay immutable."""
import argparse
from collections import Counter
from functools import lru_cache
import hashlib
import importlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil
import struct
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path("RuntimeKit/Candidates/SparkSixCapabilities20261105")
FOLDER = Path("RuntimeKit/Validation/SparkSixCapabilities20261105V2")
BASELINE = Path("RuntimeKit/Validation/SparkSixCapabilitiesBaseline20261105")
CERTIFICATE = Path("RuntimeKit/Patches/spark-six-capabilities-20261105.json")
CERTIFICATE_SHA256 = "7b8616c99fcc9e6d43a5bb59bd5b66c788b20f4cf57c804760642297ec649e54"
RENDERER_POLICY_SHA256 = "7a777886c08754d591ab7b054629ca29da8a3a2a4fee15c46059028c0abbbccd"
RENDERER_BUILDER_SHA256 = "ed6433d29c551eef6a5e3a638eecdbae7ab756b81e3ef9711880dfa3ba929c98"
RENDERER_NOTICE_SHA256 = "aa75f792b2b40fa74bbdb7852179fff0d825799bbfb91004fa9716d154aa0ad0"
PREVIOUS_RENDERER_POLICY_SHA256 = "45237213952b2e199b06c526feb9219190c566f43f358194f73d2291a26f6ae5"
PREVIOUS_RENDERER_BUILDER_SHA256 = "192c9a23e7928c60a139b8799c9e9a299ad14ae4bcaa74151fd1be7fd90196c0"
RENDERER_NOTICE = Path("RuntimeKit/Notices/spark-six-live2d-renderer-validation-20261105.json")
RETENTION_SHA256 = "77bfffd691435a7638fae9c799a3b7eccdede6609e6cc10a1e10b2dab49fda13"
REPLAY_SHA256 = "5acd59e6ce927760e28ced7a02d3398ecee4a3483fff202b564000500501c5d6"
VERSIONS = ("7.8.4", "8.3.4", "8.5.0", "8.5.2", "7.8.8", "8.5.4")
ALL_VERSIONS = ("8.5.3", "7.4.11", "7.5.3", "7.6.3", "7.7.3", "7.8.7", "8.0.3", "8.1.3", "8.2.3", "8.3.7", "8.4.1") + VERSIONS
MODES = ("enhanced", "minimal", "nativeCompatibility")
MARKER = "sparkSixCapabilitiesSchemaVersion"
QUALIFICATION_ID = "spark-six-capabilities-20261105"
SCOPE = "Live2D publicMesh and independent custom-engine overlays; minimum iOS 17.5 Core and existing mode boundaries retained"
LIVE2D_MODULES = ("rr_live2d_backend", "rr_live2d_effects", "rr_live2d_renderer", "rr_live2d_blend", "rr_live2d_tree", "rr_live2d_shaders")
DENIAL = b'        _live2d_info.update(available=False, reason="newProfileLive2DUnqualified")\n'
PRESERVED_SOURCES = ("App/Core/AdvancedTranslationState.swift",
    "App/Services/Translation/AdvancedTranslationCapture.swift",
    "App/Services/Translation/TranslationProvider.swift",
    "App/Services/Translation/OnlineTranslationService.swift",
    "App/Services/Translation/TranslationTextLayout.swift",
    "App/Services/Import/BuiltinStoryRepairRuntime.swift",
    "App/Services/Import/EngineOverlayService.swift",
    "App/Services/Import/CompiledScriptIdentity.swift",
    "App/Services/Import/CompiledScriptValidation.swift",
    "App/RuntimeScriptIdentityCapture.swift",
    "RuntimeKit/Bridge/RRRuntimeBridge.m", "RuntimeKit/Bridge/RRRuntimeBridge.h",
    "RuntimeKit/Native/RRRuntime.m")


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or linked six-capability input: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    sha(path)
    return json.loads(path.read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def checked(root, name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Six-capability evidence must remain root-relative")
    target = root / path
    if target.resolve() != target.absolute():
        raise ValueError("Linked six-capability input")
    return target


def files(directory):
    if not directory.is_dir() or directory.is_symlink() or directory.resolve() != directory.absolute():
        raise ValueError("Missing or linked six-capability resource directory: " + str(directory))
    result = {}
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("Linked six-capability resource")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = [path.stat().st_size, sha(path)]
        elif not path.is_dir():
            raise ValueError("Special six-capability resource entry: " + str(path))
    return result


def directories(directory):
    return {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_dir()}


def bundle(artifacts, version):
    return artifacts / ("RenPy" + version.replace(".", "") + ".bundle")


@lru_cache(maxsize=1)
def frozen_baseline(root):
    baseline = root / BASELINE
    if RETENTION_SHA256 is None or REPLAY_SHA256 is None or sha(baseline / "retention.json") != RETENTION_SHA256 or sha(baseline / "replay.json") != REPLAY_SHA256:
        raise ValueError("Six-capability retained qualification root is not frozen")
    retained, replay = read(baseline / "retention.json"), read(baseline / "replay.json")
    for name, expected in dict(retained["sources"], **retained["certificates"]).items():
        if sha(baseline / name) != expected:
            raise ValueError("Six-capability retained source or certificate changed: " + name)
    if replay.get("passed") is not True or replay.get("catalogCount") != 17 or sha(baseline / "replay.log") != replay.get("replayLogSHA256"):
        raise ValueError("Six-capability predecessor replay did not finish")
    alias = "_rr_spark_six_frozen_runtime"
    package = types.ModuleType(alias)
    package.__path__ = [str(baseline / "Scripts/runtime")]
    package.__package__ = alias
    sys.modules[alias] = package
    old = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        modules = {name: importlib.import_module(alias + "." + name) for name in (
            "advanced_translation17_update", "overlay_capability_guard", "nightly_profile_guard")}
        advanced = modules["advanced_translation17_update"]
        entries = {p["runtimeID"]: p for p in read(baseline / "RuntimeKit/Artifacts/runtime-catalog.json")["profiles"]}
        advanced.verify_added_profiles(baseline, entries, set(VERSIONS))
        modules["overlay_capability_guard"].check(baseline, read(baseline / "RuntimeKit/Patches/overlay-capability-853.json"))
    finally:
        sys.dont_write_bytecode = old
    if set(entries) != set(ALL_VERSIONS) or replay.get("translationCertificateSHA256") != advanced.CERTIFICATE_SHA256:
        raise ValueError("Six-capability predecessor changed the seventeen-profile qualification")
    return baseline, modules, entries, replay


def preserved_sources(root, baseline):
    for name in PRESERVED_SOURCES:
        if sha(root / name) != sha(baseline / name):
            raise ValueError("Six-capability update changed an unrelated product source: " + name)


def host_bytes(previous):
    if previous.count(DENIAL) != 1:
        raise ValueError("Unknown six-profile Live2D host admission boundary")
    source = previous.replace(DENIAL, b"", 1).decode("utf-8")
    early = '    __import__("rr_series_state")\n'
    added_early = ("    global _stock_live2d_loader\n"
        "    _stock_live2d_loader = getattr(sys.modules.get(\"__main__\"), \"_stock_module\", None)\n"
        "    if not callable(_stock_live2d_loader):\n"
        "        raise RuntimeError(\"The trusted stock module loader is unavailable\")\n"
        "    for name in (\"rr_live2d_backend\", \"rr_live2d_effects\", \"rr_live2d_renderer\", \"rr_live2d_blend\"):\n"
        "        _stock_live2d_loader(name, name + \".py\")\n")
    late = "        renpy.import_all()\n"
    added_late = ("        for name in (\"rr_live2d_tree\", \"rr_live2d_shaders\"):\n"
        "            _stock_live2d_loader(name, name + \".py\")\n")
    if source.count(early) != 1 or source.count(late) != 1 or "_stock_live2d_loader" in source:
        raise ValueError("Unknown trusted Live2D dependency loading boundary")
    return source.replace(early, added_early + early, 1).replace(late, late + added_late, 1).encode("utf-8")


def expected_profile(previous):
    profile = json.loads(json.dumps(previous))
    live = profile["live2D"]
    if live.get("available") is not False or profile.get("advancedTranslationSchemaVersion") != 1 or profile.get("scriptTranslationPagingSchemaVersion") != 1 or "engineOverlaySchemaVersion" in profile or MARKER in profile:
        raise ValueError("Unknown six-profile capability predecessor")
    live.update(available=True, reason=None)
    live["modelPolicy"].update(maximumMocVersion=6, offscreenSupported=True,
        advancedBlendSupported=True, rendererBackend="renpy.publicMesh", rendererAvailable=True,
        rendererReason=None, rendererAPIRevision=2, samplerBinding="childTextures", textureExtentAPI=0)
    profile.update(engineOverlaySchemaVersion=1)
    profile[MARKER] = 1
    return profile


def expected_api(previous):
    api = json.loads(json.dumps(previous))
    renderer = api["renderer"]
    if renderer.get("enabled") is not False or renderer.get("featureMask") != 0 or "certificateSHA256" in renderer:
        raise ValueError("Unknown six-profile renderer predecessor")
    renderer.update(enabled=True, featureMask=3, maximumMocVersion=6, qualificationID=QUALIFICATION_ID)
    return api


def checked_resources(root, version, actual, baseline):
    previous = bundle(baseline / "RuntimeKit/Artifacts", version)
    before, after = files(previous), files(actual)
    if directories(previous) != directories(actual):
        raise ValueError("Six-capability runtime packaging changed")
    if version not in VERSIONS:
        if before != after:
            raise ValueError("Six-capability update changed an original runtime: " + version)
        return after
    allowed = {"base/rr_host.py", "base/rr-live2d-api.json", "runtime-profile.json", "provenance.json"}
    if set(before) != set(after) or any(before[name] != after[name] for name in before if name not in allowed):
        raise ValueError("Six-capability update changed an unrelated resource: " + version)
    if (actual / "base/rr_host.py").read_bytes() != host_bytes((previous / "base/rr_host.py").read_bytes()):
        raise ValueError("Six-capability host changed beyond its one admission line")
    profile = read(actual / "runtime-profile.json")
    if any(type(profile.get(name)) is not int or profile[name] != 1 for name in (
            "advancedTranslationSchemaVersion", "scriptTranslationPagingSchemaVersion", "engineOverlaySchemaVersion", MARKER)):
        raise ValueError("Six-capability profile changed an exact supported integer schema")
    if canonical(profile) != canonical(expected_profile(read(previous / "runtime-profile.json"))):
        raise ValueError("Six-capability profile changed another policy")
    api = read(actual / "base/rr-live2d-api.json")
    if canonical(api) != canonical(expected_api(read(previous / "base/rr-live2d-api.json"))):
        raise ValueError("Six-capability renderer metadata changed another field")
    # The independent certificate validates this narrow record and its renderer
    # proof after real model, custom-engine and translation sessions finish.
    old_provenance, new_provenance = read(previous / "provenance.json"), read(actual / "provenance.json")
    record = new_provenance.pop("sparkSixCapabilities", None)
    expected_record = {"schemaVersion": 1, "previousProvenanceSHA256": sha(previous / "provenance.json"),
        "hostSHA256": sha(actual / "base/rr_host.py"), "live2DAPISHA256": sha(actual / "base/rr-live2d-api.json"),
        "qualificationID": QUALIFICATION_ID, "scope": SCOPE}
    if canonical(new_provenance) != canonical(old_provenance) or canonical(record) != canonical(expected_record):
        raise ValueError("Six-capability provenance lost its exact predecessor")
    return after


def expected_registry_bytes(root, identity):
    baseline, _, _, _ = frozen_baseline(root)
    previous = (baseline / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes()
    expression = rb'\.init\(runtimeID: "(renpy-[0-9.]+)", previousProvenanceSHA256: "([0-9a-f]{64})", currentProvenanceSHA256: "([0-9a-f]{64})", currentBaseFingerprint: "([0-9a-f]{64})"\)'
    rows = re.findall(expression, previous)
    if len(rows) != 171 or len(rows) != previous.count(b".init(runtimeID:"):
        raise ValueError("The retained direct engine-update registry changed")
    added = []
    for version in VERSIONS:
        runtime = "renpy-" + version
        origins = {r[i].decode() for r in rows if r[0].decode() == runtime for i in (1, 2)}
        origins.add(sha(bundle(baseline / "RuntimeKit/Artifacts", version) / "provenance.json"))
        record = identity["runtimes"][version]
        for origin in sorted(origins):
            added.append('        .init(runtimeID: "%s", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' % (runtime, origin, record["provenanceSHA256"], record["baseFingerprint"]))
    end = b"\n    ]\n}\n"
    if previous.count(end) != 1:
        raise ValueError("The retained registry append boundary changed")
    return previous.replace(end, b",\n" + ",\n".join(added).encode() + end, 1)


def verify_native(root, artifacts, identity):
    baseline, modules, _, replay = frozen_baseline(root)
    packages = {path.name: path for path in artifacts.glob("*.xcframework")}
    if set(packages) != set(replay["frameworkTrees"]) or set(identity.get("frameworks", {})) != set(packages):
        raise ValueError("Six-capability native package inventory changed")
    for name, package in packages.items():
        record = identity["frameworks"][name]
        if (record.get("tree") != replay["frameworkTrees"][name]
                or record.get("files") != files(package)
                or modules["overlay_capability_guard"].tree_digest(package) != record["tree"]):
            raise ValueError("Six-capability native/shared framework bytes changed: " + name)
    for version in ALL_VERSIONS:
        if identity["runtimes"][version].get("native") != replay["native"][version] or modules["nightly_profile_guard"].native_identities(root, artifacts, version) != replay["native"][version]:
            raise ValueError("Six-capability native image loading identity changed: " + version)


def input_paths(root):
    paths = [Path(name) for name in PRESERVED_SOURCES]
    paths += [CANDIDATE / "AdvancedProbeV2" / name for name in (
        "run_probe.py", "AdvancedTranslationProbe.m", "NativeOCRProbe.swift", "rr_advanced_translation.py", "game/script.rpy")]
    paths.append(FOLDER / "identity.json")
    return paths


def verify_prepared(root):
    baseline, modules, entries, replay = frozen_baseline(root)
    preserved_sources(root, baseline)
    identity = read(root / FOLDER / "identity.json")
    artifacts = root / FOLDER / "Artifacts"
    if (type(identity.get("schemaVersion")) is not int or identity["schemaVersion"] != 1 or identity.get("qualificationID") != QUALIFICATION_ID
            or identity.get("qualified") is not False or set(identity.get("runtimes", {})) != set(ALL_VERSIONS)
            or identity.get("sourceCatalogSHA256") != sha(baseline / "RuntimeKit/Artifacts/runtime-catalog.json")
            or canonical(identity.get("baselineCatalogProfiles")) != canonical(list(entries.values()))
            or identity.get("prepareSourceSHA256") != sha(root / CANDIDATE / "prepare_stage_v2.py")):
        raise ValueError("The frozen six-capability stage identity changed")
    fingerprint = modules["advanced_translation17_update"].frozen_baseline(baseline)[1]["advanced_translation_update"].fingerprint
    for version in ALL_VERSIONS:
        actual = bundle(artifacts, version)
        current = checked_resources(root, version, actual, baseline)
        previous = bundle(baseline / "RuntimeKit/Artifacts", version)
        record = identity["runtimes"][version]
        if (record.get("beforeFiles") != files(previous) or record.get("files") != current
                or record.get("bundle") != modules["overlay_capability_guard"].tree_digest(actual)
                or record.get("profileSHA256") != sha(actual / "runtime-profile.json")
                or record.get("provenanceSHA256") != sha(actual / "provenance.json")
                or record.get("hostSHA256") != sha(actual / "base/rr_host.py")
                or record.get("live2DAPISHA256") != sha(actual / "base/rr-live2d-api.json")
                or record.get("helperSHA256") != sha(actual / "base/rr_advanced_translation.py")
                or record.get("baseFingerprint") != fingerprint(actual / "base")
                or record.get("native") != replay["native"][version]):
            raise ValueError("The six-capability stage lost its exact resource/native identity: " + version)
        wanted_changes = ["base/rr-live2d-api.json", "base/rr_host.py", "provenance.json", "runtime-profile.json"] if version in VERSIONS else []
        if record.get("changedFiles") != wanted_changes:
            raise ValueError("The six-capability stage changed an unrelated file")
    packages = {path.name: path for path in artifacts.glob("*.xcframework")}
    if set(packages) != set(replay["frameworkTrees"]) or set(identity.get("frameworks", {})) != set(packages):
        raise ValueError("The six-capability stage changed its native package inventory")
    for name, package in packages.items():
        record = identity["frameworks"][name]
        if record.get("tree") != replay["frameworkTrees"][name] or record.get("files") != files(package) or modules["overlay_capability_guard"].tree_digest(package) != record["tree"]:
            raise ValueError("The six-capability stage changed native/shared framework bytes: " + name)
    catalog = read(artifacts / "runtime-catalog.json")
    expected_catalog = read(baseline / "RuntimeKit/Artifacts/runtime-catalog.json")
    for entry in expected_catalog["profiles"]:
        if entry["runtimeID"] in VERSIONS:
            profile = read(bundle(artifacts, entry["runtimeID"]) / "runtime-profile.json")
            entry.update(live2D=profile["live2D"], engineOverlaySchemaVersion=1)
            entry[MARKER] = 1
    if (canonical(catalog) != canonical(expected_catalog)
            or identity.get("catalogSHA256") != sha(artifacts / "runtime-catalog.json")):
        raise ValueError("The six-capability stage changed an unrelated catalog field")
    return identity


def verify_advanced_events(rows, phase):
    pairs = [(v, m) for v in VERSIONS for m in MODES]
    contexts = {('advanced-' + str(i), i + 1): pair for i, pair in enumerate(pairs)}
    enabled = {key: pair for key, pair in contexts.items() if pair[1] != 'nativeCompatibility'}
    of = lambda name: [r for r in rows if r.get('type') == name]
    if phase not in {'warm', 'cold'} or any(r.get('type') in {'probeFailure', 'translationProbeFailed', 'gameError', 'saveFailed', 'error', 'quarantined'} for r in rows):
        raise ValueError('Six-profile translation matrix contains a failure')
    final = of('translationProbePassed')
    if len(final) != 1 or final[0].get('sessions') != 18 or final[0].get('failures') != 0 or bool(final[0].get('cold')) is not (phase == 'cold'):
        raise ValueError('Six-profile translation phase did not complete 18 sessions')
    pid, run_id = final[0].get('processID'), final[0].get('runID')
    if type(pid) is not int or pid <= 0 or not isinstance(run_id, str) or not run_id or any(r.get('processID') != pid or r.get('runID') != run_id for r in rows):
        raise ValueError('Six-profile translation phase process/run identity changed')

    def key(row):
        if type(row.get('epoch')) is not int:
            raise ValueError('Six-profile translation epoch is not an exact integer')
        return row.get('sessionID'), row['epoch']

    def coverage(name, expected):
        current = of(name)
        if Counter(key(r) for r in current) != Counter({k: 1 for k in expected}):
            raise ValueError('Six-profile translation session coverage changed: ' + name)
        if any((r.get('runtime'), r.get('mode')) != expected[key(r)] for r in current):
            raise ValueError('Six-profile translation session/runtime binding changed: ' + name)
        return current

    for name in ('ready', 'firstFrameDrawn', 'translationProbeValidated', 'saveCommitted', 'threadAudit', 'eventQueueCleanupSummary', 'didReset'):
        coverage(name, contexts)
    if any(r.get('remaining') != [] for r in of('threadAudit')) or any(r.get('succeeded') is not True or r.get('errors') != [] for r in of('eventQueueCleanupSummary')):
        raise ValueError('Six-profile translation did not release session threads or events')
    if any(r.get('slot') != 'rr_suspend' for r in of('saveCommitted')):
        raise ValueError('Six-profile translation did not commit its exit checkpoint')
    for row in of('ready'):
        native = row['mode'] == 'nativeCompatibility'
        cap = row.get('capabilities', {})
        if cap.get('advancedTranslation') is not (not native) or cap.get('titlePatches') is not False or row.get('engineOverlaySHA256') is not None:
            raise ValueError('Six-profile translation capability/mode boundary changed')
        if cap.get('live2D') is not True or row.get('live2D', {}).get('available') is not True:
            raise ValueError('Six-profile translation lost qualified Live2D admission')
    rejection_contexts = {}
    for owner, pair in contexts.items():
        native = pair[1] == 'nativeCompatibility'
        requests = ('frame', 'script-0', 'bad-frame', 'bad-script') if native else ('bad-frame', 'bad-script')
        for request in requests:
            message = 'Reader enhancements are disabled for this session' if native else {
                'bad-frame': 'Invalid screenshot dimensions', 'bad-script': 'Invalid script line budget'}[request]
            rejection_contexts[owner + (request,)] = (pair, message)
    rejections = of('commandRejected')
    if Counter(key(row) + (row.get('requestID'),) for row in rejections) != Counter({owner: 1 for owner in rejection_contexts}):
        raise ValueError('Six-profile translation raw rejection coverage changed')
    for row in rejections:
        pair, message = rejection_contexts[key(row) + (row['requestID'],)]
        if (row.get('runtime'), row.get('mode')) != pair or row.get('message') != message:
            raise ValueError('Six-profile translation raw rejection escaped its mode/session')
    for row in of('translationProbeValidated'):
        native = row['mode'] == 'nativeCompatibility'
        if (type(row.get('rejected')) is not int or row['rejected'] != (4 if native else 2)
                or row.get('image') is not (not native) or row.get('script') is not (not native)):
            raise ValueError('Six-profile translation summary disagrees with its raw mode evidence')
    for name in ('nativeOCRPassed', 'translationFrame', 'scriptPaginationPassed'):
        coverage(name, enabled)
    script_rows = of('translationScript')
    if any(key(r) not in enabled or (r.get('runtime'), r.get('mode')) != enabled[key(r)] for r in script_rows):
        raise ValueError('Six-profile translation script response escaped its enabled session')
    summaries = {key(r): r for r in of('scriptPaginationPassed')}
    for owner, summary in summaries.items():
        pages = [r for r in script_rows if key(r) == owner]
        if len(pages) < 2 or len(pages) != summary.get('pageCount') or summary.get('uniqueFixtureLines') != 1505 or summary.get('complete') is not True:
            raise ValueError('Six-profile translation did not traverse all recorded script pages')
        previous_position, previous_scanned, total, token = (0, 0), 0, None, None
        fixture_lines = set()
        for index, page in enumerate(pages):
            scanned, count = page.get('scannedStatements'), page.get('totalStatements')
            if page.get('requestID') != 'script-' + str(index) or type(scanned) is not int or type(count) is not int or not 0 <= scanned <= count <= 2**31 - 1 or scanned < previous_scanned:
                raise ValueError('Six-profile translation raw script page progress changed')
            if total is not None and count != total:
                raise ValueError('Six-profile translation script table changed between pages')
            total = count
            items = page.get('items')
            if not isinstance(items, list) or len(items) > 1000:
                raise ValueError('Six-profile translation raw page exceeded its item budget')
            for item in items:
                text = item.get('text')
                if not isinstance(text, str) or '[marker]' in text:
                    raise ValueError('Six-profile translation included dynamic script text')
                match = re.fullmatch(r'Pagination verification line ([0-9]{4})\.', text)
                if match: fixture_lines.add(int(match[1]))
            cursor = page.get('nextCursor')
            if cursor is None:
                if index != len(pages) - 1 or scanned != count:
                    raise ValueError('Six-profile translation ended before the complete statement table')
            else:
                if not isinstance(cursor, dict) or set(cursor) != {'nodeIndex', 'choiceIndex', 'statementCount', 'scriptToken'}:
                    raise ValueError('Six-profile translation raw cursor shape changed')
                node, choice = cursor['nodeIndex'], cursor['choiceIndex']
                current_token = cursor['scriptToken']
                if (type(node) is not int or type(choice) is not int or not 0 <= node < count or not 0 <= choice <= 1000
                        or cursor['statementCount'] != count or node != scanned or (node, choice) <= previous_position
                        or not isinstance(current_token, str) or re.fullmatch('[0-9a-f]{32}', current_token) is None
                        or (token is not None and token != current_token) or index == len(pages) - 1):
                    raise ValueError('Six-profile translation raw cursor did not advance within its original table')
                token, previous_position = current_token, (node, choice)
            previous_scanned = scanned
        if fixture_lines != set(range(1505)) or summary.get('scannedStatements') != total or summary.get('totalStatements') != total:
            raise ValueError('Six-profile translation raw pages omitted fixture text or complete progress')
    for row in of('nativeOCRPassed'):
        if any(row.get(field) is not True for field in ('regionValid', 'frameMappingVerified', 'glyphMeasurementVerified')) or row.get('captureWidth') != 640 or row.get('captureHeight') != 360:
            raise ValueError('Six-profile translation did not verify actual OCR geometry and native font measurement')
    if phase == 'cold':
        resumes = coverage('resumeState', contexts)
        if any(r.get('slot') != 'rr_suspend' or r.get('available') is not True for r in resumes):
            raise ValueError('Six-profile translation cold checkpoints were not explicitly resumed')
    return {'processID': pid, 'runID': run_id, 'sessions': 18}


def verified_evidence(root, evidence, names):
    if set(evidence) != set(names):
        raise ValueError("Six-capability evidence inventory changed")
    paths = {}
    for name, item in evidence.items():
        path = checked(root, item["path"])
        if sha(path) != item["sha256"]:
            raise ValueError("Six-capability raw evidence changed: " + name)
        paths[name] = path
    return paths


def verify_advanced(root, paths, identity):
    inputs, products = read(paths["advancedInputs"]), read(paths["advancedBuildProducts"])
    if set(inputs.get("sources", {})) != {p.as_posix() for p in input_paths(root)}:
        raise ValueError("Six-profile translation compilation source inventory changed")
    for name, expected in inputs["sources"].items():
        if sha(checked(root, name)) != expected:
            raise ValueError("Six-profile translation compiled source changed: " + name)
    if inputs.get("identitySHA256") != sha(root / FOLDER / "identity.json") or inputs.get("sourceCapture") != "before first object or Swift compilation":
        raise ValueError("Six-profile translation used another frozen stage")
    wanted_sessions = [{"version": version, "mode": mode} for version in VERSIONS for mode in MODES]
    if inputs.get("sessions") != wanted_sessions or set(inputs.get("resources", {})) != set(VERSIONS):
        raise ValueError("Six-profile translation matrix order changed")
    for version, item in inputs["resources"].items():
        expected = identity["runtimes"][version]
        if item.get("files") != expected["files"] or any(item.get(key) != expected[key] for key in ("hostSHA256", "helperSHA256", "profileSHA256")):
            raise ValueError("Six-profile translation did not run the complete accepted resources")
    wanted_packages = {name: item["files"] for name, item in identity["frameworks"].items()
        if not name.startswith("RRRuntime") or name in {"RRRuntime" + v.replace(".", "") + ".xcframework" for v in VERSIONS}}
    if inputs.get("frameworks") != wanted_packages:
        raise ValueError("Six-profile translation changed a native/shared compilation input")
    if products.get("inputsSHA256") != sha(paths["advancedInputs"]):
        raise ValueError("Six-profile translation products were not bound to their inputs")
    output = paths["advancedInputs"].parent
    if set(products.get("objects", {})) != {"RRRuntimeBridge.o", "AdvancedTranslationProbe.o"}:
        raise ValueError("Six-profile translation object inventory changed")
    for name, expected in products["objects"].items():
        if sha(output / name) != expected:
            raise ValueError("Six-profile translation compiled object changed")
    app = output / "AdvancedTranslationProbe.app"
    if products.get("executableSHA256") != sha(app / "TranslationProbe") or products.get("signedApp") != files(app):
        raise ValueError("Six-profile translation executable or signed resources changed")
    verify_probe_frameworks(root, app, identity)
    verification = read(paths["advancedVerification"])
    if (verification.get("passed") is not True or verification.get("buildProductsSHA256") != sha(paths["advancedBuildProducts"])
            or verification.get("compiledIdentitySHA256") != sha(paths["advancedCompiled"])):
        raise ValueError("Six-profile translation verification did not finish")
    compiled = read(paths["advancedCompiled"])
    if compiled.get("unchangedAfterCold") is not True or len(compiled.get("warmCompiledSHA256", {})) < 6:
        raise ValueError("Six-profile translation cold launch changed statement identities")
    processes, ocr_images = [], {}
    for phase in ("warm", "cold"):
        rows = [json.loads(line) for line in paths["advanced" + phase.title()].read_text().splitlines() if line]
        processes.append(verify_advanced_events(rows, phase)["processID"])
        ocr_images.update({(phase, r["sessionID"]): r.get("imageSHA256") for r in rows if r.get("type") == "nativeOCRPassed"})
    if len(set(processes)) != 2:
        raise ValueError("Six-profile translation cold process was not independent")
    frames = read(paths["advancedFrames"])
    if frames.get("schemaVersion") != 1 or len(frames.get("frames", [])) != 24:
        raise ValueError("Six-profile translation actual PNG evidence is incomplete")
    seen = set()
    for item in frames["frames"]:
        path = checked(root, item["path"])
        data = path.read_bytes()
        key = (item["phase"], item["sessionID"])
        if (key in seen or sha(path) != item["sha256"] or item["sha256"] != ocr_images.get(key)
                or len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", data[16:24]) != (640, 360)):
            raise ValueError("Six-profile translation screenshot evidence changed")
        seen.add(key)
    wanted = {(phase, "advanced-" + str(index)) for phase in ("warm", "cold")
              for index, session in enumerate(wanted_sessions) if session["mode"] != "nativeCompatibility"}
    if seen != wanted:
        raise ValueError("Six-profile translation screenshot/session coverage changed")
    return {"sessions": 36, "actualOCRAndPNG": 24, "processes": processes}


def object_files(directory):
    return {name: {"size": item[0], "sha256": item[1]} for name, item in files(directory).items()}


def verify_probe_frameworks(root, app, identity):
    baseline, modules, _, _ = frozen_baseline(root)
    overlay = modules["overlay_capability_guard"]
    wanted = {"RRRuntime" + version.replace(".", ""): identity["runtimes"][version]["native"]["iphonesimulator"] for version in VERSIONS}
    for package in identity["frameworks"]:
        name = Path(package).stem
        if not name.startswith("RRRuntime"):
            source = overlay.framework_slice(baseline, name, "iphonesimulator") / name
            wanted[name] = overlay.packaged_source_identity(baseline, source, "iphonesimulator")
    actual_names = {path.stem for path in (app / "Frameworks").glob("*.framework")}
    if actual_names != set(wanted):
        raise ValueError("Six-profile probe embedded another native package inventory")
    for name, expected in wanted.items():
        if overlay.image_identity(root, app / "Frameworks" / (name + ".framework") / name) != expected:
            raise ValueError("Six-profile probe executed another native/shared image: " + name)


def filemap_fingerprint(items):
    digest = hashlib.sha256()
    for name, (size, value) in sorted(items.items()):
        digest.update(("%d:%s:%d:%s\n" % (len(name.encode()), name, size, value)).encode())
    return digest.hexdigest()


def verify_prepared_services(root, paths, inputs, products, identity):
    prepared = inputs.get("preparedServices", {})
    expected_keys = {"directory", "inputsSHA256", "buildProductsSHA256", "fixturesSHA256", "builderExecutableSHA256", "sources", "installationFilemaps"}
    if set(prepared) != expected_keys:
        raise ValueError("Six-profile custom-engine preparation receipt is incomplete")
    parent = paths["overlayPreparedInputs"].parent
    parent_inputs, parent_products = read(paths["overlayPreparedInputs"]), read(paths["overlayPreparedBuildProducts"])
    for field, name in (("inputsSHA256", "overlayPreparedInputs"), ("buildProductsSHA256", "overlayPreparedBuildProducts"),
                        ("fixturesSHA256", "overlayPreparedFixtures"), ("builderExecutableSHA256", "overlayPreparedBuilder")):
        if prepared[field] != sha(paths[name]):
            raise ValueError("Six-profile custom-engine retained preparation input changed")
    if (parent_products.get("inputsSHA256") != sha(paths["overlayPreparedInputs"])
            or parent_products.get("fixturesSHA256") != sha(paths["overlayPreparedFixtures"])
            or sha(paths["overlayFixtures"]) != sha(paths["overlayPreparedFixtures"])
            or parent_inputs.get("resources") != inputs.get("resources")
            or parent_inputs.get("frameworks") != inputs.get("frameworks")):
        raise ValueError("Six-profile custom-engine preparation was rebound to another resource/native generation")
    baseline, _, _, _ = frozen_baseline(root)
    source_names = {"App/Services/Import/DataServiceTypes.swift", "App/Services/Import/EngineOverlayService.swift",
        "App/Services/Import/SparkParityEngineUpdates.swift", "RuntimeKit/Candidates/SparkSixOverlay20261105/OverlayFixtureBuilder.swift",
        "RuntimeKit/Candidates/SparkSixOverlay20261105/fixture.rpy"}
    if set(prepared["sources"]) != source_names:
        raise ValueError("Six-profile custom-engine preparation source inventory changed")
    for name, expected in prepared["sources"].items():
        wanted = sha(baseline / name) if name == "App/Services/Import/SparkParityEngineUpdates.swift" else sha(root / name)
        if expected != wanted or parent_inputs.get("sources", {}).get(name) != expected or inputs.get("sources", {}).get(name) != expected:
            raise ValueError("Six-profile custom-engine preparation source changed: " + name)
    if (inputs.get("stageIdentitySHA256") != sha(root / FOLDER / "identity.json")
            or sha(paths["overlayInputs"].parent / "stage-identity.json") != inputs["stageIdentitySHA256"]):
        raise ValueError("Six-profile custom-engine preparation lost its archived joint-stage identity")
    suffixes = {version.replace(".", "") for version in VERSIONS}
    if set(prepared["installationFilemaps"]) != suffixes:
        raise ValueError("Six-profile custom-engine prepared installation inventory changed")
    fixture_rows = {item["runtimeID"]: item for item in read(paths["overlayFixtures"])["runtimes"]}
    for version in VERSIONS:
        suffix = version.replace(".", "")
        old_install = parent / "Fixtures" / suffix / "Installation"
        final_install = paths["overlayInputs"].parent / "Fixtures" / suffix / "Installation"
        expected = prepared["installationFilemaps"][suffix]
        prefix = "Fixtures/" + suffix + "/Installation/"
        for signed in (parent_products.get("signedApp", {}), products.get("signedApp", {})):
            if {name[len(prefix):]: item for name, item in signed.items() if name.startswith(prefix)} != expected:
                raise ValueError("Six-profile custom-engine signed installation differs from its prepared services")
        if object_files(old_install) != expected or object_files(final_install) != expected:
            raise ValueError("Six-profile custom-engine prepared installation changed")
        fixture = fixture_rows[version]
        item = parent / "Fixtures" / suffix
        stored = item / "PreviousStored/manifest.json"
        manifest = read(stored)
        previous = bundle(baseline / "RuntimeKit/Artifacts", version)
        if (sha(stored) != fixture["previousManifestSHA256"] or manifest.get("runtimeID") != "renpy-" + version
                or manifest.get("runtimeProvenanceSHA256") != sha(previous / "provenance.json")
                or len(manifest.get("files", [])) != 1):
            raise ValueError("Six-profile custom-engine retained stored overlay identity changed")
        before = {name[5:]: value for name, value in identity["runtimes"][version]["beforeFiles"].items() if name.startswith("base/")}
        after = {name[5:]: value for name, value in identity["runtimes"][version]["files"].items() if name.startswith("base/")}
        patch = manifest["files"][0]
        if (patch.get("relativePath") != fixture["sourcePath"] or patch.get("originalSHA256") != fixture["originalSHA256"]
                or patch.get("newSHA256") != fixture["newSHA256"] or before[patch["relativePath"]][1] != patch["originalSHA256"]):
            raise ValueError("Six-profile custom-engine retained patch changed")
        stored_files = {"manifest.json": [stored.stat().st_size, sha(stored)],
            "Content/" + patch["relativePath"]: [patch["byteCount"], patch["newSHA256"]]}
        if files(stored.parent) != stored_files:
            raise ValueError("Six-profile custom-engine retained stored overlay payload changed")
        caches = {record.parent.name: record for record in (item / "PreviousCache").glob("*/materialization.json")}
        expected_caches = {filemap_fingerprint(before): (before, sha(previous / "provenance.json")),
            filemap_fingerprint(after): (after, identity["runtimes"][version]["provenanceSHA256"])}
        if set(caches) != set(expected_caches):
            raise ValueError("Six-profile custom-engine retained cache generations changed")
        for key, (original, provenance) in expected_caches.items():
            materialization = read(caches[key])
            # Match the production service's narrowly scoped bytecode eviction
            # for the replaced .py source, including tagged __pycache__ files.
            def stale(name):
                if not name.endswith((".pyc", ".pyo")):
                    return False
                if name[:-1] == patch["relativePath"]:
                    return True
                path = Path(name)
                return path.parent.name == "__pycache__" and (path.parent.parent / (path.name.split(".")[0] + ".py")).as_posix() == patch["relativePath"]
            wanted = {name: value for name, value in original.items() if not stale(name)}
            wanted[patch["relativePath"]] = [patch["byteCount"], patch["newSHA256"]]
            if (files(caches[key].parent / "base") != wanted
                    or type(materialization.get("schemaVersion")) is not int or materialization["schemaVersion"] != 1
                    or materialization.get("runtimeID") != "renpy-" + version
                    or materialization.get("runtimeProvenanceSHA256") != provenance
                    or materialization.get("manifestSHA256") != fixture["previousManifestSHA256"]
                    or materialization.get("bundledBaseFingerprint") != key
                    or materialization.get("materializedBaseFingerprint") != filemap_fingerprint(wanted)):
                raise ValueError("Six-profile custom-engine old or rebound complete cache tree changed")


def verify_overlay(root, paths, identity):
    inputs, products = read(paths["overlayInputs"]), read(paths["overlayBuildProducts"])
    baseline, _, _, _ = frozen_baseline(root)
    expected_versions = sorted(VERSIONS)
    if inputs.get("versions") != expected_versions or inputs.get("modes") != list(MODES):
        raise ValueError("Six-profile custom-engine matrix order changed")
    for name, expected in inputs.get("sources", {}).items():
        actual = checked(root, name)
        if name == "App/Services/Import/SparkParityEngineUpdates.swift":
            # This probe compiled the retained 171 rows. Final shipped migration
            # rows are an exact append, independently tested after promotion.
            if expected != sha(baseline / name) or actual.read_bytes() not in (
                    (baseline / name).read_bytes(), expected_registry_bytes(root, identity)):
                raise ValueError("Six-profile custom-engine registry compilation predecessor changed")
        elif sha(actual) != expected:
            raise ValueError("Six-profile custom-engine compiled source changed: " + name)
    candidate = Path("RuntimeKit/Candidates/SparkSixOverlay20261105")
    required = {str(candidate / name) for name in ("run_six_overlay_probe.py", "OverlayFixtureBuilder.swift", "OverlayWorkspace.swift", "OverlayProbe.m", "fixture.rpy")}
    required.update(("App/Services/Import/DataServiceTypes.swift", "App/Services/Import/EngineOverlayService.swift",
        "App/Services/Import/SparkParityEngineUpdates.swift", "App/Services/Import/CompiledScriptIdentity.swift",
        "App/Services/Import/CompiledScriptValidation.swift", "App/RuntimeScriptIdentityCapture.swift",
        "RuntimeKit/Bridge/RRRuntimeBridge.h", "RuntimeKit/Bridge/RRRuntimeBridge.m"))
    if not required <= set(inputs.get("sources", {})):
        raise ValueError("Six-profile custom-engine compilation source inventory is incomplete")
    expected_resources = {"RenPy" + v.replace(".", "") + ".bundle": {
        name: {"size": item[0], "sha256": item[1]} for name, item in identity["runtimes"][v]["files"].items()} for v in VERSIONS}
    if inputs.get("resources") != expected_resources:
        raise ValueError("Six-profile custom-engine resources differ from the frozen joint stage")
    expected_packages = {name: {n: {"size": v[0], "sha256": v[1]} for n, v in item["files"].items()}
        for name, item in identity["frameworks"].items() if not name.startswith("RRRuntime")
        or name in {"RRRuntime" + v.replace(".", "") + ".xcframework" for v in VERSIONS}}
    if inputs.get("frameworks") != expected_packages:
        raise ValueError("Six-profile custom-engine native/shared inputs changed")
    output = paths["overlayInputs"].parent
    fixtures = read(paths["overlayFixtures"])
    if products.get("inputsSHA256") != sha(paths["overlayInputs"]) or products.get("fixturesSHA256") != sha(paths["overlayFixtures"]):
        raise ValueError("Six-profile custom-engine products are not bound to their actual inputs")
    if set(products.get("objects", {})) != {"RRRuntimeBridge.o", "OverlayProbe.o"} or any(sha(output / name) != expected for name, expected in products.get("objects", {}).items()):
        raise ValueError("Six-profile custom-engine actual compilation objects changed")
    app = output / "SixOverlayProbe.app"
    if products.get("executableSHA256") != sha(app / "SixOverlayProbe") or products.get("signedApp") != object_files(app):
        raise ValueError("Six-profile custom-engine signed app changed")
    verify_probe_frameworks(root, app, identity)
    verification = read(paths["overlayVerification"])
    if (verification.get("passed") is not True or verification.get("inputsSHA256") != sha(paths["overlayInputs"])
            or verification.get("buildProductsSHA256") != sha(paths["overlayBuildProducts"])):
        raise ValueError("Six-profile custom-engine verification did not finish")
    verify_prepared_services(root, paths, inputs, products, identity)
    fixture_rows = {item["runtimeID"]: item for item in fixtures.get("runtimes", [])}
    if set(fixture_rows) != set(VERSIONS) or len(fixtures.get("negativeTests", [])) < 24 or any(item.get("rejected") is not True for item in fixtures["negativeTests"]):
        raise ValueError("Six-profile custom-engine service matrix or negative checks are incomplete")
    observer = root / candidate / "run_six_overlay_probe.py"
    specification = importlib.util.spec_from_file_location("_rr_six_overlay_audit", observer)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    phases = {phase: [json.loads(line) for line in paths["overlay" + phase.title()].read_text().splitlines() if line]
              for phase in ("warm", "cold")}
    return verify_overlay_events(phases, fixture_rows, identity, verification, module)


def verify_overlay_events(phases, fixture_rows, identity, verification, module):
    expected_versions = sorted(VERSIONS)
    processes, sessions, workspaces, profiles, compiled_identities = [], set(), set(), {}, {}
    for phase in ("warm", "cold"):
        rows = phases[phase]
        final = [r for r in rows if r.get("type") == "overlayProbePassed"]
        if (len(final) != 1 or final[0].get("sessions") != 18 or final[0].get("failures") != 0
                or type(final[0].get("processID")) is not int or final[0]["processID"] <= 0):
            raise ValueError("Six-profile custom-engine phase did not complete eighteen sessions")
        pid, run_id = final[0]["processID"], final[0].get("runID")
        if not isinstance(run_id, str) or not run_id or any(r.get("processID") != pid or r.get("runID") != run_id or r.get("cold") is not (phase == "cold") for r in rows):
            raise ValueError("Six-profile custom-engine phase/process binding changed")
        if any(r.get("type") in {"overlayProbeFailure", "overlayProbeFailed", "error", "gameError", "saveFailed", "quarantined"} for r in rows):
            raise ValueError("Six-profile custom-engine raw run contains a failure")
        module.verify(rows, phase)
        processes.append(pid)
        for version in expected_versions:
            for mode in MODES:
                owned = [r for r in rows if (r.get("runtime"), r.get("mode")) == (version, mode)]
                selected = lambda kind: [r for r in owned if r.get("type") == kind]
                for kind in ("customPrepare", "ready", "saveCommitted", "threadAudit", "eventQueueCleanupSummary", "didReset", "overlaySessionValidated", "overlayCompiledIdentityVerified", "nativeEnginePinProbe"):
                    if len(selected(kind)) != 1:
                        raise ValueError("Six-profile custom-engine lifecycle coverage changed: " + kind)
                preparation, ready = selected("customPrepare")[0], selected("ready")[0]
                owner = preparation["qaSessionID"]
                fixture = fixture_rows[version]
                if (preparation.get("manifestSHA256") != fixture.get("manifestSHA256")
                        or preparation.get("installationID") != fixture.get("installationID")
                        or preparation.get("profileID") != fixture.get("profileID")
                        or selected("overlaySessionValidated")[0].get("manifestSHA256") != fixture.get("manifestSHA256")):
                    raise ValueError("Six-profile custom-engine raw selection differs from its immutable fixture")
                if owner in sessions or preparation.get("prepared") is not True or preparation.get("workspace") in workspaces:
                    raise ValueError("Six-profile custom-engine reused a session/workspace")
                sessions.add(owner);workspaces.add(preparation["workspace"])
                profiles.setdefault(version, preparation.get("profileID"))
                if preparation.get("profileID") != profiles[version]:
                    raise ValueError("Six-profile custom-engine modes did not share their original profile")
                epoch = expected_versions.index(version) * len(MODES) + MODES.index(mode) + 1
                if any(r.get("qaSessionID") != owner or (r.get("sessionID") is not None and (
                        r["sessionID"] != owner or type(r.get("epoch")) is not int or r["epoch"] != epoch)) for r in owned):
                    raise ValueError("Six-profile custom-engine borrowed another session")
                cap, native = ready.get("capabilities", {}), mode == "nativeCompatibility"
                if (ready.get("runtimeVersion") != version or ready.get("launchMode") != mode
                        or ready.get("engineOverlaySHA256") != preparation.get("manifestSHA256")
                        or cap.get("save") is not (not native) or cap.get("advancedTranslation") is not (not native)
                        or cap.get("titlePatches") is not False or cap.get("live2D") is not True
                        or ready.get("live2D", {}).get("available") is not True):
                    raise ValueError("Six-profile custom-engine capability/selection boundary changed")
                expected_rejections = {"mode-boundary-" + name for name in ("getVariables", "save", "load")} if native else set()
                rejected = selected("commandRejected")
                if Counter(r.get("requestID") for r in rejected) != Counter({name: 1 for name in expected_rejections}) or any(r.get("message") != "Reader enhancements are disabled for this session" for r in rejected):
                    raise ValueError("Six-profile custom-engine native raw command boundary changed")
                helper_hashes = {name: identity["runtimes"][version]["files"]["base/" + name + ".py"][1] for name in LIVE2D_MODULES}
                if fixture.get("trustedHelperSHA256") != helper_hashes:
                    raise ValueError("Six-profile custom-engine fixture did not bind the complete trusted Live2D dependency closure")
                lines = selected("overlayFixtureLine")
                if len(lines) < 3 or [(r.get("value"), r.get("loaded")) for r in (lines[0], lines[-1])] != [(73, phase == "cold"), (73, True)] or not any(r.get("value") == 91 for r in lines):
                    raise ValueError("Six-profile custom-engine original quick-save/load did not restore 73")
                for line in lines:
                    if (line.get("moduleSource") != preparation["base"] + "/" + fixture["sourcePath"]
                            or line.get("moduleSHA256") != fixture["newSHA256"] or line.get("rendered") != fixture["marker"]
                            or line.get("dontWriteBytecode") is not True):
                        raise ValueError("Six-profile custom-engine did not execute the materialized Python source")
                    helper_sources = line.get("helperSources", {})
                    if set(helper_sources) != set(LIVE2D_MODULES) or line.get("helperSHA256") != helper_hashes or any(
                            not isinstance(helper_sources[name], str) or not helper_sources[name].endswith(
                                "/RenPy" + version.replace(".", "") + ".bundle/base/" + name + ".py") for name in LIVE2D_MODULES):
                        raise ValueError("Six-profile custom-engine loaded a shadow of a trusted Live2D dependency")
                capture = selected("overlayCompiledIdentityVerified")[0]
                detail = json.loads(capture["identityJSON"])
                documents = preparation["workspace"].rsplit("/Workspaces/", 1)[0]
                if (detail.get("sourceInstallationUnchanged") is not True or detail.get("exactCompilerOutputVerified") is not True
                        or type(capture.get("captureCount")) is not int or capture["captureCount"] <= 0
                        or type(capture.get("saves")) is not int or capture["saves"] <= 0
                        or detail.get("runtimeID") != "renpy-" + version or detail.get("contentFingerprint") != fixture.get("contentFingerprint")
                        or detail.get("workspace") != preparation["workspace"]
                        or preparation.get("base") != documents + "/EngineCaches/" + version.replace(".", "") + "/" + fixture["manifestSHA256"] + "/" + fixture["currentBaseFingerprint"] + "/base"
                        or detail.get("installation") != documents + "/Installations/" + fixture["installationID"]
                        or detail.get("identityDirectory") != documents + "/Profiles/" + fixture["profileID"] + "/Working/default/ScriptIdentity/renpy-" + version
                        or selected("saveCommitted")[0].get("slot") != "rr_suspend"):
                    raise ValueError("Six-profile custom-engine did not preserve its compiler identity")
                fingerprint = detail.get("compiledIdentityFingerprint")
                if not isinstance(fingerprint, str) or re.fullmatch("[0-9a-f]{64}", fingerprint) is None:
                    raise ValueError("Six-profile custom-engine compiled identity fingerprint is invalid")
                compiled = (fingerprint, canonical(detail.get("compiledFiles")))
                if compiled != compiled_identities.setdefault(version, compiled):
                    raise ValueError("Six-profile custom-engine modes/cold launch changed their compiled statement namespace")
                if selected("threadAudit")[0].get("remaining") != [] or selected("eventQueueCleanupSummary")[0].get("succeeded") is not True or selected("eventQueueCleanupSummary")[0].get("errors") != []:
                    raise ValueError("Six-profile custom-engine did not release its session owner")
    if len(set(processes)) != 2 or len(sessions) != 36 or len(workspaces) != 36 or len(set(profiles.values())) != 6:
        raise ValueError("Six-profile custom-engine warm/cold ownership matrix is incomplete")
    if verification.get("warmPID") != processes[0] or verification.get("coldPID") != processes[1] or len(verification.get("sessions", [])) != 36:
        raise ValueError("Six-profile custom-engine verification process matrix changed")
    return {"sessions": 36, "workspaces": 36, "profiles": 6, "processes": processes}


def verify_live2d_contexts(rows, phase):
    if phase not in ("warm", "cold"):
        raise ValueError("Six-profile Live2D phase is unknown")
    contexts = {"smoke-" + str(index + 1): (version, mode, index + 1)
        for index, (version, mode) in enumerate((version, mode) for version in sorted(VERSIONS) for mode in MODES)}
    # These two original SmokeHost annotations name their exact session but
    # predate its epoch field. All functional engine/fixture evidence has both.
    annotations = {"preferencesReadbackPassed", "live2DColdResumeRequested"}
    for row in rows:
        session, kind = row.get("sessionID"), row.get("type")
        if session is None:
            if kind != "smokePassed":
                raise ValueError("Six-profile Live2D functional evidence lost its session context")
            continue
        if session not in contexts:
            raise ValueError("Six-profile Live2D evidence names another session")
        version, mode, epoch = contexts[session]
        if (row.get("epoch") is None and kind not in annotations) or (row.get("epoch") is not None and (
                type(row["epoch"]) is not int or row["epoch"] != epoch)):
            raise ValueError("Six-profile Live2D evidence escaped its frozen epoch")
        if kind == "ready" and (row.get("runtimeVersion") != version or row.get("launchMode") != mode):
            raise ValueError("Six-profile Live2D ready escaped its frozen runtime/mode")
        if kind == "preferencesReadbackPassed" and mode == "nativeCompatibility":
            raise ValueError("Six-profile Live2D native mode acquired reader preferences")
        if kind == "nativeModeProbe" and mode != "nativeCompatibility":
            raise ValueError("Six-profile Live2D native proof escaped its frozen mode")
        if kind == "live2DColdResumeRequested" and (phase != "cold" or row.get("slot") != "rr_suspend"):
            raise ValueError("Six-profile Live2D cold annotation escaped its phase")
    resumes = [r for r in rows if r.get("type") == "live2DColdResumeRequested"]
    if Counter(r.get("sessionID") for r in resumes) != Counter({name: 1 for name in contexts} if phase == "cold" else {}):
        raise ValueError("Six-profile Live2D cold checkpoint request coverage changed")
    native_sessions = {name: 1 for name, (_, mode, _) in contexts.items() if mode == "nativeCompatibility"}
    if Counter(r.get("sessionID") for r in rows if r.get("type") == "nativeModeProbe") != Counter(native_sessions):
        raise ValueError("Six-profile Live2D native proof session coverage changed")
    return contexts


def verify_live2d(root, paths, identity):
    record = read(paths["live2DCertificate"])
    inputs, products = read(paths["live2DInputs"]), read(paths["live2DBuildProducts"])
    if (type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1
            or record.get("passed") is not True or record.get("qualificationID") != QUALIFICATION_ID
            or set(record.get("profiles", {})) != set(VERSIONS) or record.get("nativeImagesRebuilt") is not False
            or record.get("legacyCoreQualified") is not False or record.get("legacyCoreQualificationUnchanged") is not True):
        raise ValueError("Six-profile Live2D acceptance scope changed")
    for inventory in (record.get("sourceSHA256", {}), inputs.get("sourceSHA256", {})):
        if not inventory:
            raise ValueError("Six-profile Live2D source inventory is incomplete")
        for name, expected in inventory.items():
            if sha(checked(root, name)) != expected:
                raise ValueError("Six-profile Live2D compiled or review source changed: " + name)
    review_sources = {"RuntimeKit/Python/" + name + ".py" for name in LIVE2D_MODULES}
    review_sources.update("RuntimeKit/Native/" + name for name in ("RRLive2DCore.c", "RRLive2DEffects.mm", "RRLive2DPhysicsState.cpp"))
    review_sources.update("RuntimeKit/Candidates/SparkSixLive2D20261105/" + name for name in (
        "certify.py", "compare_pixels.py", "rr_six_owned_hooks.py", "run_probe.py"))
    if not review_sources <= set(record.get("sourceSHA256", {})):
        raise ValueError("Six-profile Live2D review source inventory is incomplete")
    compilation_sources = {"RuntimeKit/Candidates/SparkSixLive2D20261105/" + name for name in ("run_probe.py", "compare_pixels.py")}
    compilation_sources.update("Scripts/runtime/" + name for name in ("smoke_runtime.py", "live2d_fixture.py",
        "live2d_dynamic_fixture.py", "verify_ren_renderer_fixture.py", "prepare_renderer_reference.py"))
    compilation_sources.update(("RuntimeKit/Tests/SmokeHost.m", "RuntimeKit/Tests/launch_mode_probe.rpy",
        "RuntimeKit/Tests/launch_mode_external.py", "RuntimeKit/Bridge/RRRuntimeBridge.m", "RuntimeKit/Bridge/RRRuntimeBridge.h"))
    if not compilation_sources <= set(inputs.get("sourceSHA256", {})) or not any(name.endswith("/Kit/Tests/SmokeHost.m") for name in inputs["sourceSHA256"]):
        raise ValueError("Six-profile Live2D actual compilation source inventory is incomplete")
    output = paths["live2DInputs"].parent
    if (record.get("inputsSHA256") != sha(paths["live2DInputs"])
            or record.get("buildProductsSHA256") != sha(paths["live2DBuildProducts"])
            or products.get("inputsSHA256") != sha(paths["live2DInputs"])
            or inputs.get("stageIdentitySHA256") != sha(root / FOLDER / "identity.json")):
        raise ValueError("Six-profile Live2D compilation products lost their exact input binding")
    expected_sessions = [{"runtimeID": version, "mode": mode} for version in sorted(VERSIONS) for mode in MODES]
    if inputs.get("sessions") != expected_sessions:
        raise ValueError("Six-profile Live2D matrix order changed")
    artifact_files = {"RenPy" + v.replace(".", "") + ".bundle": {
        name: {"size": value[0], "sha256": value[1]} for name, value in identity["runtimes"][v]["files"].items()} for v in VERSIONS}
    artifact_files.update({name: {n: {"size": value[0], "sha256": value[1]} for n, value in item["files"].items()}
        for name, item in identity["frameworks"].items() if not name.startswith("RRRuntime")
        or name in {"RRRuntime" + v.replace(".", "") + ".xcframework" for v in VERSIONS}})
    if inputs.get("artifactFiles") != artifact_files:
        raise ValueError("Six-profile Live2D resources/native differ from the frozen joint stage")
    app = output / "SixLive2DProbe.app"
    if products.get("executableSHA256") != sha(app / "RuntimeSmoke") or products.get("appFiles") != object_files(app):
        raise ValueError("Six-profile Live2D signed compilation product changed")
    verify_probe_frameworks(root, app, identity)
    wanted_reports = {"warm.events.ndjson", "cold.events.ndjson", "script-identity.json", "run-result.json"}
    if set(record.get("reportSHA256", {})) != wanted_reports or any(sha(output / name) != expected for name, expected in record["reportSHA256"].items()):
        raise ValueError("Six-profile Live2D raw reports changed")
    run_result, compiled = read(output / "run-result.json"), read(output / "script-identity.json")
    if (run_result.get("passed") is not True or run_result.get("sessions") != 36
            or run_result.get("inputsSHA256") != sha(paths["live2DInputs"])
            or run_result.get("buildProductsSHA256") != sha(paths["live2DBuildProducts"])
            or compiled.get("sameInstalledApplication") is not True or compiled.get("unchanged") is not True
            or len(compiled.get("warmCompiled", {})) < 6 or compiled.get("warmCompiled") != compiled.get("afterCold")):
        raise ValueError("Six-profile Live2D warm/cold compiler identity changed")
    observer = root / "RuntimeKit/Candidates/SparkSixLive2D20261105/certify.py"
    specification = importlib.util.spec_from_file_location("_rr_six_live2d_audit", observer)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    # These existing strict observers are shared with the original qualified
    # renderer; their complete source bytes are frozen in this compilation.
    sys.path.insert(0, str(root / "Scripts/runtime"))
    try:
        ren = importlib.import_module("verify_ren_renderer_fixture")
        dynamic = importlib.import_module("live2d_dynamic_fixture")
    finally:
        sys.path.pop(0)
    phases, processes = {}, []
    for phase in ("warm", "cold"):
        path = output / (phase + ".events.ndjson")
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        verify_live2d_contexts(rows, phase)
        phases[phase] = rows
        final = [r for r in rows if r.get("type") == "smokePassed"]
        if (len(final) != 1 or final[0].get("sessions") != 18 or final[0].get("failures") != 0
                or type(final[0].get("processID")) is not int or final[0]["processID"] <= 0
                or any(r.get("processID") != final[0]["processID"] or r.get("runID") != final[0].get("runID") for r in rows)):
            raise ValueError("Six-profile Live2D phase/process binding changed")
        if any(r.get("type") in {"gameError", "error", "smokeFailure", "smokeFailed", "saveFailed", "quarantined"} for r in rows):
            raise ValueError("Six-profile Live2D raw run contains a failure")
        processes.append(final[0]["processID"])
    if len(set(processes)) != 2 or run_result.get("warmProcessID") != processes[0] or run_result.get("coldProcessID") != processes[1]:
        raise ValueError("Six-profile Live2D cold process was not independent")
    pixel_records = record.get("pixels", [])
    pixel_keys = [(r.get("runtimeID"), r.get("mode"), r.get("phase")) for r in pixel_records]
    expected_pixels = {(v, mode, phase) for v in VERSIONS for mode in MODES for phase in ("warm", "cold")}
    if Counter(pixel_keys) != Counter({key: 1 for key in expected_pixels}):
        raise ValueError("Six-profile Live2D official pixel coverage changed")
    for index, version in enumerate(sorted(VERSIONS)):
        profile = record["profiles"][version]
        expected = identity["runtimes"][version]
        if (profile.get("rendererAPISHA256") != expected["live2DAPISHA256"]
                or profile.get("runtimeProfileSHA256") != expected["profileSHA256"]
                or profile.get("hostSHA256") != expected["hostSHA256"]
                or profile.get("provenanceSHA256") != expected["provenanceSHA256"]
                or profile.get("native") != expected["native"] or profile.get("actualNativeImage") != expected["native"]["iphonesimulator"]):
            raise ValueError("Six-profile Live2D did not execute the accepted renderer/native profile")
        helper_hashes = {name + ".py": expected["files"]["base/" + name + ".py"][1] for name in LIVE2D_MODULES}
        staged_profile = read(bundle(root / FOLDER / "Artifacts", version) / "runtime-profile.json")
        if (profile.get("pythonSourceSHA256") != helper_hashes or profile.get("minimumOS") != "17.5"
                or profile.get("sdkRelease") != staged_profile["live2D"]["sdkRelease"]
                or canonical(profile.get("capabilities")) != canonical(staged_profile["live2D"]["modelPolicy"])):
            raise ValueError("Six-profile Live2D trusted dependency identity changed")
        if set(profile.get("evidence", {})) != {mode + "-" + phase for mode in MODES for phase in ("warm", "cold")}:
            raise ValueError("Six-profile Live2D per-mode evidence changed")
        for mode_index, mode in enumerate(MODES):
            session, cases = "smoke-" + str(index * 3 + mode_index + 1), {}
            for phase in ("warm", "cold"):
                case = profile["evidence"][mode + "-" + phase]
                path = output / (phase + ".events.ndjson")
                lines = [line for line in path.read_text().splitlines() if json.loads(line).get("sessionID") in (session, None)]
                subset = output / "Verified" / (version + "-" + mode + "-" + phase + ".events-subset.ndjson")
                if (case.get("sessionID") != session or subset.read_text() != "\n".join(lines) + "\n"
                        or sha(subset) != case.get("eventSubsetSHA256")):
                    raise ValueError("Six-profile Live2D borrowed another raw session")
                # The shared lifecycle observer requires the checked whole-run
                # terminal. No contextless functional evidence enters a case.
                cases[phase] = [json.loads(line) for line in lines if json.loads(line).get("sessionID") == session
                    or (json.loads(line).get("sessionID") is None and json.loads(line).get("type") == "smokePassed")]
                ready = module.common_checks(cases[phase], session)
                cap, native_mode = ready.get("capabilities", {}), mode == "nativeCompatibility"
                if (ready.get("runtimeVersion") != version or ready.get("launchMode") != mode
                        or ready.get("engineOverlaySHA256") is not None or cap.get("titlePatches") is not False
                        or cap.get("advancedTranslation") is not (not native_mode) or cap.get("live2D") is not True):
                    raise ValueError("Six-profile Live2D raw runtime/mode identity changed")
                disabled = {"native-disabled-" + name for name in ("getVariables", "setVariable", "getPreferences", "setPreferences",
                    "toggleAuto", "toggleSkip", "save", "load", "rollback", "history", "hideInterface", "showTools", "gameMenu")} if native_mode else set()
                rejected = [r for r in cases[phase] if r.get("type") == "commandRejected"]
                if (Counter(r.get("requestID") for r in rejected) != Counter({name: 1 for name in disabled})
                        or any(r.get("sessionID") != session or type(r.get("epoch")) is not int or r["epoch"] != index * 3 + mode_index + 1
                            or r.get("message") != "Reader enhancements are disabled for this session" for r in rejected)):
                    raise ValueError("Six-profile Live2D native raw rejection coverage changed")
                stock = [r for r in cases[phase] if r.get("type") == "live2DStockDependencies"]
                if len(stock) != 1 or stock[0].get("allStock") is not True or set(stock[0].get("modules", {})) != set(LIVE2D_MODULES):
                    raise ValueError("Six-profile Live2D dependency-shadow proof is incomplete")
                for name, item in stock[0]["modules"].items():
                    if (item.get("sameStockPath") is not True or item.get("sha256") != helper_hashes[name + ".py"]
                            or not str(item.get("sourceFile", "")).endswith("/RenPy" + version.replace(".", "") + ".bundle/base/" + name + ".py")):
                        raise ValueError("Six-profile Live2D executed a shadow dependency")
                if mode != "nativeCompatibility":
                    previous = output / "Verified" / (version + "-" + mode + "-warm.events-subset.ndjson") if phase == "cold" else None
                    ren.verify(subset, previous)
                    dynamic.verify(cases[phase], cases["warm"] if phase == "cold" else None)
                screenshot = output / (phase + "." + session + ".png")
                comparison = output / "Verified" / (version + "-" + mode + "-" + phase + "-pixels/comparison.json")
                pixel = read(comparison)
                certified = next(r["result"] for r in pixel_records if (r["runtimeID"], r["mode"], r["phase"]) == (version, mode, phase))
                if (sha(screenshot) != case.get("screenshotSHA256") or sha(comparison) != case.get("pixelsSHA256")
                        or canonical(pixel) != canonical(certified) or pixel.get("passed") is not True
                        or pixel.get("predeclaredThresholds") != {"rmsRGB": 3.0, "p95AbsoluteChannelError": 5}
                        or type(pixel.get("rmsRGB")) not in (int, float) or not math.isfinite(pixel["rmsRGB"]) or not 0 <= pixel["rmsRGB"] <= 3
                        or type(pixel.get("p95AbsoluteChannelError")) is not int or not 0 <= pixel["p95AbsoluteChannelError"] <= 5
                        or pixel.get("inputSHA256", {}).get("screenshot") != sha(screenshot)
                        or pixel.get("inputSHA256", {}).get("events") != sha(path)):
                    raise ValueError("Six-profile Live2D official renderer pixels changed or missed their fixed thresholds")
            if mode == "nativeCompatibility":
                module.native_checks(cases["warm"], cases["cold"])
    return {"sessions": 36, "officialPixelCases": 36, "processes": processes}


def verify_renderer_configuration(root, identity, record=None):
    baseline, _, _, _ = frozen_baseline(root)
    paths = {"rendererPolicySHA256": root / "RuntimeKit/Live2DRendererPolicy.json",
        "rendererBuilderSHA256": root / "Scripts/runtime/build_live2d.py", "rendererNoticeSHA256": root / RENDERER_NOTICE}
    expected = {"rendererPolicySHA256": RENDERER_POLICY_SHA256,
        "rendererBuilderSHA256": RENDERER_BUILDER_SHA256, "rendererNoticeSHA256": RENDERER_NOTICE_SHA256}
    for name, path in paths.items():
        if sha(path) != expected[name] or (record is not None and record.get(name) != expected[name]):
            raise ValueError("Six-profile renderer release input changed: " + name)
    previous_path = root / CANDIDATE / "RendererPolicyPredecessor/Live2DRendererPolicy.json"
    if sha(previous_path) != PREVIOUS_RENDERER_POLICY_SHA256:
        raise ValueError("Six-profile renderer predecessor policy changed")
    previous = read(previous_path)
    if set(previous.get("profiles", {})) != set(ALL_VERSIONS) - set(VERSIONS):
        raise ValueError("Six-profile renderer predecessor lost its eleven profiles")
    policy = json.loads(json.dumps(previous))
    for version in sorted(VERSIONS):
        policy["profiles"][version] = {"enabled": True, "textureExtentAPI": 0,
            "certificate": RENDERER_NOTICE.relative_to("RuntimeKit").as_posix(),
            "certificateSHA256": RENDERER_NOTICE_SHA256, "resourceQualificationID": QUALIFICATION_ID}
    if canonical(read(paths["rendererPolicySHA256"])) != canonical(policy):
        raise ValueError("Six-profile renderer policy changed the global or original eleven configuration")
    old_notice = Path("RuntimeKit") / previous["certificate"]
    if sha(root / old_notice) != previous["certificateSHA256"] or sha(root / old_notice) != sha(baseline / old_notice):
        raise ValueError("Six-profile renderer policy replaced the original eleven certificate")
    before = (baseline / "Scripts/runtime/build_live2d.py").read_bytes()
    after = paths["rendererBuilderSHA256"].read_bytes()
    if hashlib.sha256(before).hexdigest() != PREVIOUS_RENDERER_BUILDER_SHA256:
        raise ValueError("Six-profile renderer builder predecessor changed")
    start, end = b"def renderer_policy(base):\n", b"\ndef renderer_symbols():\n"
    if any(data.count(start) != 1 or data.count(end) != 1 for data in (before, after)):
        raise ValueError("Six-profile renderer builder boundary changed")
    if before.split(start, 1)[0] != after.split(start, 1)[0] or before.split(end, 1)[1] != after.split(end, 1)[1]:
        raise ValueError("Six-profile renderer builder changed outside its reviewed policy function")
    notice = read(paths["rendererNoticeSHA256"])
    if notice.get("qualificationID") != QUALIFICATION_ID or set(notice.get("profiles", {})) != set(VERSIONS):
        raise ValueError("Six-profile renderer dedicated notice names another qualification")
    spec = importlib.util.spec_from_file_location("_rr_six_renderer_builder", paths["rendererBuilderSHA256"])
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root / "Scripts/runtime"))
    try:
        spec.loader.exec_module(module)
        for version in ALL_VERSIONS:
            base = bundle(root / FOLDER / "Artifacts", version) / "base"
            if canonical(module.renderer_policy(base)) != canonical(read(base / "rr-live2d-api.json")["renderer"]):
                raise ValueError("Six-profile renderer builder does not reproduce the accepted runtime API: " + version)
    finally:
        sys.path.pop(0)
    return expected


def certificate(root):
    if CERTIFICATE_SHA256 is None or sha(root / CERTIFICATE) != CERTIFICATE_SHA256:
        raise ValueError("Six-profile capabilities have no pinned independent acceptance")
    return _validate(root, read(root / CERTIFICATE))


EVIDENCE_NAMES = {"advancedInputs", "advancedBuildProducts", "advancedVerification", "advancedWarm", "advancedCold", "advancedFrames", "advancedCompiled",
    "overlayInputs", "overlayBuildProducts", "overlayVerification", "overlayWarm", "overlayCold", "overlayFixtures",
    "overlayPreparedInputs", "overlayPreparedBuildProducts", "overlayPreparedFixtures", "overlayPreparedBuilder",
    "live2DCertificate", "live2DInputs", "live2DBuildProducts"}


def _validate(root, record):
    baseline, _, _, _ = frozen_baseline(root)
    if (type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1
            or record.get("qualificationID") != QUALIFICATION_ID or record.get("status") != "simulatorWarmColdPassed"
            or record.get("baselineRetentionSHA256") != RETENTION_SHA256 or record.get("baselineReplaySHA256") != REPLAY_SHA256
            or record.get("identitySHA256") != sha(root / FOLDER / "identity.json")):
        raise ValueError("Six-profile capability acceptance lost its independent predecessor or execution stage")
    identity = verify_prepared(root)
    if canonical(record.get("identity")) != canonical(identity):
        raise ValueError("Six-profile capability certificate names another immutable stage")
    preserved_sources(root, baseline)
    verify_renderer_configuration(root, identity, record)
    paths = verified_evidence(root, record.get("evidence", {}), EVIDENCE_NAMES)
    advanced = verify_advanced(root, paths, identity)
    overlay = verify_overlay(root, paths, identity)
    live2d = verify_live2d(root, paths, identity)
    if sha(paths["live2DCertificate"]) != record["rendererNoticeSHA256"]:
        raise ValueError("Six-profile renderer release notice differs from the actually executed Live2D certificate")
    if canonical(record.get("results")) != canonical({"advancedTranslation": advanced, "engineOverlay": overlay, "live2D": live2d}):
        raise ValueError("Six-profile capability certificate disagrees with its raw execution results")
    wanted_registry = expected_registry_bytes(root, identity)
    if record.get("registrySHA256") != hashlib.sha256(wanted_registry).hexdigest():
        raise ValueError("Six-profile capability certificate changed the direct engine-update registry")
    return record


def accept(root, advanced_output, overlay_output, live2d_output):
    identity = verify_prepared(root)
    prepared_output = Path(read(overlay_output / "inputs.json")["preparedServices"]["directory"])
    prepared_output.resolve().relative_to(root.resolve())
    names = {
        "advancedInputs": advanced_output / "inputs.json", "advancedBuildProducts": advanced_output / "build-products.json",
        "advancedVerification": advanced_output / "verification.json", "advancedWarm": advanced_output / "warm.events.ndjson",
        "advancedCold": advanced_output / "cold.events.ndjson", "advancedFrames": advanced_output / "frames.json",
        "advancedCompiled": advanced_output / "compiled-identity.json",
        "overlayInputs": overlay_output / "inputs.json", "overlayBuildProducts": overlay_output / "build-products.json",
        "overlayVerification": overlay_output / "verification.json", "overlayWarm": overlay_output / "warm.events.ndjson",
        "overlayCold": overlay_output / "cold.events.ndjson", "overlayFixtures": overlay_output / "Fixtures/fixtures.json",
        "overlayPreparedInputs": prepared_output / "inputs.json", "overlayPreparedBuildProducts": prepared_output / "build-products.json",
        "overlayPreparedFixtures": prepared_output / "Fixtures/fixtures.json", "overlayPreparedBuilder": prepared_output / "OverlayFixtureBuilder",
        "live2DCertificate": live2d_output / "live2d-review-certificate.json", "live2DInputs": live2d_output / "inputs.json",
        "live2DBuildProducts": live2d_output / "build-products.json"}
    evidence = {name: {"path": path.resolve().relative_to(root.resolve()).as_posix(), "sha256": sha(path)} for name, path in names.items()}
    paths = verified_evidence(root, evidence, EVIDENCE_NAMES)
    results = {"advancedTranslation": verify_advanced(root, paths, identity),
        "engineOverlay": verify_overlay(root, paths, identity), "live2D": verify_live2d(root, paths, identity)}
    record = {"schemaVersion": 1, "qualificationID": QUALIFICATION_ID, "status": "simulatorWarmColdPassed",
        "baselineRetentionSHA256": RETENTION_SHA256, "baselineReplaySHA256": REPLAY_SHA256,
        "identitySHA256": sha(root / FOLDER / "identity.json"), "identity": identity,
        "registrySHA256": hashlib.sha256(expected_registry_bytes(root, identity)).hexdigest(),
        "evidence": evidence, "results": results,
        "limits": ["The six unchanged physical-device native slices were statically audited, not physically executed.",
            "Original eleven resource/native identities and all seventeen translation qualifications remain independently retained.",
            "Pixel oracle covers the fixed licensed local QA models and recorded states, not every arbitrary model combination."]}
    record.update(verify_renderer_configuration(root, identity))
    if sha(paths["live2DCertificate"]) != record["rendererNoticeSHA256"]:
        raise ValueError("Six-profile renderer release notice differs from the actually executed Live2D certificate")
    target = root / CERTIFICATE
    if target.exists():
        raise ValueError("Preserve the existing six-profile capability certificate before replacement")
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def promote(root):
    record = certificate(root)
    baseline, _, _, _ = frozen_baseline(root)
    identity = record["identity"]
    registry = root / "App/Services/Import/SparkParityEngineUpdates.swift"
    registry_bytes = expected_registry_bytes(root, identity)
    if registry.read_bytes() not in ((baseline / registry.relative_to(root)).read_bytes(), registry_bytes):
        raise ValueError("The shipped registry changed outside the six-profile append")
    verify_native(root, root / "RuntimeKit/Artifacts", identity)
    for version in ALL_VERSIONS:
        actual = files(bundle(root / "RuntimeKit/Artifacts", version))
        before, after = identity["runtimes"][version]["beforeFiles"], identity["runtimes"][version]["files"]
        if set(actual) != set(before) or any(actual[name] not in (before[name], after[name]) for name in actual):
            raise ValueError("A runtime changed before six-profile promotion: " + version)
    source_catalog = root / "RuntimeKit/Artifacts/runtime-catalog.json"
    staged_catalog = root / FOLDER / "Artifacts/runtime-catalog.json"
    if source_catalog.read_bytes() not in ((baseline / source_catalog.relative_to(root)).read_bytes(), staged_catalog.read_bytes()):
        raise ValueError("The catalog changed before six-profile promotion")
    changed = []
    for version in VERSIONS:
        source, target = bundle(root / FOLDER / "Artifacts", version), bundle(root / "RuntimeKit/Artifacts", version)
        for name in ("base/rr_host.py", "base/rr-live2d-api.json", "runtime-profile.json", "provenance.json"):
            pending = (target / name).with_name((target / name).name + ".spark-six-pending")
            shutil.copy2(source / name, pending);pending.replace(target / name)
            changed.append((target / name).relative_to(root).as_posix())
        notice = root / "RuntimeKit/Notices" / ("renpy-" + version + "-provenance.json")
        pending = notice.with_name(notice.name + ".spark-six-pending")
        shutil.copy2(source / "provenance.json", pending);pending.replace(notice)
    pending = registry.with_name(registry.name + ".spark-six-pending")
    pending.write_bytes(registry_bytes);pending.replace(registry)
    pending = source_catalog.with_name(source_catalog.name + ".spark-six-pending")
    shutil.copy2(staged_catalog, pending);pending.replace(source_catalog)
    entries = {p["runtimeID"]: p for p in read(source_catalog)["profiles"]}
    _verify_added_profiles(root, entries, set(VERSIONS), record)
    report = {"schemaVersion": 1, "certificateSHA256": CERTIFICATE_SHA256,
        "identitySHA256": sha(root / FOLDER / "identity.json"), "changedResourceFiles": changed,
        "registrySHA256": sha(registry), "nativeImagesUnchanged": True, "originalElevenResourcesUnchanged": True,
        "sources": {name: sha(root / name) for name in PRESERVED_SOURCES}}
    (root / FOLDER / "promotion.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def _verify_registry_bytes(root, identity):
    if (root / "App/Services/Import/SparkParityEngineUpdates.swift").read_bytes() != expected_registry_bytes(root, identity):
        raise ValueError("Six-capability direct engine-update registry changed")


def verify_registry_successor(root):
    _verify_registry_bytes(root, certificate(root)["identity"])


def verify_added_profiles(root, entries, versions, *, built_app=None, platform=None):
    return _verify_added_profiles(root, entries, versions, certificate(root), built_app=built_app, platform=platform)


def _verify_added_profiles(root, entries, versions, record, *, built_app=None, platform=None):
    if built_app is not None:
        # Xcode's external build root may use the system /tmp alias. Resolve
        # that trusted root once; files() still rejects links inside the App.
        built_app = built_app.resolve(strict=True)
    baseline, modules, previous_entries, _ = frozen_baseline(root)
    preserved_sources(root, baseline)
    if set(entries) != set(ALL_VERSIONS) or not set(versions) <= set(VERSIONS):
        raise ValueError("Six-capability profile family changed")
    identity = record["identity"]
    verify_native(root, root / "RuntimeKit/Artifacts", identity)
    for version in ALL_VERSIONS:
        actual = bundle(root / "RuntimeKit/Artifacts", version)
        if checked_resources(root, version, actual, baseline) != identity["runtimes"][version]["files"]:
            raise ValueError("Six-capability runtime differs from its accepted stage: " + version)
        expected = dict(previous_entries[version])
        if version in VERSIONS:
            profile = read(actual / "runtime-profile.json")
            expected.update(live2D=profile["live2D"], engineOverlaySchemaVersion=1)
            expected[MARKER] = 1
        if canonical(entries[version]) != canonical(expected):
            raise ValueError("Six-capability catalog changed an unrelated field")
        if built_app is not None:
            if files(bundle(built_app, version)) != identity["runtimes"][version]["files"]:
                raise ValueError("Built six-capability runtime differs from acceptance")
            name = "RRRuntime" + version.replace(".", "")
            if modules["overlay_capability_guard"].image_identity(root, built_app / "Frameworks" / (name + ".framework") / name) != identity["runtimes"][version]["native"][platform]:
                raise ValueError("Built six-capability native image differs from acceptance")
    _verify_registry_bytes(root, record["identity"])


def verify_runtime_successor(root, version, actual, *, bridge=None):
    record = certificate(root)
    baseline, modules, _, _ = frozen_baseline(root)
    if version not in VERSIONS or checked_resources(root, version, actual, baseline) != record["identity"]["runtimes"][version]["files"]:
        raise ValueError("Six-capability runtime changed an unrelated file")
    if sha(bridge or root / "RuntimeKit/Bridge/RRRuntimeBridge.m") != sha(baseline / "RuntimeKit/Bridge/RRRuntimeBridge.m"):
        raise ValueError("Six-capability bridge changed")
    _verify_registry_bytes(root, record["identity"])
    return modules["advanced_translation17_update"].verify_runtime_successor(
        baseline, version, bundle(baseline / "RuntimeKit/Artifacts", version), bridge=baseline / "RuntimeKit/Bridge/RRRuntimeBridge.m")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify-stage", "accept", "verify", "promote"))
    parser.add_argument("--advanced-probe", type=Path)
    parser.add_argument("--overlay-probe", type=Path)
    parser.add_argument("--live2d-probe", type=Path)
    options = parser.parse_args()
    if options.command == "verify-stage":
        print(json.dumps({"passed": True, "identitySHA256": sha(ROOT / FOLDER / "identity.json"), "runtimes": sorted(verify_prepared(ROOT)["runtimes"])}, indent=2))
    elif options.command == "accept":
        if any(value is None for value in (options.advanced_probe, options.overlay_probe, options.live2d_probe)):
            parser.error("accept requires all three actual probe outputs")
        result = accept(ROOT, options.advanced_probe.resolve(), options.overlay_probe.resolve(), options.live2d_probe.resolve())
        print(json.dumps({"passed": True, "certificateSHA256": sha(ROOT / CERTIFICATE), "results": result["results"]}, indent=2))
    elif options.command == "verify":
        print(json.dumps({"passed": True, "results": certificate(ROOT)["results"]}, indent=2))
    elif options.command == "promote":
        print(json.dumps(promote(ROOT), indent=2))


if __name__ == "__main__":
    main()
