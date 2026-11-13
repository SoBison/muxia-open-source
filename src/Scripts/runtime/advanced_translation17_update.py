"""Seventeen-runtime translation successor, preserving every original proof."""
import argparse
from collections import Counter
from functools import lru_cache
import hashlib
import importlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path('RuntimeKit/Candidates/AdvancedTranslation17_20261105')
FOLDER = Path('RuntimeKit/Validation/AdvancedTranslation17_20261105')
BASELINE = Path('RuntimeKit/Validation/AdvancedTranslation17Baseline20261105')
CERTIFICATE = Path('RuntimeKit/Patches/advanced-translation17-20261105.json')
CERTIFICATE_SHA256 = '37aa64bd4ef2644f65def0647d486fd9b67570e77834c314aabccd25a4c38acc'
RETENTION_SHA256 = '209442ad5e15c78f8fa2a0c88574e1bda3c1398215d439bec673d51324f79971'
REPLAY_SHA256 = 'c7b9ed9bd3093e2044f19dd55422b075336a37f05ca291941d69715911f09fe5'
PREVIOUS_HELPER_SHA256 = 'c20451ec8b1b04174318cedbce882afbd7b16a7602015c286ef5b7d81e61e08e'
HELPER_SHA256 = '81ea6326d3f7f183419c8d112ea3ae25ca8c19bc317e73bcb72d812a9fcdcff7'
ADDED = {'7.8.4', '8.3.4', '8.5.0', '8.5.2', '7.8.8', '8.5.4'}
VERSIONS = ('8.5.3', '7.4.11', '7.5.3', '7.6.3', '7.7.3', '7.8.7', '8.0.3', '8.1.3', '8.2.3', '8.3.7', '8.4.1', '7.8.4', '8.3.4', '8.5.0', '8.5.2', '7.8.8', '8.5.4')
MODES = ('enhanced', 'minimal', 'nativeCompatibility')
SOURCE_PREDECESSORS = {
    'App/Core/AdvancedTranslationState.swift': '15a7fb516492772bcd265aab057c1d821b8c991b2db0e01c2517578e6f9c2b55',
    'App/Services/Translation/AdvancedTranslationCapture.swift': '06176145b1b6bc7fac243f745b51aa50e809fc67e1135adc6f7b023a70496c33',
    'App/Services/Translation/TranslationProvider.swift': '50d56fdbe688a93aebbda8ad2e09679287c5eccc875c2f76041e09225bc283a4',
    'App/Services/Translation/OnlineTranslationService.swift': '9ed46b5cd562a84971a25514fecb9448fbfe55e8efc27071c4dd42c4b9ad2d75',
    'App/Services/Import/BuiltinStoryRepairRuntime.swift': '9509378f1bd0e0bfa5740409f26aa3ea3a03ec000938dffc1f708195666cfe06',
}


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing or linked translation17 input: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    sha(path)
    return json.loads(path.read_bytes())


def relative(root, path):
    return path.resolve().relative_to(root.resolve()).as_posix()


def checked(root, name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Translation17 evidence must remain root-relative')
    target = root / path
    if target.resolve() != target.absolute():
        raise ValueError('Linked translation17 input')
    return target


def files(directory):
    result = {}
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('Linked translation17 resource')
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = [path.stat().st_size, sha(path)]
    return result


def directories(directory):
    return {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_dir()}


@lru_cache(maxsize=1)
def frozen_baseline(root):
    """One replay per guard process; the retained qualification root is immutable."""
    baseline = root / BASELINE
    if sha(baseline / 'retention.json') != RETENTION_SHA256 or sha(baseline / 'replay.json') != REPLAY_SHA256:
        raise ValueError('Translation17 retained baseline changed')
    retention = read(baseline / 'retention.json')
    for name, expected in dict(retention['sources'], **SOURCE_PREDECESSORS).items():
        if sha(baseline / name) != expected:
            raise ValueError('Translation17 frozen source changed: ' + name)
    alias = '_rr_translation17_frozen_runtime'
    package = types.ModuleType(alias)
    package.__path__ = [str(baseline / 'Scripts/runtime')]
    package.__package__ = alias
    sys.modules[alias] = package
    old_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        modules = {name: importlib.import_module(alias + '.' + name) for name in
                   ('advanced_translation_update', 'story_repair_update', 'spark_profile_guard', 'nightly_profile_guard', 'overlay_capability_guard')}
        advanced = modules['advanced_translation_update']
        prior_advanced = {}
        for version in advanced.VERSIONS:
            prior_advanced[version] = advanced.verify(baseline, version, bundle(baseline / 'RuntimeKit/Artifacts', version))
        entries = {r['runtimeID']: r for r in read(baseline / 'RuntimeKit/Artifacts/runtime-catalog.json')['profiles']}
        modules['spark_profile_guard'].verify(baseline, entries)
        modules['nightly_profile_guard'].verify(baseline, entries)
        modules['prior_advanced'] = prior_advanced
    finally:
        sys.dont_write_bytecode = old_bytecode
    return baseline, modules, entries


def bundle(artifacts, version):
    return artifacts / ('RenPy' + version.replace('.', '') + '.bundle')


def host_bytes(previous):
    text = previous.decode('utf-8')
    marker = '    if kind == "galleryUnlock":\n'
    imports = 'from pyobjus import autoclass\n'
    if text.count(marker) != 1 or text.count(imports) != 1 or '_advanced_translation_handle' in text:
        raise ValueError('Review the exact added-profile translation boundary')
    capability = '"advancedTranslation": False,'
    if capability in text:
        if text.count(capability) != 1:
            raise ValueError('Repeated disabled translation capability')
        text = text.replace(capability, '"advancedTranslation": enabled,', 1)
    else:
        needle = '"inlineTranslation": enabled,'
        if text.count(needle) != 1 or '"advancedTranslation"' in text:
            raise ValueError('Unexpected added-profile capability boundary')
        text = text.replace(needle, needle + ' "advancedTranslation": enabled,', 1)
    dispatch = '    if kind in ("captureTranslationFrame", "collectTranslationScript"):\n        _advanced_translation_handle(request, renpy, emit)\n        return\n'
    return text.replace(imports, 'from rr_advanced_translation import handle as _advanced_translation_handle\n' + imports, 1).replace(marker, dispatch + marker, 1).encode('utf-8')


def metadata_bytes(root, version, previous):
    profile = read(previous / 'runtime-profile.json')
    if version in ADDED:
        if any(k in profile for k in ('advancedTranslationSchemaVersion', 'engineOverlaySchemaVersion', 'storySessionPatchSchemaVersion')) or profile.get('live2D', {}).get('available') is not False:
            raise ValueError('Added profile acquired an unrelated capability')
        profile['advancedTranslationSchemaVersion'] = 1
    elif profile.get('advancedTranslationSchemaVersion') != 1:
        raise ValueError('Original profile lost its qualified translation adapter')
    profile['scriptTranslationPagingSchemaVersion'] = 1
    provenance = read(previous / 'provenance.json')
    provenance['advancedTranslation17'] = {
        'schemaVersion': 1, 'previousProvenanceSHA256': sha(previous / 'provenance.json'),
        'hostSHA256': sha(root / CANDIDATE / 'hosts' / (version + '.py')) if version in ADDED else sha(previous / 'base/rr_host.py'),
        'helperSHA256': HELPER_SHA256,
        'scope': 'screenshot and paginated bounded static script collection; existing Live2D and overlay limits retained'}
    encode = lambda v: (json.dumps(v, indent=2) + '\n').encode('utf-8')
    return {'runtime-profile.json': encode(profile), 'provenance.json': encode(provenance)}


def expected_files(root, version, baseline):
    previous = bundle(baseline / 'RuntimeKit/Artifacts', version)
    result = files(previous)
    changes = metadata_bytes(root, version, previous)
    if version in ADDED:
        candidate_host = root / CANDIDATE / 'hosts' / (version + '.py')
        if candidate_host.read_bytes() != host_bytes((previous / 'base/rr_host.py').read_bytes()):
            raise ValueError('Translation17 host changed outside the three adapter boundaries')
        changes['base/rr_host.py'] = candidate_host.read_bytes()
    helper = root / CANDIDATE / 'rr_advanced_translation.py'
    if HELPER_SHA256 is None or sha(helper) != HELPER_SHA256:
        raise ValueError('Translation17 pagination helper is not frozen')
    changes['base/rr_advanced_translation.py'] = helper.read_bytes()
    for name, data in changes.items():
        result[name] = [len(data), hashlib.sha256(data).hexdigest()]
    return result


def stage(root):
    baseline, modules, entries = frozen_baseline(root)
    output = root / FOLDER / 'Artifacts'
    if output.exists():
        raise ValueError('Preserve the existing translation17 stage before replacement')
    candidate = root / CANDIDATE
    (candidate / 'hosts').mkdir(parents=True, exist_ok=True)
    helper = baseline / 'RuntimeKit/Candidates/SparkParity20261104/rr_advanced_translation.py'
    if sha(helper) != PREVIOUS_HELPER_SHA256:
        raise ValueError('The qualified translation helper changed')
    target_helper = candidate / helper.name
    if HELPER_SHA256 is None or sha(target_helper) != HELPER_SHA256:
        raise ValueError('Run pagination tests and freeze the new helper first')
    gate_name = 'App/Services/Import/BuiltinStoryRepairRuntime.swift'
    gate_previous = (baseline / gate_name).read_bytes()
    old_helper = PREVIOUS_HELPER_SHA256.encode('ascii')
    if gate_previous.count(old_helper) != 1:
        raise ValueError('Review the exact compiled-story helper admission boundary')
    gate_candidate = candidate / 'BuiltinStoryRepairRuntime.swift'
    gate_data = gate_previous.replace(old_helper, HELPER_SHA256.encode('ascii'), 1)
    if gate_candidate.exists() and gate_candidate.read_bytes() != gate_data:
        raise ValueError('Existing compiled-story helper admission candidate changed')
    gate_candidate.write_bytes(gate_data)
    identity = {'schemaVersion': 1, 'baselineRetentionSHA256': RETENTION_SHA256,
        'baselineReplaySHA256': REPLAY_SHA256, 'helperSHA256': HELPER_SHA256,
        'baselineCatalogProfiles': list(entries.values()), 'runtimes': {}}
    output.mkdir(parents=True)
    native = modules['nightly_profile_guard'].native_identities
    tree = modules['overlay_capability_guard'].tree_digest
    for version in VERSIONS:
        previous = bundle(baseline / 'RuntimeKit/Artifacts', version)
        target = bundle(output, version)
        subprocess.run(['cp', '-cR', str(previous), str(target)], check=True)
        if version in ADDED:
            path = candidate / 'hosts' / (version + '.py')
            data = host_bytes((previous / 'base/rr_host.py').read_bytes())
            if path.exists() and path.read_bytes() != data:
                raise ValueError('Existing translation17 candidate differs')
            path.write_bytes(data)
            (target / 'base/rr_host.py').write_bytes(data)
        shutil.copy2(target_helper, target / 'base/rr_advanced_translation.py')
        for name, data in metadata_bytes(root, version, previous).items():
            (target / name).write_bytes(data)
        if files(target) != expected_files(root, version, baseline):
            raise ValueError('Unexpected translation17 stage delta')
        identity['runtimes'][version] = {'bundle': tree(target), 'profileSHA256': sha(target / 'runtime-profile.json'),
            'hostSHA256': sha(target / 'base/rr_host.py'), 'helperSHA256': sha(target / 'base/rr_advanced_translation.py'),
            'provenanceSHA256': sha(target / 'provenance.json'),
            'baseFingerprint': modules['advanced_translation_update'].fingerprint(target / 'base'),
            'native': native(baseline, baseline / 'RuntimeKit/Artifacts', version)}
    (root / FOLDER / 'identity.json').write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
    return output


def input_paths(root):
    paths = [Path(name) for name in SOURCE_PREDECESSORS]
    paths += [Path('App/Services/Translation/TranslationTextLayout.swift'), Path('RuntimeKit/Bridge/RRRuntimeBridge.m'), Path('RuntimeKit/Bridge/RRRuntimeBridge.h')]
    paths += [CANDIDATE / name for name in ('run_probe.py', 'AdvancedTranslationProbe.m', 'NativeOCRProbe.swift', 'rr_advanced_translation.py', 'game/script.rpy')]
    paths += [CANDIDATE / 'hosts' / (v + '.py') for v in sorted(ADDED)]
    paths += [FOLDER / 'identity.json']
    return paths


def expected_registry_bytes(root, identity):
    baseline, _, _ = frozen_baseline(root)
    previous = (baseline / 'App/Services/Import/SparkParityEngineUpdates.swift').read_bytes()
    expression = rb'\.init\(runtimeID: "(renpy-[0-9.]+)", previousProvenanceSHA256: "([0-9a-f]{64})", currentProvenanceSHA256: "([0-9a-f]{64})", currentBaseFingerprint: "([0-9a-f]{64})"\)'
    rows = re.findall(expression, previous)
    if not rows or len(rows) != previous.count(b'.init(runtimeID:'):
        raise ValueError('Review the exact retained engine-update registry')
    added = []
    old_keys = {(r[0].decode(), r[1].decode(), r[2].decode()) for r in rows}
    for version in sorted(VERSIONS):
        runtime = 'renpy-' + version
        origins = {r[i].decode() for r in rows if r[0].decode() == runtime for i in (1, 2)}
        origins.add(sha(bundle(baseline / 'RuntimeKit/Artifacts', version) / 'provenance.json'))
        record = identity['runtimes'][version]
        for origin in sorted(origins):
            if (runtime, origin, record['provenanceSHA256']) in old_keys:
                continue
            added.append('        .init(runtimeID: "%s", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' %
                         (runtime, origin, record['provenanceSHA256'], record['baseFingerprint']))
    end = b'\n    ]\n}\n'
    if previous.count(end) != 1 or not added:
        raise ValueError('Review engine-update append boundary')
    return previous.replace(end, b',\n' + ',\n'.join(added).encode('utf-8') + end, 1)


def verify_events(rows, phase):
    pairs = [(v, m) for v in VERSIONS for m in MODES]
    contexts = {('advanced-' + str(i), i + 1): pair for i, pair in enumerate(pairs)}
    enabled = {key: pair for key, pair in contexts.items() if pair[1] != 'nativeCompatibility'}
    of = lambda name: [r for r in rows if r.get('type') == name]
    if phase not in {'warm', 'cold'} or any(r.get('type') in {'probeFailure', 'translationProbeFailed', 'gameError', 'saveFailed', 'error', 'quarantined'} for r in rows):
        raise ValueError('Translation17 matrix contains a failure')
    final = of('translationProbePassed')
    if len(final) != 1 or final[0].get('sessions') != 51 or final[0].get('failures') != 0 or bool(final[0].get('cold')) is not (phase == 'cold'):
        raise ValueError('Translation17 phase did not complete 51 sessions')
    pid, run_id = final[0].get('processID'), final[0].get('runID')
    if type(pid) is not int or pid <= 0 or not isinstance(run_id, str) or not run_id or any(r.get('processID') != pid or r.get('runID') != run_id for r in rows):
        raise ValueError('Translation17 phase process/run identity changed')

    def key(row):
        if type(row.get('epoch')) is not int:
            raise ValueError('Translation17 epoch is not an exact integer')
        return row.get('sessionID'), row['epoch']

    def coverage(name, expected):
        current = of(name)
        if Counter(key(r) for r in current) != Counter({k: 1 for k in expected}):
            raise ValueError('Translation17 session coverage changed: ' + name)
        if any((r.get('runtime'), r.get('mode')) != expected[key(r)] for r in current):
            raise ValueError('Translation17 session/runtime binding changed: ' + name)
        return current

    for name in ('ready', 'firstFrameDrawn', 'translationProbeValidated', 'saveCommitted', 'threadAudit', 'eventQueueCleanupSummary', 'didReset'):
        coverage(name, contexts)
    if any(r.get('remaining') != [] for r in of('threadAudit')) or any(r.get('succeeded') is not True or r.get('errors') != [] for r in of('eventQueueCleanupSummary')):
        raise ValueError('Translation17 did not release session threads or events')
    if any(r.get('slot') != 'rr_suspend' for r in of('saveCommitted')):
        raise ValueError('Translation17 did not commit its exit checkpoint')
    for row in of('ready'):
        native = row['mode'] == 'nativeCompatibility'
        cap = row.get('capabilities', {})
        if cap.get('advancedTranslation') is not (not native) or cap.get('titlePatches') is not False or row.get('engineOverlaySHA256') is not None:
            raise ValueError('Translation17 capability/mode boundary changed')
        if row['runtime'] in ADDED and (cap.get('live2D') is not False or row.get('live2D', {}).get('available') is not False):
            raise ValueError('Translation17 granted an unqualified Live2D capability')
    for name in ('nativeOCRPassed', 'translationFrame', 'scriptPaginationPassed'):
        coverage(name, enabled)
    script_rows = of('translationScript')
    if any(key(r) not in enabled or (r.get('runtime'), r.get('mode')) != enabled[key(r)] for r in script_rows):
        raise ValueError('Translation17 script response escaped its enabled session')
    summaries = {key(r): r for r in of('scriptPaginationPassed')}
    for owner, summary in summaries.items():
        pages = [r for r in script_rows if key(r) == owner]
        if len(pages) < 2 or len(pages) != summary.get('pageCount') or summary.get('uniqueFixtureLines') != 1505 or summary.get('complete') is not True:
            raise ValueError('Translation17 did not traverse all recorded script pages')
        previous_position, previous_scanned, total, token = (0, 0), 0, None, None
        fixture_lines = set()
        for index, page in enumerate(pages):
            scanned, count = page.get('scannedStatements'), page.get('totalStatements')
            if page.get('requestID') != 'script-' + str(index) or type(scanned) is not int or type(count) is not int or not 0 <= scanned <= count <= 2**31 - 1 or scanned < previous_scanned:
                raise ValueError('Translation17 raw script page progress changed')
            if total is not None and count != total:
                raise ValueError('Translation17 script table changed between pages')
            total = count
            items = page.get('items')
            if not isinstance(items, list) or len(items) > 1000:
                raise ValueError('Translation17 raw page exceeded its item budget')
            for item in items:
                text = item.get('text')
                if not isinstance(text, str) or '[marker]' in text:
                    raise ValueError('Translation17 included dynamic script text')
                match = re.fullmatch(r'Pagination verification line ([0-9]{4})\.', text)
                if match: fixture_lines.add(int(match[1]))
            cursor = page.get('nextCursor')
            if cursor is None:
                if index != len(pages) - 1 or scanned != count:
                    raise ValueError('Translation17 ended before the complete statement table')
            else:
                if not isinstance(cursor, dict) or set(cursor) != {'nodeIndex', 'choiceIndex', 'statementCount', 'scriptToken'}:
                    raise ValueError('Translation17 raw cursor shape changed')
                node, choice = cursor['nodeIndex'], cursor['choiceIndex']
                current_token = cursor['scriptToken']
                if (type(node) is not int or type(choice) is not int or not 0 <= node < count or not 0 <= choice <= 1000
                        or cursor['statementCount'] != count or node != scanned or (node, choice) <= previous_position
                        or not isinstance(current_token, str) or re.fullmatch('[0-9a-f]{32}', current_token) is None
                        or (token is not None and token != current_token) or index == len(pages) - 1):
                    raise ValueError('Translation17 raw cursor did not advance within its original table')
                token, previous_position = current_token, (node, choice)
            previous_scanned = scanned
        if fixture_lines != set(range(1505)) or summary.get('scannedStatements') != total or summary.get('totalStatements') != total:
            raise ValueError('Translation17 raw pages omitted fixture text or complete progress')
    for row in of('nativeOCRPassed'):
        if any(row.get(field) is not True for field in ('regionValid', 'frameMappingVerified', 'glyphMeasurementVerified')) or row.get('captureWidth') != 640 or row.get('captureHeight') != 360:
            raise ValueError('Translation17 did not verify actual OCR geometry and native font measurement')
    if phase == 'cold':
        resumes = coverage('resumeState', contexts)
        if any(r.get('slot') != 'rr_suspend' or r.get('available') is not True for r in resumes):
            raise ValueError('Translation17 cold checkpoints were not explicitly resumed')
    return {'processID': pid, 'runID': run_id, 'sessions': 51}


def verify_story_events(rows, phase, modules, baseline):
    of = lambda name: [r for r in rows if r.get('type') == name]
    if any(r.get('type') in {'compiledProbeFailure', 'compiledProbeFailed', 'compiledMenuFailure', 'gameError', 'error', 'saveFailed', 'quarantined'} for r in rows):
        raise ValueError('Paginated helper story regression contains a failure')
    final = of('compiledProbePassed')
    if len(final) != 1 or final[0].get('sessions') != 24 or final[0].get('failures') != 0:
        raise ValueError('Paginated helper story regression did not finish')
    identity = read(baseline / 'RuntimeKit/Candidates/BuiltinStoryCompiledEdition20261104/identity.json')
    expected = Counter({(fp, mode): 2 if mode == 'enhanced' else 1 for fp in identity['fingerprints'].values() for mode in MODES})
    validated = of('compiledSessionValidated')
    if Counter((r.get('fingerprint'), r.get('mode')) for r in validated) != expected or any(r.get('value') != 73 or r.get('patchActive') is not (r.get('mode') == 'enhanced') or (phase == 'cold' and r.get('restored') != 1) for r in validated):
        raise ValueError('Paginated helper changed immutable story save semantics')
    modules['story_repair_update'].verify_menu_evidence(rows, expected, phase)
    if len(of('compiledIdentityVerified')) != 24 or any(r.get('sidecarAbsent') is not True or r.get('captureCount', 0) < 1 for r in of('compiledIdentityVerified')):
        raise ValueError('Paginated helper changed compiled-original identity capture')
    if len(of('threadAudit')) != 24 or any(r.get('remaining') != [] for r in of('threadAudit')) or len(of('eventQueueCleanupSummary')) != 24 or any(r.get('succeeded') is not True or r.get('errors') != [] for r in of('eventQueueCleanupSummary')):
        raise ValueError('Paginated helper story session did not reset cleanly')
    if not of('compiledOldTokenRejected') or not of('compiledChangedOriginalRejected'):
        raise ValueError('Paginated helper omitted immutable-story refusal controls')
    return final[0]['processID']


def _validate(root, record):
    frozen_baseline(root)
    if record.get('schemaVersion') != 1 or record.get('status') != 'simulatorWarmColdPassed' or record.get('baselineRetentionSHA256') != RETENTION_SHA256 or record.get('baselineReplaySHA256') != REPLAY_SHA256:
        raise ValueError('Translation17 has no independent acceptance')
    evidence = record.get('evidence', {})
    if set(evidence) != {'inputs', 'verification', 'warm', 'cold', 'frameManifest', 'storyInputs', 'storyVerification', 'storyWarm', 'storyCold', 'storyCache', 'storyBuildProducts'}:
        raise ValueError('Translation17 evidence inventory changed')
    paths = {}
    for name, item in evidence.items():
        path = checked(root, item['path'])
        if sha(path) != item['sha256']:
            raise ValueError('Translation17 evidence changed: ' + name)
        paths[name] = path
    inputs = read(paths['inputs'])
    if set(inputs.get('sources', {})) != {p.as_posix() for p in input_paths(root)}:
        raise ValueError('Translation17 compilation source inventory changed')
    for name, expected in inputs['sources'].items():
        if sha(checked(root, name)) != expected:
            raise ValueError('Translation17 compiled source changed: ' + name)
    identity = read(root / FOLDER / 'identity.json')
    if inputs.get('identitySHA256') != sha(root / FOLDER / 'identity.json') or record.get('identity') != identity:
        raise ValueError('Translation17 used another runtime stage')
    if read(paths['verification']).get('passed') is not True:
        raise ValueError('Translation17 verification did not finish')
    processes = []
    ocr_images = {}
    for phase in ('warm', 'cold'):
        rows = [json.loads(line) for line in paths[phase].read_text().splitlines() if line]
        processes.append(verify_events(rows, phase)['processID'])
        ocr_images.update({(phase, r['sessionID']): r.get('imageSHA256') for r in rows if r.get('type') == 'nativeOCRPassed'})
    if len(set(processes)) != 2:
        raise ValueError('Translation17 cold phase reused its warm process')
    frames = read(paths['frameManifest'])
    if frames.get('schemaVersion') != 1 or len(frames.get('frames', [])) != 68:
        raise ValueError('Translation17 actual PNG evidence is incomplete')
    seen = set()
    for item in frames['frames']:
        path = checked(root, item['path']);data = path.read_bytes()
        key = (item['phase'], item['sessionID'])
        if key in seen or sha(path) != item['sha256'] or item['sha256'] != ocr_images.get(key) or len(data) < 24 or data[:8] != b'\x89PNG\r\n\x1a\n' or struct.unpack('>II', data[16:24]) != (640, 360):
            raise ValueError('Translation17 screenshot evidence changed')
        seen.add(key)
    expected_frames = {(phase, 'advanced-' + str(i)) for phase in ('warm', 'cold') for i, (v, m) in enumerate((v, m) for v in VERSIONS for m in MODES) if m != 'nativeCompatibility'}
    if seen != expected_frames:
        raise ValueError('Translation17 screenshot/session coverage changed')
    baseline, modules, _ = frozen_baseline(root)
    story_inputs = read(paths['storyInputs'])
    for name, expected in story_inputs['sources'].items():
        if sha(checked(root, name)) != expected:
            raise ValueError('Paginated helper story source changed: ' + name)
    if story_inputs.get('privateBridgeSHA256') != sha(root / 'RuntimeKit/Bridge/RRRuntimeBridge.m'):
        raise ValueError('Paginated helper story used another native bridge')
    expected_story_files = {name: {'size': size, 'sha256': digest} for name, (size, digest) in files(bundle(root / FOLDER / 'Artifacts', '8.5.3')).items()}
    if story_inputs.get('runtimeResourceFiles') != expected_story_files:
        raise ValueError('Paginated helper story used another complete runtime resource snapshot')
    candidate = story_inputs.get('candidateIdentity', {}).get('candidateSHA256', {})
    for name, relative_name in (('rr_host.py', 'base/rr_host.py'), ('rr_story_patch.py', 'base/rr_story_patch.py'), ('bootstrap853.py', 'base/renpy/bootstrap.py'), ('rr_advanced_translation.py', 'base/rr_advanced_translation.py')):
        if candidate.get(name) != sha(bundle(root / FOLDER / 'Artifacts', '8.5.3') / relative_name):
            raise ValueError('Paginated helper story did not use the staged 853 sources')
    story_verification = read(paths['storyVerification'])
    if story_verification.get('passed') is not True or story_verification.get('buildProductsSHA256') != sha(paths['storyBuildProducts']):
        raise ValueError('Paginated helper story verification did not finish')
    if read(paths['storyBuildProducts']).get('inputsSHA256') != sha(paths['storyInputs']):
        raise ValueError('Paginated helper story products were not bound to their compilation inputs')
    story_processes = []
    for phase in ('warm', 'cold'):
        rows = [json.loads(line) for line in paths['story' + phase.title()].read_text().splitlines() if line]
        story_processes.append(verify_story_events(rows, phase, modules, baseline))
    if len(set(story_processes)) != 2:
        raise ValueError('Paginated helper story cold process was not independent')
    cache = read(paths['storyCache'])
    if cache.get('removedReconstructibleWorkspaces') != 24 or cache.get('profilesAndCompiledInstallationsUnchanged') is not True:
        raise ValueError('Paginated helper story did not prove independent cache reconstruction')
    return record


def certificate(root):
    path = root / CERTIFICATE
    if CERTIFICATE_SHA256 is None or sha(path) != CERTIFICATE_SHA256:
        raise ValueError('Translation17 acceptance certificate is not pinned')
    return _validate(root, read(path))


def verify_source_successor(root, name, expected_previous):
    if name not in SOURCE_PREDECESSORS or SOURCE_PREDECESSORS[name] != expected_previous:
        raise ValueError('Translation17 cannot authorize another source predecessor')
    record = certificate(root)
    inputs = read(checked(root, record['evidence']['inputs']['path']))
    if sha(root / name) != inputs['sources'][name]:
        raise ValueError('Translation17 source successor changed')
    if name == 'App/Services/Import/BuiltinStoryRepairRuntime.swift':
        baseline, _, _ = frozen_baseline(root)
        previous = (baseline / name).read_bytes()
        old = PREVIOUS_HELPER_SHA256.encode('ascii')
        if previous.count(old) != 1 or (root / name).read_bytes() != previous.replace(old, HELPER_SHA256.encode('ascii'), 1):
            raise ValueError('Translation17 changed another compiled-story admission rule')


def verify_added_profiles(root, entries, versions, *, built_app=None, platform=None):
    if any('sparkSixCapabilitiesSchemaVersion' in entries.get(version, {}) for version in ADDED):
        if __package__:
            from .spark_six_capabilities_guard import verify_added_profiles as verify_capability_successor
        else:
            from spark_six_capabilities_guard import verify_added_profiles as verify_capability_successor
        return verify_capability_successor(root, entries, versions, built_app=built_app, platform=platform)
    record = certificate(root)
    baseline, modules, previous_entries = frozen_baseline(root)
    if set(entries) != set(VERSIONS) or not set(versions) <= ADDED:
        raise ValueError('Translation17 profile family changed')
    tree = modules['overlay_capability_guard'].tree_digest
    native = modules['nightly_profile_guard'].native_identities
    for version in VERSIONS:
        actual = bundle(root / 'RuntimeKit/Artifacts', version)
        if files(actual) != expected_files(root, version, baseline):
            raise ValueError('Translation17 changed another runtime resource: ' + version)
        if directories(actual) != directories(bundle(baseline / 'RuntimeKit/Artifacts', version)):
            raise ValueError('Translation17 changed runtime packaging')
        expected_profile = read(actual / 'runtime-profile.json')
        old_entry = previous_entries[version]
        wanted_entry = dict(old_entry, scriptTranslationPagingSchemaVersion=1)
        if version in ADDED:
            wanted_entry['advancedTranslationSchemaVersion'] = 1
        if entries[version] != wanted_entry or any(entries[version].get(k) != value for k, value in expected_profile.items()):
            raise ValueError('Translation17 changed an unrelated catalog field')
        expected = record['identity']['runtimes'][version]
        if tree(actual) != expected['bundle'] or native(root, root / 'RuntimeKit/Artifacts', version) != expected['native']:
            raise ValueError('Translation17 runtime/native identity changed')
        if built_app is not None:
            name = 'RRRuntime' + version.replace('.', '')
            if tree(bundle(built_app, version)) != expected['bundle'] or modules['overlay_capability_guard'].image_identity(root, built_app / 'Frameworks' / (name + '.framework') / name) != expected['native'][platform]:
                raise ValueError('Built translation17 runtime differs from acceptance')


def verify_runtime_successor(root, version, actual, *, bridge=None):
    if 'sparkSixCapabilitiesSchemaVersion' in read(actual / 'runtime-profile.json'):
        if __package__:
            from .spark_six_capabilities_guard import verify_runtime_successor as verify_capability_successor
        else:
            from spark_six_capabilities_guard import verify_runtime_successor as verify_capability_successor
        return verify_capability_successor(root, version, actual, bridge=bridge)
    record = certificate(root)
    baseline, modules, _ = frozen_baseline(root)
    if version not in VERSIONS or files(actual) != expected_files(root, version, baseline):
        raise ValueError('Translation17 changed an unrelated runtime file')
    if directories(actual) != directories(bundle(baseline / 'RuntimeKit/Artifacts', version)):
        raise ValueError('Translation17 changed runtime packaging')
    if modules['overlay_capability_guard'].tree_digest(actual) != record['identity']['runtimes'][version]['bundle']:
        raise ValueError('Translation17 runtime differs from its accepted stage')
    modules['story_repair_update'].verify_bridge(baseline, bridge=bridge or root / 'RuntimeKit/Bridge/RRRuntimeBridge.m')
    if version == '8.5.3' and (root / 'App/Services/Import/SparkParityEngineUpdates.swift').read_bytes() != expected_registry_bytes(root, record['identity']):
        if __package__:
            from .spark_six_capabilities_guard import verify_registry_successor
        else:
            from spark_six_capabilities_guard import verify_registry_successor
        try:
            verify_registry_successor(root)
        except ValueError as error:
            raise ValueError('Translation17 did not retain complete direct engine-update migrations') from error
    return baseline, modules


def promote(root):
    record = certificate(root)
    baseline, _, previous_entries = frozen_baseline(root)
    identity = record['identity']
    registry = root / 'App/Services/Import/SparkParityEngineUpdates.swift'
    previous_registry = (baseline / 'App/Services/Import/SparkParityEngineUpdates.swift').read_bytes()
    wanted_registry = expected_registry_bytes(root, identity)
    if registry.read_bytes() not in (previous_registry, wanted_registry):
        raise ValueError('Engine-update registry changed outside the retained append-only successor')
    catalog_path = root / 'RuntimeKit/Artifacts/runtime-catalog.json'
    catalog = read(catalog_path)
    entries = {p['runtimeID']: p for p in catalog['profiles']}
    if set(entries) != set(VERSIONS):
        raise ValueError('Translation17 must retain the exact original seventeen runtimes')
    for version in VERSIONS:
        before = files(bundle(baseline / 'RuntimeKit/Artifacts', version))
        after = expected_files(root, version, baseline)
        actual = files(bundle(root / 'RuntimeKit/Artifacts', version))
        if any(actual.get(name) not in (before.get(name), after.get(name)) for name in set(actual) | set(before) | set(after)):
            raise ValueError('Runtime changed before translation17 promotion: ' + version)
        wanted_entry = dict(previous_entries[version], scriptTranslationPagingSchemaVersion=1)
        if version in ADDED: wanted_entry['advancedTranslationSchemaVersion'] = 1
        if entries[version] not in (previous_entries[version], wanted_entry):
            raise ValueError('Catalog changed before translation17 promotion')
    changed = []
    for version in VERSIONS:
        staged = bundle(root / FOLDER / 'Artifacts', version)
        actual = bundle(root / 'RuntimeKit/Artifacts', version)
        names = ['base/rr_advanced_translation.py', 'runtime-profile.json', 'provenance.json']
        if version in ADDED: names.append('base/rr_host.py')
        for name in names:
            pending = (actual / name).with_name((actual / name).name + '.advanced17-pending')
            shutil.copy2(staged / name, pending);pending.replace(actual / name)
            changed.append((actual / name).relative_to(root).as_posix())
        notice = root / 'RuntimeKit/Notices' / ('renpy-' + version + '-provenance.json')
        pending = notice.with_name(notice.name + '.advanced17-pending')
        shutil.copy2(staged / 'provenance.json', pending);pending.replace(notice)
    pending = registry.with_name(registry.name + '.advanced17-pending')
    pending.write_bytes(wanted_registry);pending.replace(registry)
    for profile in catalog['profiles']:
        profile['scriptTranslationPagingSchemaVersion'] = 1
        if profile['runtimeID'] in ADDED: profile['advancedTranslationSchemaVersion'] = 1
    pending = catalog_path.with_name(catalog_path.name + '.advanced17-pending')
    pending.write_text(json.dumps(catalog, indent=2) + '\n');pending.replace(catalog_path)
    verify_added_profiles(root, {p['runtimeID']: p for p in catalog['profiles']}, ADDED)
    report = {'schemaVersion': 1, 'versions': list(VERSIONS), 'helperSHA256': HELPER_SHA256,
        'certificateSHA256': CERTIFICATE_SHA256, 'changedResourceFiles': changed,
        'registrySHA256': sha(registry), 'nativeImagesUnchanged': True,
        'productionSources': {name: sha(root / name) for name in SOURCE_PREDECESSORS}}
    (root / FOLDER / 'promotion.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser();commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('stage')
    commands.add_parser('accept')
    commands.add_parser('promote')
    options = parser.parse_args()
    if options.command == 'stage':
        print(stage(ROOT));return
    if options.command == 'promote':
        print(json.dumps(promote(ROOT), indent=2));return
    evidence_dir = ROOT / FOLDER / 'Probe'
    names = {'inputs': 'inputs.json', 'verification': 'verification.json', 'warm': 'warm.events.ndjson', 'cold': 'cold.events.ndjson', 'frameManifest': 'frames.json'}
    record = {'schemaVersion': 1, 'status': 'simulatorWarmColdPassed', 'baselineRetentionSHA256': RETENTION_SHA256,
        'baselineReplaySHA256': REPLAY_SHA256, 'identity': read(ROOT / FOLDER / 'identity.json'),
        'evidence': {name: {'path': relative(ROOT, evidence_dir / file), 'sha256': sha(evidence_dir / file)} for name, file in names.items()}}
    story_dir = ROOT / FOLDER / 'StoryProbe'
    for name, file in {'storyInputs': 'inputs.json', 'storyVerification': 'verification.json', 'storyWarm': 'warm.events.ndjson', 'storyCold': 'cold.events.ndjson', 'storyCache': 'cache-rebuild.json', 'storyBuildProducts': 'build-products.json'}.items():
        record['evidence'][name] = {'path': relative(ROOT, story_dir / file), 'sha256': sha(story_dir / file)}
    _validate(ROOT, record)
    target = ROOT / CERTIFICATE
    if target.exists():raise ValueError('Preserve the old translation17 certificate before replacement')
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print('Reviewed translation17 certificate SHA256=' + sha(target))


if __name__ == '__main__':
    main()
