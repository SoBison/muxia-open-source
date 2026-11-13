#!/usr/bin/env python3
"""Explicit fixed-device software successor. Candidate inspection grants no execution qualification."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import sys
import shlex
import textwrap

sys.dont_write_bytecode = True
CERTIFICATE_SHA256 = '740774667ca39d80e883db86ff0e39aaca998a369fbe696dfde3f0ab59f9356b'
CERTIFICATE = Path('RuntimeKit/Patches/legacy-core-integration-20261111.json')
BASE = Path('RuntimeKit/Candidates/LegacyCoreIntegration20261111')
BASELINE = BASE / 'BaselinePublishedSecond'
BASELINE_SHA = '968cfc052a5a3316ad4f7b51d00e1fcba03585e27269ac2273f7a2908591f588'
IDENTITY = BASE / 'ResourcesFirst/identity.json'
IDENTITY_SHA = 'ac34b913afc5dabc1bfc1302d67fed55e3fecb23715994b3ea59c709de8567c4'
PARENT_GUARD = 'Scripts/runtime/unicode_save_slots_guard.py'
PARENT_GUARD_SHA = 'be15001a02f2b7dbe16c93c2037ba8cd42151fa8d00e879789dd82723c173cef'
PARENT_CERT = 'RuntimeKit/Patches/unicode-save-slots-20261111.json'
PARENT_CERT_SHA = 'ab45575dd0e06ad5079eda6d0fbba548685733cec96638adcd280e7e1f4f34e6'
FINAL = 'RuntimeKit/Validation/SparkUnicodeSlots20261111/final-verification.json'
FINAL_SHA = 'd5a5822c27524f84d6866fce138918eab24e07190246b67277c6f8a524db63d1'
REPLAY = BASE / 'ParentReplayAPI/First/replay.py'
REPLAY_SHA = '537bc26aa5302deb2fd4b11ce6f0efc78f887eea15f658294926ed91935b6d5d'
FULL_REPLAY = 'RuntimeKit/Validation/LegacyCoreIntegration20261111/ParentReplayAPI/FullFirst/verification.json'
FULL_REPLAY_SHA = 'bbeb802447421b1fb0305c5dd49f8d0cca9405740673de7e2f26b2f28efbb709'
HELPER = BASE / 'RuntimeAdapter/ReleaseSourceV2/rr_legacy_live2d.py'
HELPER_SHA = '81af7fec339fb500a34e0ff3cf8868829411b13e95ce9fba190ce8d38c796252'
BRIDGE = BASE / 'Integration/BridgeSecond/RRRuntimeBridge.m'
BRIDGE_SHA = 'd087603b3f9d08795fce839edc50c4b26b37f5c51f41e421884a6b9264be3355'
HEADER = BASE / 'Integration/BridgeSecond/RRLive2DLegacyContract.h'
HEADER_SHA = '3793f3729bc77625f31b8c360e5cbe2282287ab2d3d31d5d6d3c584cf8bd2fac'
PACKAGING = BASE / 'Packaging/legacy_core_candidate.py'
PACKAGING_SHA = '7b1181dec12cb97359676186f97c681504973b7279c3a311765b25f99b80cfdc'
PROJECTS = BASE / 'ProjectsAndLegal'
PROJECT_PLAN = 'RuntimeKit/Validation/LegacyCoreIntegration20261111/ProjectsAndLegal/verification.json'
PROJECT_PLAN_SHA = '779271aab0ce9f5ed2125a26a03c0554241c7d3aa7227c82a3fcc946edb9c6b1'
LEGAL_PLAN = 'RuntimeKit/Validation/LegacyCoreIntegration20261111/ProjectsAndLegal/legal-extension.json'
LEGAL_PLAN_SHA = 'a47b9e7a4e7501461d43de38e73a61e5166555adc189bca3933a9e42beae6d6c'
BUILT_PARENT_SHA = 'f22dd4fa79bca73b58480f334fd9ff318d45e4947f0eb8e594e41d873db059d7'
MARKER = 'PASS: COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED; fixed legacy Core software integration is not oldOS/device execution qualification'
CORE_IMAGE_SHA = 'bf1918a6f570835676e33916accd040d588b2545ac9782154859261f38874834'
ARCHIVE_SHA = '073f623fc3fb06c192e68bb5287fdb9dab1952164c2a956dec6d4b45fd342ffb'


def safe(path, directory=False):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not (path.is_dir() if directory else path.is_file()):
        raise ValueError('Missing, linked or nonregular successor input: ' + str(path))
    return path


def sha(path):
    return hashlib.sha256(safe(path).read_bytes()).hexdigest()


def read(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate JSON key')
            value[key] = item
        return value
    return json.loads(safe(path).read_bytes(), object_pairs_hook=unique)


def load(root, name, digest, module_name):
    path = safe(root / name)
    if sha(path) != digest:
        raise ValueError('An exact retained source changed: ' + str(name))
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parent(root):
    module = load(root, PARENT_GUARD, PARENT_GUARD_SHA, 'legacy_core_original_unicode_parent')
    if sha(root / PARENT_CERT) != PARENT_CERT_SHA or module.CERTIFICATE_SHA256 != PARENT_CERT_SHA:
        raise ValueError('The exact published Unicode qualification changed')
    return module


def api(root):
    return parent(root).parent(root)


def reference(root, value):
    return api(root).ref(root, value)


def baseline(root):
    old = api(root)
    if sha(root / BASELINE / 'identity.json') != BASELINE_SHA or sha(root / FINAL) != FINAL_SHA:
        raise ValueError('The complete actual published predecessor closure changed')
    value = read(root / BASELINE / 'identity.json')
    if (value.get('passed') is not True or value.get('actualPublishedPredecessor') is not True or
            value.get('predecessorReceipt') != {'path': FINAL, 'sha256': FINAL_SHA} or
            len(value.get('sources', {})) != 238 or len(value.get('protected13', {})) != 13):
        raise ValueError('The completed actual published predecessor is required')
    if (old.filemap(root / BASELINE / 'Artifacts') != value['artifacts'] or
            old.directories(root / BASELINE / 'Artifacts') != value['artifactDirectories'] or
            old.filemap(root / BASELINE / 'SourceInputs') != value['sources'] or
            old.directories(root / BASELINE / 'SourceInputs') != value['sourceDirectories']):
        raise ValueError('The actual complete saved predecessor tree changed')
    return value


def retained_replay(root, *, execute=False, replay=True):
    module = load(root, REPLAY, REPLAY_SHA, 'legacy_core_exact_predecessor_replay')
    if Path(root).absolute() != module.ROOT:
        raise ValueError('Historical evidence must retain its real original global root')
    if sha(root / FULL_REPLAY) != FULL_REPLAY_SHA:
        raise ValueError('The actual complete predecessor replay receipt changed')
    evidence = read(root / FULL_REPLAY)
    if (evidence.get('passed') is not True or evidence.get('fullActualPredecessorReplay') is not True or
            evidence.get('newQualificationGranted') is not False or evidence.get('inputsUnchanged') is not True):
        raise ValueError('An actual full predecessor replay is required')
    for name, digest in evidence['inputs'].items():
        if sha(root / name) != digest:
            raise ValueError('A real predecessor replay input changed: ' + name)
    return module.verify_predecessor(root, replay=replay) if execute else evidence


def expected_main(data):
    marker = b'_save_slots = _save_slots_module.Session(session, rr_host)\n'
    cleanup = b'finally:\n    try:\n        _save_slots.finish()\n    finally:\n        _preferences.finish()\n'
    if data.count(marker) != 1 or data.count(cleanup) != 1 or not data.endswith(cleanup) or b'rr_legacy_live2d' in data:
        raise ValueError('Unknown published trusted-entry/cleanup shape')
    addition = (b'_legacy_live2d_module = _stock_module("rr_legacy_live2d", "rr_legacy_live2d.py")\n'
        b'_legacy_live2d = _legacy_live2d_module.Session(session, rr_host, _stock_module("rr_live2d_backend", "rr_live2d_backend.py"))\n')
    updated = data.replace(marker, marker + addition, 1)
    final = (b'finally:\n    try:\n        _legacy_live2d.finish()\n    finally:\n        try:\n            _save_slots.finish()\n        finally:\n            _preferences.finish()\n')
    updated = updated[:-len(cleanup)] + final
    compile(updated, 'main.py', 'exec')
    return updated


def expected_registry(old, original, inline, runtimes):
    rows, shipped = old.registry_rows(original), old.registry_rows(inline)
    if len(rows) != 753 or len(shipped) != 36 or set(runtimes) != set(old.VERSIONS):
        raise ValueError('The complete753 plus shipped36 migration history is required')
    keys = {row[:3] for row in rows + shipped}
    additions, counts = [], {}
    for version in old.VERSIONS:
        runtime = ('renpy-' + version).encode()
        target = runtimes[version]['provenanceSHA256'].encode()
        origins = {row[i] for row in rows + shipped if row[0] == runtime for i in (1, 2)}
        origins.add(runtimes[version]['previousProvenanceSHA256'].encode())
        counts[version] = 0
        for origin in sorted(origins):
            key = runtime, origin, target
            if origin == target or key in keys:
                continue
            additions.append('        .init(runtimeID: "%s", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' %
                (runtime.decode(), origin.decode(), target.decode(), runtimes[version]['baseFingerprint']))
            keys.add(key)
            counts[version] += 1
    boundary = b'\n    ]\n}\n'
    if original.count(boundary) != 1 or len(additions) != 185:
        raise ValueError('The deterministic minimum185 direct edges changed')
    result = original.replace(boundary, b',\n' + ',\n'.join(additions).encode() + boundary, 1)
    if len(old.registry_rows(result)) != 938:
        raise ValueError('The complete938 registry successor is required')
    return result, counts


def expected_tool(name, original):
    if name.lower() == 'scripts/check_app_artifacts.py':
        before = b'from runtime import unicode_save_slots_guard as capability_guard\n'
        if original.count(before) != 1 or b'legacy_core_integration_guard' in original:
            raise ValueError('Unknown published artifact-check dispatcher')
        return original.replace(before, b'from runtime import legacy_core_integration_guard as capability_guard\n', 1)
    if name.lower() == 'scripts/prepare_legal_manifest.py':
        marker = b"            if (root / 'RuntimeKit/Patches/unicode-save-slots-20261111.json').is_file():\n"
        if original.count(marker) != 1 or b'legacy_core_integration_guard' in original:
            raise ValueError('Unknown published legal dispatcher')
        branch = ("            if (root / 'RuntimeKit/Patches/legacy-core-integration-20261111.json').is_file():\n"
            "                from runtime.legacy_core_integration_guard import platform_supplement_predecessor\n"
            "                from runtime.runtime_features_guard import NOTICE_NAMES as FEATURE_NOTICES\n"
            "                from runtime.legacy_compatibility_guard import NOTICE_NAMES as LEGACY_NOTICES\n"
            "                NOTICE_NAMES = (*FKEY_NOTICES, *FEATURE_NOTICES, *LEGACY_NOTICES)\n"
            "                predecessor = platform_supplement_predecessor(root)\n"
            "            elif (root / 'RuntimeKit/Patches/unicode-save-slots-20261111.json').is_file():\n").encode()
        return original.replace(marker, branch, 1)
    raise ValueError('Unknown successor publication tool')


def plans(root):
    if sha(root / PROJECT_PLAN) != PROJECT_PLAN_SHA or sha(root / LEGAL_PLAN) != LEGAL_PLAN_SHA:
        raise ValueError('The exact project/legal preparation plan changed')
    project, legal = read(root / PROJECT_PLAN), read(root / LEGAL_PLAN)
    if (project.get('passed') is not True or project.get('candidateOnly') is not True or
            project.get('identity') != {'path': str(IDENTITY), 'sha256': IDENTITY_SHA} or
            legal.get('passed') is not True or legal.get('newDocuments') != 34 or legal.get('oldDocuments') != 33):
        raise ValueError('The exact isolated project/34-document plan is required')
    for name in ['builder', 'packagingVerifier', 'qaProject', 'formalSuccessor', 'generatorSuccessor', 'legalExtension']:
        reference(root, project[name])
    return project, legal


def expected_legal_json(root):
    unused, legal = plans(root)
    original = read(reference(root, legal['oldLiteral']))
    grouped = {}
    added = []
    def legacy():
        for name in ('LICENSE.md', 'RedistributableFiles.txt', 'Live2DFramework-LICENSE.md', 'Live2DFramework.patch'):
            data = (root / packaging(root).SOURCE / name).read_bytes()
            category = 'modifications' if name.endswith('.patch') else 'live2d'
            digest = hashlib.sha256(data).hexdigest()
            key = category, digest
            if key not in grouped:
                grouped[key] = dict(id=category + '-' + digest[:20], title='Live2D 5-r.1 Core 与 Framework',
                    category=category, paths=[], byteCount=len(data), sha256=digest)
            path = 'LegalResources/live2d-legacy-' + name
            grouped[key]['paths'].append(path)
            added.append(path)
    inserted = False
    for document in original['documents']:
        if 'LegalResources/7zip-lzma-sdk.txt' in document['paths']:
            if inserted:
                raise ValueError('Repeated supplemental legal insertion boundary')
            legacy()
            inserted = True
        key = document['category'], document['sha256']
        if key in grouped:
            raise ValueError('The actual original manifest grouping changed')
        grouped[key] = copy.deepcopy(document)
    if not inserted or added != legal['addedPaths']:
        raise ValueError('Missing exact four legal paths')
    value = copy.deepcopy(original)
    value['documents'] = list(grouped.values())
    data = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    if len(value['documents']) != 34 or hashlib.sha256(data).hexdigest() != legal['fullResources']['release-legal-manifest.json']:
        raise ValueError('The exact legal literal recipe changed')
    return data


def legal_resources(root, folder):
    old = api(root)
    unused, legal = plans(root)
    actual = old.filemap(folder)
    if {name: row['sha256'] for name, row in actual.items()} != legal['fullResources'] or old.directories(folder) != {'.': 0o755}:
        raise ValueError('The complete fixed legal-resource leaf inventory changed')
    if (folder / 'release-legal-manifest.json').read_bytes() != expected_legal_json(root):
        raise ValueError('The actual literal differs from the exact34-document recipe')
    return actual


def packaging(root):
    return load(root, PACKAGING, PACKAGING_SHA, 'legacy_core_fixed_packaging')


def project_objects(path):
    output = subprocess.check_output(['plutil', '-convert', 'json', '-o', '-', str(safe(path))])
    value = json.loads(output)
    if type(value) is not dict or type(value.get('objects')) is not dict:
        raise ValueError('Invalid Xcode project object inventory')
    return value


def validate_formal_project(root, path):
    value = project_objects(path)
    objects = value['objects']
    apps = [item for item in objects.values() if item.get('isa') == 'PBXNativeTarget' and item.get('name') == 'RenReader']
    if len(apps) != 1:
        raise ValueError('The single actual main App target is required')
    app = apps[0]
    parents = {}
    for key, item in objects.items():
        if item.get('isa') in {'PBXGroup', 'PBXVariantGroup'}:
            for child in item.get('children', []):
                if child in parents and parents[child] != key:
                    raise ValueError('A project source has ambiguous parent groups')
                parents[child] = key
    def resolve(key, seen=()):
        if key in seen:
            raise ValueError('Cyclic Xcode source groups')
        item = objects[key]
        tree, text = item.get('sourceTree', '<group>'), item.get('path', '')
        for variable in ('$(SRCROOT)', '${SRCROOT}', '$SRCROOT', '$(SOURCE_ROOT)'):
            if text.startswith(variable):
                text = str(root) + text[len(variable):]
                break
        relative = Path(text)
        if relative.is_absolute():
            return relative
        if tree == '<absolute>':
            raise ValueError('An absolute Bridge reference must carry an absolute path')
        if tree == 'SOURCE_ROOT':
            base = root
        elif tree == '<group>':
            base = resolve(parents[key], seen + (key,)) if key in parents else root
        else:
            raise ValueError('Unsupported source tree for the actual Bridge')
        return base / relative
    phases = [objects[key] for key in app['buildPhases']]
    bridges = []
    for phase in phases:
        if phase.get('isa') != 'PBXSourcesBuildPhase':
            continue
        for file in phase.get('files', []):
            key = objects[file].get('fileRef')
            if key is not None and Path(objects[key].get('path', '')).name == 'RRRuntimeBridge.m':
                bridges.append(resolve(key))
    if bridges != [root / 'RuntimeKit/Bridge/RRRuntimeBridge.m']:
        raise ValueError('The main target must compile only the real formal Bridge source')
    guard = '$SRCROOT/Scripts/runtime/legacy_core_integration_guard.py'
    command = ['python3', guard, '--root', '$SRCROOT', '--contract', '$SRCROOT/RuntimeKit/Patches/overlay-capability-853.json']
    post = command + ['--built-app', '$TARGET_BUILD_DIR/$WRAPPER_NAME', '--platform', '$PLATFORM_NAME', '--configuration', '$CONFIGURATION']
    guards = []
    embeds = []
    for index, phase in enumerate(phases):
        if phase.get('isa') != 'PBXShellScriptBuildPhase':
            continue
        script = phase.get('shellScript', '')
        if re.search(r'[A-Za-z0-9_]+_guard\.py', script):
            tokens = shlex.split(script)
            if tokens not in (command, post):
                raise ValueError('A runtime guard phase is not the exact formal successor command')
            guards.append((index, tokens == post))
        if 'RRLive2DLegacyCore.framework' in script:
            embeds.append((index, script))
    if sorted(is_post for index, is_post in guards) != [False, True] or len(embeds) != 1:
        raise ValueError('Exactly two runtime guard phases and one device-only Core phase are required')
    project, unused = plans(root)
    planned = project_objects(reference(root, project['formalSuccessor']))['objects']
    strict = [item['shellScript'] for item in planned.values() if item.get('isa') == 'PBXShellScriptBuildPhase'
        and item.get('name') == 'Embed Device-Only Legacy Live2D Core']
    generator = reference(root, project['generatorSuccessor']).read_text()
    match = re.findall(r'  legacy\.shell_script = <<~SCRIPT\n(.*?)^  SCRIPT$', generator, re.S | re.M)
    if len(strict) != 1 or len(match) != 1:
        raise ValueError('The reviewed strict/generator embed recipes changed')
    accepted = {strict[0], textwrap.dedent(match[0])}
    if embeds[0][1] not in accepted:
        raise ValueError('The device-only Core phase differs from both reviewed recipes')
    pre_index = next(index for index, is_post in guards if not is_post)
    post_index = next(index for index, is_post in guards if is_post)
    if not pre_index < embeds[0][0] < post_index:
        raise ValueError('The Core copy/sign phase must be bounded by the pre/post guards')
    for phase in phases:
        if phase.get('isa') == 'PBXFrameworksBuildPhase':
            for file in phase.get('files', []):
                entry = objects[file]
                linked = objects.get(entry.get('fileRef', entry.get('productRef')), {})
                if 'RRLive2DLegacyCore' in json.dumps([entry, linked]):
                    raise ValueError('Legacy Core cannot be eagerly linked')
    project_object = objects[value['rootObject']]
    external = []
    for owner in (project_object, app):
        configuration = objects[owner['buildConfigurationList']]
        for key in configuration['buildConfigurations']:
            config = objects[key]
            if config.get('baseConfigurationReference') is not None:
                external.append(config['baseConfigurationReference'])
            for setting, flags in config.get('buildSettings', {}).items():
                if setting.startswith('OTHER_LDFLAGS') and 'RRLive2DLegacyCore' in json.dumps(flags):
                    raise ValueError('Legacy Core cannot be eagerly linked through explicit App/project linker flags')
    return dict(passed=True, structuralProjectOnly=True, exactFormalBridge=True, runtimeGuardPhases=2,
        deviceOnlyLegacyPhase=True, explicitEagerLegacyLinked=False, externalBaseConfigurations=external,
        eagerLinkBinaryValidationRequired=True, unrelatedAppReferencesOrSettingsFrozen=False)


def inspect_candidate(root, identity, *, artifacts_root=None, source_root=None):
    root = safe(root, directory=True)
    old = api(root)
    if sha(root / IDENTITY) != IDENTITY_SHA or identity != read(root / IDENTITY):
        raise ValueError('Only the exact frozen actual candidate identity is accepted')
    if (identity.get('schemaVersion') != 1 or type(identity['schemaVersion']) is not int or
            identity.get('kind') != 'legacyCoreSoftwareResourceCandidate' or identity.get('passed') is not True or
            identity.get('componentOnly') is not True or any(identity.get(k) is not False for k in
            ['runtimeExecutionQualified', 'oldOSExecutionQualified', 'publicationQualified']) or
            identity.get('predecessorIdentity') != {'path': str(BASELINE / 'identity.json'), 'sha256': BASELINE_SHA}):
        raise ValueError('The static-only frozen candidate scope changed')
    for name, digest in identity['buildInputs'].items():
        if sha(root / name) != digest:
            raise ValueError('A frozen actual candidate input changed: ' + name)
    if sha(root / HELPER) != HELPER_SHA or sha(root / BRIDGE) != BRIDGE_SHA or sha(root / HEADER) != HEADER_SHA:
        raise ValueError('The reviewed helper/Bridge/header changed')
    before = baseline(root)
    retained_replay(root)
    if identity['predecessorArtifactsPath'] != str(BASELINE / 'Artifacts') or identity['predecessorSourcesPath'] != str(BASELINE / 'SourceInputs'):
        raise ValueError('The true predecessor roots cannot be substituted')
    artifacts = safe(artifacts_root or root / identity['candidateArtifactsPath'], directory=True)
    sources = safe(source_root or root / identity['candidateSourcesPath'], directory=True)
    candidate_artifacts = root / BASE / 'ResourcesFirst/Artifacts'
    candidate_sources = root / BASE / 'ResourcesFirst/CandidateSources'
    formal = artifacts == root / 'RuntimeKit/Artifacts' and sources == root
    if not formal and (artifacts != candidate_artifacts or sources != candidate_sources):
        raise ValueError('Only the fixed actual candidate or actual formal roots are allowed')
    after = old.filemap(artifacts)
    if after != identity['candidateArtifacts'] or old.directories(artifacts) != identity['artifactDirectories']:
        raise ValueError('Actual candidate artifact inventory/modes changed')
    allowed, added = {'runtime-catalog.json'}, set()
    for version in old.VERSIONS:
        prefix = 'RenPy' + version.replace('.', '') + '.bundle/'
        allowed.update(prefix + name for name in ['base/main.py', 'runtime-profile.json', 'provenance.json'])
        added.add(prefix + 'base/rr_legacy_live2d.py')
    changed = {name for name, record in after.items() if before['artifacts'].get(name) != record}
    if set(after) != set(before['artifacts']) | added or changed != allowed | added or len(changed) != 69:
        raise ValueError('An artifact changed outside the exact69 additive leaves')
    if identity['allowedDelta'] != {name: dict(previous=before['artifacts'].get(name), candidate=after[name]) for name in changed}:
        raise ValueError('The exact resource-delta receipt changed')
    if set(identity['runtimes']) != set(old.VERSIONS):
        raise ValueError('The exact17 runtime set is required')
    predecessor = root / BASELINE / 'Artifacts'
    for version in old.VERSIONS:
        original, actual = old.bundle(predecessor, version), old.bundle(artifacts, version)
        if (actual / 'base/main.py').read_bytes() != expected_main((original / 'base/main.py').read_bytes()) or sha(actual / 'base/rr_legacy_live2d.py') != HELPER_SHA:
            raise ValueError('The trusted stock-loader/helper recipe changed: ' + version)
        profile = read(original / 'runtime-profile.json')
        profile.update(legacyLive2DSoftwareAdapterSchemaVersion=1, legacyLive2DSoftwareQualification='candidate-component-only')
        if (actual / 'runtime-profile.json').read_bytes() != old.encoded(profile):
            raise ValueError('The exact two-field runtime profile recipe changed')
        provenance = read(original / 'provenance.json')
        provenance['legacyLive2DSoftwareCandidate'] = dict(schemaVersion=1, previousProvenanceSHA256=sha(original / 'provenance.json'),
            mainSHA256=sha(actual / 'base/main.py'), helperSHA256=HELPER_SHA, hostUnchangedSHA256=sha(original / 'base/rr_host.py'),
            backendUnchangedSHA256=sha(original / 'base/rr_live2d_backend.py'), coreImageIdentitySHA256=CORE_IMAGE_SHA,
            archiveSHA256=ARCHIVE_SHA, oldOSExecutionQualified=False, status='component-unqualified')
        if (actual / 'provenance.json').read_bytes() != old.encoded(provenance):
            raise ValueError('The exact software-only provenance recipe changed')
        record = dict(previousProvenanceSHA256=sha(original / 'provenance.json'), provenanceSHA256=sha(actual / 'provenance.json'),
            baseFingerprint=old.fingerprint(actual / 'base'), mainSHA256=sha(actual / 'base/main.py'), helperSHA256=HELPER_SHA,
            hostSHA256=sha(actual / 'base/rr_host.py'), backendSHA256=sha(actual / 'base/rr_live2d_backend.py'), profileSHA256=sha(actual / 'runtime-profile.json'))
        if identity['runtimes'][version] != record:
            raise ValueError('The actual17 runtime identity changed')
    catalog = read(predecessor / 'runtime-catalog.json')
    for row in catalog['profiles']:
        row.update(legacyLive2DSoftwareAdapterSchemaVersion=1, legacyLive2DSoftwareQualification='candidate-component-only')
    if (artifacts / 'runtime-catalog.json').read_bytes() != old.encoded(catalog):
        raise ValueError('The exact catalog recipe changed')
    original_sources = root / BASELINE / 'SourceInputs'
    registry, counts = expected_registry(old, (original_sources / old.REGISTRY).read_bytes(), (original_sources / old.INLINE_REGISTRY).read_bytes(), identity['runtimes'])
    if ((sources / old.REGISTRY).read_bytes() != registry or sha(sources / old.REGISTRY) != identity['registrySHA256'] or
            identity['registryRows'] != 938 or identity['registryAddedDirectEdges'] != 185 or identity['directEdgesByRuntime'] != counts):
        raise ValueError('The complete minimal938 registry successor changed')
    project, unused = plans(root)
    for name, record in before['sources'].items():
        path, expected, mode = sources / name, (original_sources / name).read_bytes(), record['mode']
        if name == old.REGISTRY:
            expected = registry
        elif name == 'RuntimeKit/Bridge/RRRuntimeBridge.m':
            expected = (root / BRIDGE).read_bytes()
        elif name.startswith('RuntimeKit/Notices/renpy-') and name.endswith('-provenance.json'):
            version = Path(name).name[len('renpy-'):-len('-provenance.json')]
            if version in old.VERSIONS:
                expected = (old.bundle(artifacts, version) / 'provenance.json').read_bytes()
        elif formal and name.lower() in {'scripts/prepare_legal_manifest.py', 'scripts/check_app_artifacts.py'}:
            expected = expected_tool(name, expected)
        elif formal and name == 'RenReader.xcodeproj/project.pbxproj':
            validate_formal_project(root, path)
            continue
        elif formal and name.lower() == 'scripts/generate_project.rb':
            expected_path = reference(root, project['generatorSuccessor'])
            expected, mode = expected_path.read_bytes(), stat.S_IMODE(expected_path.stat().st_mode)
        if safe(path).read_bytes() != expected or stat.S_IMODE(path.stat().st_mode) != mode:
            raise ValueError('A preserved source or explicit successor recipe changed: ' + name)
    header = sources / 'RuntimeKit/Bridge/RRLive2DLegacyContract.h'
    if sha(header) != HEADER_SHA or stat.S_IMODE(header.stat().st_mode) != stat.S_IMODE((root / HEADER).stat().st_mode):
        raise ValueError('The one new Bridge header differs')
    if not formal and (old.filemap(sources) != identity['candidateSources'] or old.directories(sources) != identity['sourceDirectories']):
        raise ValueError('The complete candidate source inventory/modes changed')
    for folder in ['RuntimeKit/Native', 'RuntimeKit/Bridge']:
        expected = old.filemap(original_sources / folder)
        if folder.endswith('Bridge'):
            expected['RRRuntimeBridge.m'] = old.filemap(sources / folder)['RRRuntimeBridge.m']
            expected['RRLive2DLegacyContract.h'] = old.filemap(sources / folder)['RRLive2DLegacyContract.h']
        if old.filemap(sources / folder) != expected or old.directories(sources / folder) != old.directories(original_sources / folder):
            raise ValueError('Native/Bridge complete directory inventory changed')
    legal_resources(root, root / 'App/LegalResources' if formal else root / PROJECTS / 'LegalResources')
    legacy_source(root, formal=formal)
    return dict(passed=True, staticInspectionOnly=True, runtimeExecutionQualified=False, uiQualified=False,
        publicationQualified=False, legacyCoreSoftwareIntegrated=False, oldOSExecutionQualified=False,
        runtimes=17, changedLeaves=69, nativePackagesUnchanged=True, registryRows=938, registryAddedDirectEdges=185)


def legacy_source(root, *, formal):
    pack = packaging(root)
    historical = root / pack.SOURCE
    source = root / 'RuntimeKit/Optional/RRLive2DLegacyCore.framework' if formal else historical
    original = pack.verify(source, root, require_signed=False)
    if original['image']['signed'] or set(original['filesSHA256']) != set(pack.FILES) or api(root).filemap(source) != api(root).filemap(historical):
        raise ValueError('The source must be the exact fixed unsigned eight-leaf device Core')
    return source


def verify_legacy_target(root, app, platform, *, formal):
    pack = packaging(root)
    target = app / 'Frameworks/RRLive2DLegacyCore.framework'
    if platform != 'iphoneos':
        if target.exists() or target.is_symlink():
            raise ValueError('Device-only legacy Core is forbidden in simulator packages')
        return
    info = plistlib.loads(safe(app / 'Info.plist').read_bytes())
    name = info.get('CFBundleExecutable')
    if (info.get('CFBundleSupportedPlatforms') != ['iPhoneOS'] or type(name) is not str or not name
            or name in ('.', '..') or '/' in name or '\\' in name):
        raise ValueError('Only a real device App with a safe executable can integrate this Core')
    pack.device_app_image(safe(app / name))
    source = legacy_source(root, formal=formal)
    original = pack.verify(source, root, require_signed=False)
    actual = pack.verify(target, root, require_signed=True)
    if actual['image']['normalizedSHA256'] != original['image']['normalizedSHA256']:
        raise ValueError('Packaged legacy Core differs from its exact raw source')
    for name in pack.FILES:
        if name != pack.NAME and stat.S_IMODE((target / name).stat().st_mode) != stat.S_IMODE((source / name).stat().st_mode):
            raise ValueError('Packaged legacy Core resource mode changed')


def native_copy_attributes(root, *, formal):
    project, unused = plans(root)
    path = root / 'RenReader.xcodeproj/project.pbxproj' if formal else reference(root, project['qaProject'])
    value = project_objects(path)
    objects = value['objects']
    apps = [row for row in objects.values() if row.get('isa') == 'PBXNativeTarget' and row.get('name') == 'RenReader']
    if len(apps) != 1:
        raise ValueError('The exact main App framework copy owner is required')
    result = {}
    for key in apps[0]['buildPhases']:
        phase = objects[key]
        if phase.get('isa') != 'PBXCopyFilesBuildPhase' or str(phase.get('dstSubfolderSpec')) != '10':
            continue
        for key in phase.get('files', []):
            item = objects[key]
            reference_value = objects.get(item.get('fileRef'), {})
            name = Path(reference_value.get('path', '')).name
            if not name.endswith('.xcframework'):
                continue
            name = name[:-len('.xcframework')]
            if name in result:
                raise ValueError('Ambiguous framework copy policy: ' + name)
            result[name] = item.get('settings', {}).get('ATTRIBUTES', [])
    expected = {'RRRuntime' + version.replace('.', '') for version in api(root).VERSIONS} | {'RRPlatform', 'RRLive2DCore', 'RRGalleryAudio', 'MetalANGLE'}
    if set(result) != expected:
        raise ValueError('The actual21 framework copy policies are required')
    return result


def compare_native_leaf_maps(original, actual, name, *, remove_headers):
    signature = '_CodeSignature/CodeResources'
    # Xcode's explicit RemoveHeadersOnCopy removes these two top-level
    # directories. Nested resource names and every other leaf remain exact.
    removed = {leaf for leaf in original if len(Path(leaf).parts) > 1 and Path(leaf).parts[0] in {'Headers', 'Modules'}} if remove_headers else set()
    expected = set(original) - removed - {signature}
    if set(actual) - {signature} != expected:
        raise ValueError('A standard Native framework leaf inventory changed: ' + name)
    for leaf in expected - {name}:
        if actual[leaf] != original[leaf]:
            raise ValueError('A standard Native framework resource changed: ' + name + '/' + leaf)
    return removed


def standard_native_leaves(root, artifacts, app, platform, *, formal=False):
    old = api(root)
    attributes = native_copy_attributes(root, formal=formal)
    for package in sorted(artifacts.glob('*.xcframework')):
        name = package.stem
        metadata = plistlib.loads(safe(package / 'Info.plist').read_bytes())
        matches = [r for r in metadata['AvailableLibraries'] if r.get('SupportedPlatform') == 'ios' and
            r.get('SupportedPlatformVariant') == ('simulator' if platform == 'iphonesimulator' else None) and
            'arm64' in r.get('SupportedArchitectures', [])]
        if len(matches) != 1 or matches[0]['LibraryPath'] != name + '.framework':
            raise ValueError('The original exact arm64 Native slice changed')
        source = package / matches[0]['LibraryIdentifier'] / matches[0]['LibraryPath']
        target = app / 'Frameworks' / (name + '.framework')
        original, actual = old.filemap(source), old.filemap(target)
        compare_native_leaf_maps(original, actual, name,
            remove_headers='RemoveHeadersOnCopy' in attributes[name])


def no_eager_legacy_images(root, app):
    # Check actual load commands as well as PBX settings, so variable spelling
    # or a renamed link reference cannot turn the dynamic Core into a link.
    info = plistlib.loads(safe(app / 'Info.plist').read_bytes())
    name = info.get('CFBundleExecutable')
    if type(name) is not str or not name or name in ('.', '..') or '/' in name or '\\' in name:
        raise ValueError('Invalid main App executable')
    for path in [app / name, *sorted(app.glob('*.dylib'))]:
        data = safe(path).read_bytes()
        if len(data) < 32:
            raise ValueError('Truncated App image')
        magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
        if magic != 0xFEEDFACF or cpu != 0x100000C or count > 4096 or 32 + size > len(data):
            raise ValueError('Expected the actual thin arm64 App image')
        offset = 32
        for unused in range(count):
            if offset + 8 > 32 + size:
                raise ValueError('Truncated App load command')
            command, length = struct.unpack_from('<II', data, offset)
            if length < 8 or length % 8 or offset + length > 32 + size:
                raise ValueError('Invalid App load command')
            if command in {0xC, 0x80000018, 0x8000001F, 0x80000023, 0x20}:
                if length < 24:
                    raise ValueError('Truncated linked-library command')
                start = struct.unpack_from('<I', data, offset + 8)[0]
                if not 24 <= start < length or b'\0' not in data[offset + start:offset + length]:
                    raise ValueError('Invalid linked-library name')
                linked = data[offset + start:offset + length].split(b'\0', 1)[0]
                if b'RRLive2DLegacyCore' in linked:
                    raise ValueError('The actual App image eagerly links the device-only legacy Core')
            offset += length
        if offset != 32 + size:
            raise ValueError('Inconsistent App load-command extent')


def derived_built_check(root, identity, *, verifier, artifacts, formal=False):
    old = parent(root)
    certificate = read(root / old.CERTIFICATE)
    parent_identity = read(reference(root, certificate['identity']))
    function, original = old.derived_built_check(root, parent_identity, verifier=verifier, artifacts=artifacts)
    if hashlib.sha256(original.encode()).hexdigest() != BUILT_PARENT_SHA:
        raise ValueError('The exact inherited bitcode-aware21-Native comparator changed')
    before = '    if {p.stem for p in (app / "Frameworks").glob("*.framework")} != frameworks:\n'
    after = '    if platform == "iphoneos":\n        frameworks.add("RRLive2DLegacyCore")\n' + before
    loop = '    for name in frameworks:\n'
    addition = loop + '        if name == "RRLive2DLegacyCore":\n            successor_legacy(root, app, platform)\n            continue\n'
    if original.count(before) != 1 or original.count(loop) != 1:
        raise ValueError('Unknown exact Native-inventory/loop recipe boundary')
    updated = original.replace(before, after, 1).replace(loop, addition, 1)
    updated += '    successor_extra(root, artifacts, app, platform)\n'
    namespace = dict(function.__globals__)
    namespace['successor_legacy'] = lambda root, app, platform: verify_legacy_target(root, app, platform, formal=formal)
    def extra(root, artifacts, app, platform):
        verify_legacy_target(root, app, platform, formal=formal)
        standard_native_leaves(root, artifacts, app, platform, formal=formal)
        no_eager_legacy_images(root, app)
        legal_resources(root, app / 'LegalResources')
        # The original main App embeds17 complete runtime bundles (68 changed
        # leaves), not the source-only catalog. inspect_candidate recomputes
        # all69 source leaves, including that unconsumed catalog. The separate
        # Native probe explicitly copies it and checks its own inventory.
    namespace['successor_extra'] = extra
    exec(compile(updated, str(__file__) + '::exact-software-built-check', 'exec', dont_inherit=True, optimize=0), namespace)
    return namespace['check_built_app'], updated


def inspect_built_app(root, identity, app, platform, configuration):
    inspect_candidate(root, identity)
    def candidate(_root, *, replay=False):
        return {'identity': identity}
    function, unused = derived_built_check(root, identity, verifier=candidate, artifacts=root / identity['candidateArtifactsPath'])
    function(root, read(root / 'RuntimeKit/Patches/overlay-capability-853.json'), app, platform, configuration)
    return dict(passed=True, staticInspectionOnly=True, builtResourceAndNativeComparisonPassed=True,
        runtimeExecutionQualified=False, uiQualified=False, publicationQualified=False, oldOSExecutionQualified=False)


def normalized_guard(path):
    data = safe(path).read_bytes()
    pattern = rb'^CERTIFICATE_SHA256 = [^\n]+$'
    if len(re.findall(pattern, data, re.M)) != 1:
        raise ValueError('Unknown successor qualification declaration')
    return re.sub(pattern, b'CERTIFICATE_SHA256 = None', data, flags=re.M)


QUALIFICATION_FOLDER = BASE / 'Guard/Qualification/FinalDraft'
QUALIFICATION_MODULES = {'native_evidence.py': '858a3757dd44f6d3f6630774d4587324219772995e02b7e15cc1982c3cc52811', 'ui_evidence.py': '0857dac8ff702039623a7fbdd6255a849af66e91256d0c2b33acb202956d4f57', 'device_evidence.py': 'c071efbde1ec5e996444b0b9c1fc74e96415b35970baf88c85b649a80f6e1442'}
COMPONENT_EVIDENCE = {'packaging': {'path': 'RuntimeKit/Validation/LegacyCoreIntegration20261111/Packaging/frozen-verification.json', 'sha256': 'd7310da22a5cef7d3ea2e78c9413258f8bc8a76b0383f2b80bedc0aca1ff6d46'}, 'contract': {'path': 'RuntimeKit/Validation/LegacyCoreIntegration20261111/Integration/ContractFirst/verification.json', 'sha256': '0828381a5b9d4d4997a97eaaa6734c241de41e67d49c0a25a63a2b0accfa0f40'}, 'macCPU': {'path': 'RuntimeKit/Validation/LegacyCoreIntegration20261111/MacCPU/verification.json', 'sha256': 'd26b9e8e6042dc88c4392a7beeabeee82ac7b198ca1b8a7c10a0317639bc194f'}, 'adapter': {'path': 'RuntimeKit/Validation/LegacyCoreIntegration20261111/RuntimeAdapter/ComponentsV2First/verification.json', 'sha256': '7fc22196826809c52c3708905455f57b730f104260a0e5ee6e3ef9011a8cc01f'}}
FINAL_FLAGS = dict(passed=True, legacyCoreSoftwareIntegrated=True,
    currentSimulatorDelegationQualified=True, mainAppRegressionUIQualified=True,
    deviceDependencyPackagingQualified=True, legacyCoreQualified=False,
    oldOSExecutionQualified=False, physicalHardwareQualified=False,
    GPUModelRenderingQualified=False, mainAppHostQualified=False,
    networkIsolationQualified=False)
UI_SOURCE_KEYS = {'App/ReaderStore+Saves.swift', 'App/Views/StorageManagementView.swift',
    'App/Core/LibraryRepository.swift', 'App/Services/Import/GameImportService.swift',
    'App/ReaderStore+Imports.swift', 'App/Views/GameDetailView.swift', 'App/ReaderStore+Live2D.swift'}


def qualification_module(root, name):
    return load(root, QUALIFICATION_FOLDER / name, QUALIFICATION_MODULES[name],
        'legacy_core_final_' + name.replace('.', '_'))


def validate_scope(value):
    keys = set(FINAL_FLAGS) | {'schemaVersion', 'kind', 'hostStatus', 'identity',
        'predecessorBaseline', 'predecessorFinal', 'parentGuard', 'parentCertificate',
        'parentReplay', 'guardTemplateSHA256', 'qualificationModules',
        'derivedBuiltCheckSHA256', 'currentAppSourceSHA256', 'executionEvidence',
        'uiEvidence', 'deviceReviewEvidence', 'deviceReviewCommands', 'componentEvidence'}
    if type(value) is not dict or set(value) != keys:
        raise ValueError('An exact complete concrete software qualification is required')
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['kind'] != 'legacyCoreSoftwareIntegrationQualification':
        raise ValueError('Unknown concrete qualification schema')
    if any(value[k] is not expected for k, expected in FINAL_FLAGS.items()) or value['hostStatus'] != 'COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED':
        raise ValueError('Software evidence cannot promote legacy, oldOS, GPU or host execution')
    expected = {'identity': {'path': str(IDENTITY), 'sha256': IDENTITY_SHA},
        'predecessorBaseline': {'path': str(BASELINE / 'identity.json'), 'sha256': BASELINE_SHA},
        'predecessorFinal': {'path': FINAL, 'sha256': FINAL_SHA},
        'parentGuard': {'path': PARENT_GUARD, 'sha256': PARENT_GUARD_SHA},
        'parentCertificate': {'path': PARENT_CERT, 'sha256': PARENT_CERT_SHA},
        'parentReplay': {'path': str(REPLAY), 'sha256': REPLAY_SHA},
        'qualificationModules': QUALIFICATION_MODULES, 'componentEvidence': COMPONENT_EVIDENCE}
    if any(value[k] != v for k, v in expected.items()):
        raise ValueError('The exact actual predecessor/verifier/component closure changed')
    if type(value['currentAppSourceSHA256']) is not dict or set(value['currentAppSourceSHA256']) != UI_SOURCE_KEYS:
        raise ValueError('The concrete final seven App sources are required')
    for name in ['executionEvidence', 'uiEvidence', 'deviceReviewEvidence', 'deviceReviewCommands']:
        if type(value[name]) is not dict or set(value[name]) != {'path', 'sha256'}:
            raise ValueError('A missing actual UI/device/native evidence ref cannot qualify')
    return True


def validate_current_sources(root, sources):
    if set(sources) != UI_SOURCE_KEYS or any(sha(root / n) != digest for n, digest in sources.items()):
        raise ValueError('A concrete final source changed after its actual UI/device build')


def validate_qualification(root, value, *, artifacts_root=None, source_root=None,
        replay=True, execute_parent=False):
    if sys.flags.optimize:
        raise ValueError('Actual qualification requires Python assertions')
    validate_scope(value)
    if value['guardTemplateSHA256'] != hashlib.sha256(normalized_guard(Path(__file__))).hexdigest():
        raise ValueError('The exact approved qualification source template changed')
    for key in ['identity', 'predecessorBaseline', 'predecessorFinal', 'parentGuard', 'parentCertificate', 'parentReplay']:
        reference(root, value[key])
    validate_current_sources(root, value['currentAppSourceSHA256'])
    identity = read(reference(root, value['identity']))
    inspect_candidate(root, identity, artifacts_root=artifacts_root, source_root=source_root)
    def candidate(_root, *, replay=False):
        return {'identity': identity}
    unused, comparator = derived_built_check(root, identity, verifier=candidate,
        artifacts=artifacts_root or root / identity['candidateArtifactsPath'], formal=source_root == root)
    if hashlib.sha256(comparator.encode()).hexdigest() != value['derivedBuiltCheckSHA256']:
        raise ValueError('The inherited complete Native/resource comparator recipe changed')
    for name, ref in COMPONENT_EVIDENCE.items():
        component = read(reference(root, ref))
        if component.get('passed') is not True:
            raise ValueError('The exact actual component qualification failed')
    native = qualification_module(root, 'native_evidence.py').verify_native(root, value['executionEvidence'])
    ui = qualification_module(root, 'ui_evidence.py').verify_ui(root, value['uiEvidence'], value['currentAppSourceSHA256'])
    device = qualification_module(root, 'device_evidence.py').verify_device_review(root,
        value['deviceReviewEvidence'], value['currentAppSourceSHA256'], value['deviceReviewCommands'])
    retained_replay(root, execute=execute_parent, replay=replay)
    return dict(value, identity=identity, actualNativeEvidence=native, actualFinalUIEvidence=ui,
        actualDeviceReviewEvidence=device, fullActualParentReplayExecuted=execute_parent,
        formalCertificateInstalled=False)


def verify(root, *, replay=True):
    if CERTIFICATE_SHA256 is None or sha(root / CERTIFICATE) != CERTIFICATE_SHA256:
        raise ValueError('The fixed legacy Core software successor remains UNQUALIFIED')
    result = validate_qualification(root, read(root / CERTIFICATE),
        artifacts_root=root / 'RuntimeKit/Artifacts', source_root=root,
        replay=replay, execute_parent=True)
    result['formalCertificateInstalled'] = True
    return result


def check(root, contract):
    if contract != read(root / 'RuntimeKit/Patches/overlay-capability-853.json'):
        raise ValueError('The original overlay contract changed')
    return verify(root)


def check_built_app(root, contract, app, platform, configuration):
    value = verify(root, replay=False)
    function, unused = derived_built_check(root, value['identity'], verifier=verify, artifacts=root / 'RuntimeKit/Artifacts', formal=True)
    return function(root, contract, app, platform, configuration)


def image_identity(root, path):
    return parent(root).image_identity(root, path)


def platform_supplement_predecessor(root):
    verify(root, replay=False)
    old = api(root)
    certificate = read(root / old.CERTIFICATE)
    identity = read(reference(root, certificate['identity']))
    original = old.parent(root, root / identity['predecessorSourcesPath']).parent(root).load_parent(root).previous
    return original.safe_root(root / original.FOLDER / 'Baseline/RuntimeKit/Artifacts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--inspect-candidate', action='store_true')
    parser.add_argument('--contract', type=Path)
    parser.add_argument('--validate-qualification', type=Path)
    parser.add_argument('--replay-predecessor', action='store_true')
    parser.add_argument('--built-app', type=Path)
    parser.add_argument('--platform')
    parser.add_argument('--configuration')
    args = parser.parse_args()
    if sys.flags.optimize:
        raise ValueError('Qualification requires assertions')
    if args.validate_qualification:
        result = validate_qualification(args.root, read(args.validate_qualification), execute_parent=args.replay_predecessor)
    elif args.inspect_candidate:
        if args.identity is None or safe(args.identity) != safe(args.root / IDENTITY) or sha(args.identity) != IDENTITY_SHA:
            raise ValueError('An exact real frozen candidate identity is required')
        identity = read(args.identity)
        result = inspect_built_app(args.root, identity, args.built_app, args.platform, args.configuration) if args.built_app else inspect_candidate(args.root, identity)
    else:
        if args.contract is None:
            raise ValueError('The original overlay contract is required')
        contract = read(args.contract)
        result = check_built_app(args.root, contract, args.built_app, args.platform, args.configuration) if args.built_app else check(args.root, contract)
    print(json.dumps(result, sort_keys=True))
    print(MARKER)
