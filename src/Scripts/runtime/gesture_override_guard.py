"""Concrete gesture software qualification; uninstalled until actual evidence closes."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import inspect
import json
import re
import stat
import sys

sys.dont_write_bytecode = True
BASE = Path('RuntimeKit/Candidates/GestureOverrideAll20261111')
CERTIFICATE = Path('RuntimeKit/Patches/gesture-override-all-20261111.json')
CERTIFICATE_SHA256 = '463a963ca27c85e8696236e6b5c6605547cc74b2f69244350780855feaca7743'
INSPECTOR = BASE / 'Guard/Third/gesture_override_guard.py'
INSPECTOR_SHA = '31057b914595707e8aced1ee19d7cba6c7506c48d5002f5888984501f948c777'
NATIVE_VERIFIER = BASE / 'Guard/Qualification/native_evidence.py'
NATIVE_VERIFIER_SHA = '8aafbe16d759231a7c33f96d656d033a4b3fdaff42ba7813b0c51085006a5f93'
UI_VERIFIER = BASE / 'Guard/Qualification/ui_evidence.py'
UI_VERIFIER_SHA = '01b44fb8e1ec661b5efd8e6205a02c7bf82f3a19a8de7a15143a962444530ad3'
QA_BUILD = Path('RuntimeKit/Validation/SparkGestureOverrideAll20261111/QA/CandidateDebugFirst/verification.json')
QA_BUILD_SHA = 'e47f4254490e930af8173575bf4f601cd7c623dc74d9d8227458e824e851407e'
TYPECHECK = Path('RuntimeKit/Validation/SparkGestureOverrideAll20261111/SwiftTypecheck/verification-first.json')
TYPECHECK_SHA = '79d27ca83eecd2f8c503d54d68cbb07e5823db4c532a780fa59837101fa6b921'
PARENT_REPLAY = Path('RuntimeKit/Validation/SparkGestureOverrideAll20261111/ParentReplayAPI/SecondFullFirst/verification.json')
PARENT_REPLAY_SHA = '059f8bfce9f82866a3af45b756563fdc63bb954625df5addff58dda83aa12490'
MARKER = 'COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED'
FLAGS = dict(passed=True, gestureOverrideAllSoftwareIntegrated=True,
    currentSimulatorEnhancedGestureDispatchQualified=True, representativeCompatibilityModesQualified=True,
    mainAppGestureSettingsUIQualified=True, nativePackagesUnchanged=True, hostSourcesUnchanged=True,
    oldOSExecutionQualified=False, GPUQualified=False, physicalInputQualified=False, globalHostQualified=False)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(root, path, digest, name):
    target = (root / path).absolute()
    if digest is None or target.resolve(strict=True) != target or not target.is_file() or target.is_symlink() or sha(target) != digest:
        raise ValueError('A fixed qualification source is missing or changed: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, target)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def inspector(root):
    return load(root, INSPECTOR, INSPECTOR_SHA, 'gesture_complete_static_inspector')


def normalized_guard(path):
    data = Path(path).read_bytes()
    pattern = rb'^CERTIFICATE_SHA256 = [^\n]+$'
    if len(re.findall(pattern, data, re.M)) != 1:
        raise ValueError('Unknown exact qualification declaration')
    return re.sub(pattern, b'CERTIFICATE_SHA256 = None', data, flags=re.M)


def validate_plan(root, core, value, *, formal):
    plan = core.read(core.reference(root, value['publicationPlan']))
    identity = core.read(core.pinned(root, core.IDENTITY, core.IDENTITY_SHA))
    app = core.read(core.pinned(root, core.APP_MANIFEST, core.APP_MANIFEST_SHA))
    expected = {'RuntimeKit/Artifacts/' + name: root / identity['candidateArtifactsPath'] / name for name in identity['allowedDelta']}
    expected.update({name: root / identity['candidateSourcesPath'] / name for name in identity['candidateSources']})
    expected.update({name: root / BASE / 'AppSources' / name for name in app['sources']})
    prep = core.read(root / BASE / 'PublicationPlan/preparation.json')
    expected.update({name: root / row['candidatePath'] for name, row in prep['files'].items()})
    if set(plan['operations']) != set(expected) or len(expected) != 96:
        raise ValueError('The complete exact96 publication destination set is required')
    for name, source in expected.items():
        row = plan['operations'][name]
        if row['candidatePath'] != str(source.relative_to(root)) or core.sha(source) != row['afterSHA256']:
            raise ValueError('An exact publication source changed: ' + name)
        if formal and name == 'RenReader.xcodeproj/project.pbxproj':
            validate_formal_project(root, core, root / name)
        elif formal and core.sha(root / name) != row['afterSHA256']:
            raise ValueError('A formally selected publication image changed: ' + name)
    return plan


def validate_formal_project(root, core, path):
    old = core.module(core.pinned(root, core.OLD, core.OLD_SHA), 'gesture_current_structural_project')
    original = inspect.getsource(old.validate_formal_project)
    before = "    guard = '$SRCROOT/Scripts/runtime/legacy_core_integration_guard.py'\n"
    after = "    guard = '$SRCROOT/Scripts/runtime/gesture_override_guard.py'\n"
    if original.count(before) != 1:
        raise ValueError('Unknown exact inherited project guard-command boundary')
    derived = original.replace(before, after, 1)
    namespace = dict(old.validate_formal_project.__globals__)
    exec(compile(derived, str(__file__) + '::exact-structural-project-successor', 'exec', dont_inherit=True, optimize=0), namespace)
    result = namespace['validate_formal_project'](root, path)
    validate_qualified_target_sources(root, core, old.project_objects(path))
    return result


def validate_qualified_target_sources(root, core, project):
    objects = project['objects']
    app = next(item for item in objects.values() if item.get('isa') == 'PBXNativeTarget' and item.get('name') == 'RenReader')
    manifest = core.read(core.pinned(root, core.APP_MANIFEST, core.APP_MANIFEST_SHA))
    expected = {Path(name).name: root / name for name in manifest['sources']}
    expected['SparkParityEngineUpdates.swift'] = root / 'App/Services/Import/SparkParityEngineUpdates.swift'
    if len(expected) != 6:
        raise ValueError('The exact six qualified Swift source owners are required')
    parents = {}
    for key, item in objects.items():
        if item.get('isa') in {'PBXGroup', 'PBXVariantGroup'}:
            for child in item.get('children', []):
                if child in parents and parents[child] != key:
                    raise ValueError('A qualified source has ambiguous parent groups')
                parents[child] = key
    def resolve(key, seen=()):
        if key in seen:
            raise ValueError('Cyclic qualified source groups')
        item = objects[key]
        tree, text = item.get('sourceTree', '<group>'), item.get('path', '')
        for variable in ('$(SRCROOT)', '${SRCROOT}', '$SRCROOT', '$(SOURCE_ROOT)'):
            if text.startswith(variable):
                text = str(root) + text[len(variable):]
                break
        relative = Path(text)
        if relative.is_absolute():
            return relative
        if tree == 'SOURCE_ROOT':
            return root / relative
        if tree != '<group>':
            raise ValueError('Unsupported qualified source tree')
        base = resolve(parents[key], seen + (key,)) if key in parents else root
        return base / relative
    found = {name: [] for name in expected}
    for phase in (objects[key] for key in app['buildPhases']):
        if phase.get('isa') != 'PBXSourcesBuildPhase':
            continue
        for key in phase.get('files', []):
            reference = objects[key].get('fileRef')
            if reference is None:
                continue
            name = Path(objects[reference].get('path', '')).name
            if name in found:
                found[name].append(resolve(reference))
    if any(found[name] != [path] for name, path in expected.items()):
        raise ValueError('The main target must compile the six actual qualified Swift sources exactly once')


def validate_current_inherited_sources(root, core, plan):
    # The parent's public retained-source API validates historical evidence.
    # Also retain its existing current-source protections at the new formal root.
    identity = core.read(core.pinned(root, core.OLD_BASE / 'identity.json', core.OLD_IDENTITY_SHA))
    operations = plan['operations']
    names = {name.casefold(): name for name in operations}
    if len(names) != len(operations):
        raise ValueError('Ambiguous publication destination casing')
    for name, previous in identity['candidateSources'].items():
        selected = names.get(name.casefold())
        if name.casefold() == 'renreader.xcodeproj/project.pbxproj':
            validate_formal_project(root, core, root / (selected or name))
            continue
        expected = ({'sha256': operations[selected]['afterSHA256'], 'size': operations[selected]['afterSize'],
                     'mode': operations[selected]['afterMode']} if selected else previous)
        path = core.safe(root / (selected or name))
        if (core.sha(path) != expected['sha256'] or path.stat().st_size != expected['size']
                or stat.S_IMODE(path.stat().st_mode) != expected['mode']):
            raise ValueError('An inherited current source or explicit successor changed: ' + name)
    old = core.module(core.pinned(root, core.OLD, core.OLD_SHA), 'gesture_current_native_source_protection')
    api = old.api(root)
    for folder in ['RuntimeKit/Native', 'RuntimeKit/Bridge']:
        previous = root / core.OLD_BASE / 'CandidateSources' / folder
        if api.filemap(root / folder) != api.filemap(previous) or api.directories(root / folder) != api.directories(previous):
            raise ValueError('The complete inherited current Native/Bridge source inventory changed')


def validate_qualification(root, value, *, formal=False, replay=True):
    if sys.flags.optimize:
        raise ValueError('Actual qualification requires assertions')
    root = Path(root).absolute()
    core = inspector(root)
    expected_keys = set(FLAGS) | {'schemaVersion', 'kind', 'guardTemplateSHA256', 'identity', 'appSourceManifest',
        'currentAppSourceSHA256', 'nativeEvidence', 'uiEvidence', 'qaBuildEvidence', 'typecheckEvidence',
        'parentReplayEvidence', 'publicationPlan', 'verifiers'}
    if (type(value) is not dict or set(value) != expected_keys or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['kind'] != 'gestureOverrideAllSoftwareSuccessor'
            or any(value[name] is not expected for name, expected in FLAGS.items())):
        raise ValueError('The exact narrow software qualification scope is required')
    if value['guardTemplateSHA256'] != hashlib.sha256(normalized_guard(__file__)).hexdigest():
        raise ValueError('The reviewed qualification template changed')
    if value['identity'] != {'path': str(core.IDENTITY), 'sha256': core.IDENTITY_SHA} or value['appSourceManifest'] != {'path': str(core.APP_MANIFEST), 'sha256': core.APP_MANIFEST_SHA}:
        raise ValueError('The exact actual resource/App candidates are required')
    if value['verifiers'] != {'native': {'path': str(NATIVE_VERIFIER), 'sha256': NATIVE_VERIFIER_SHA}, 'ui': {'path': str(UI_VERIFIER), 'sha256': UI_VERIFIER_SHA}}:
        raise ValueError('The exact actual qualification verifiers are required')
    for key, path, digest in [('qaBuildEvidence', QA_BUILD, QA_BUILD_SHA), ('typecheckEvidence', TYPECHECK, TYPECHECK_SHA),
                              ('parentReplayEvidence', PARENT_REPLAY, PARENT_REPLAY_SHA)]:
        if value[key] != {'path': str(path), 'sha256': digest}:
            raise ValueError('An exact actual build/typecheck/parent replay reference is required')
    static = core.inspect(root, formal=formal, replay=replay)
    app = core.read(core.reference(root, value['appSourceManifest']))
    sources = {name: row['sha256'] for name, row in app['sources'].items()}
    if value['currentAppSourceSHA256'] != sources:
        raise ValueError('The complete fixed App5 source set is required')
    for name, digest in sources.items():
        path = root / name if formal else root / BASE / 'AppSources' / name
        if core.sha(path) != digest:
            raise ValueError('A qualified App source changed: ' + name)
    qa = core.read(core.reference(root, value['qaBuildEvidence']))
    if (qa.get('passed') is not True or qa['sourceCount'] != 184 or qa['inputCount'] != 310
            or qa['inputsChanged'] or qa['productionChanged'] or qa['registryRows'] != 1140
            or qa['identitySHA256'] != core.IDENTITY_SHA or qa['appSourceManifestSHA256'] != core.APP_MANIFEST_SHA
            or qa['strictBefore'] != {'derived': True, 'frozen': True} or qa['strictAfter'] != {'derived': True, 'frozen': True}
            or qa['rawNativeUnchanged'] is not True):
        raise ValueError('The actual complete184-source isolated App build is required')
    types = core.read(core.reference(root, value['typecheckEvidence']))
    if types.get('passed') is not True or len(types['runs']) != 3:
        raise ValueError('The actual three declared system-target typechecks are required')
    qa_inputs = core.read(root / QA_BUILD.parent / 'inputs.json')
    api = core.module(core.pinned(root, core.OLD, core.OLD_SHA), 'gesture_retained_typecheck_inventory').api(root)
    current_registry = root / core.read(core.reference(root, value['identity']))['candidateSourcesPath'] / api.REGISTRY
    targets = set()
    for row in types['runs']:
        proof_path = core.reference(root, {'path': row['path'], 'sha256': row['sha256']})
        proof = core.read(proof_path)
        if proof['passed'] is not True or proof['swiftVersion'] != 6 or proof['sourceCount'] != 184 or proof['inputCount'] != 190 or proof['changed'] or proof['contextChanged']:
            raise ValueError('A complete target typecheck failed or changed')
        typed_inputs = core.read(proof_path.parent / 'inputs-before.json')
        if len(typed_inputs) != 190 or core.read(proof_path.parent / 'inputs-after.json') != typed_inputs:
            raise ValueError('The complete typed input inventory changed')
        mapping = core.read(proof_path.parent / 'source-map.json')
        actual_inputs = {record['actualPath']: record['sha256'] for record in mapping['sources']}
        logical_inputs = {record['logicalPath']: record['sha256'] for record in mapping['sources']}
        if len(actual_inputs) != 184 or len(logical_inputs) != 184 or len(mapping['headers']) != 6:
            raise ValueError('A complete unambiguous typed source map is required')
        actual_inputs.update(mapping['headers'])
        logical_inputs.update(mapping['headers'])
        if actual_inputs != typed_inputs:
            raise ValueError('Typed actual source paths disagree with the frozen source map')
        for record in mapping['sources']:
            if core.sha(root / record['frozenPath']) != record['sha256']:
                raise ValueError('A frozen actual typed source changed')
        for name, digest in logical_inputs.items():
            if name != api.REGISTRY and qa_inputs.get(name) != digest:
                raise ValueError('A typed source differs from the actual final QA build: ' + name)
        # V2 changed Python cleanup and its provenance hashes, not Swift code.
        # The first1140 table and final1140 table differ only in SHA string
        # literals. The final table was also compiled in the actual QA App.
        typed_registry = proof_path.parent / 'SourceInputs' / api.REGISTRY
        if core.sha(typed_registry) != logical_inputs[api.REGISTRY]:
            raise ValueError('The retained typed registry changed')
        before_rows, after_rows = api.registry_rows(typed_registry.read_bytes()), api.registry_rows(current_registry.read_bytes())
        if (len(before_rows) != 1140 or len(after_rows) != 1140
                or [record[:2] for record in before_rows] != [record[:2] for record in after_rows]
                or re.sub(rb'"[0-9a-f]{64}"', b'"SHA256"', typed_registry.read_bytes())
                   != re.sub(rb'"[0-9a-f]{64}"', b'"SHA256"', current_registry.read_bytes())):
            raise ValueError('A final registry change exceeds the exact SHA-literal revision')
        targets.add(proof['target'])
    if targets != {'arm64-apple-ios15.5', 'arm64-apple-ios16.0', 'arm64-apple-ios17.0'}:
        raise ValueError('All three distinct declared system targets are required')
    parent = core.read(core.reference(root, value['parentReplayEvidence']))
    if parent.get('passed') is not True:
        raise ValueError('The actual explicit Second predecessor replay is required')
    native = load(root, NATIVE_VERIFIER, NATIVE_VERIFIER_SHA, 'gesture_actual_native_qualification').verify_native(root, value['nativeEvidence'])
    ui = load(root, UI_VERIFIER, UI_VERIFIER_SHA, 'gesture_actual_settings_ui_qualification').verify_ui(root, value['uiEvidence'], sources)
    plan = validate_plan(root, core, value, formal=formal)
    if formal:
        validate_current_inherited_sources(root, core, plan)
    return dict(value, actualNativeEvidence=native, actualUIEvidence=ui, identity=core.read(core.reference(root, value['identity'])),
                completeStaticInspection=static, formalCertificateInstalled=False)


def verify(root, *, replay=True):
    root = Path(root).absolute()
    if CERTIFICATE_SHA256 is None or sha(root / CERTIFICATE) != CERTIFICATE_SHA256:
        raise ValueError('Override-all gestures remain UNQUALIFIED: no fixed concrete certificate is installed')
    result = validate_qualification(root, inspector(root).read(root / CERTIFICATE), formal=True, replay=replay)
    result['formalCertificateInstalled'] = True
    return result


def check(root, contract):
    core = inspector(root)
    if contract != core.read(root / 'RuntimeKit/Patches/overlay-capability-853.json'):
        raise ValueError('The original overlay contract changed')
    return verify(root)


def check_built_app(root, contract, app, platform, configuration):
    core = inspector(root)
    if contract != core.read(root / 'RuntimeKit/Patches/overlay-capability-853.json'):
        raise ValueError('The original overlay contract changed')
    if CERTIFICATE_SHA256 is None or sha(root / CERTIFICATE) != CERTIFICATE_SHA256:
        raise ValueError('An actual concrete software qualification is required')
    value = core.read(root / CERTIFICATE)
    identity = core.read(core.reference(root, value['identity']))
    old = core.module(core.pinned(root, core.OLD, core.OLD_SHA), 'gesture_retained_complete_built_comparator')
    comparator, unused = old.derived_built_check(root, identity, verifier=verify, artifacts=root / 'RuntimeKit/Artifacts', formal=True)
    return comparator(root, contract, app, platform, configuration)


def image_identity(root, path):
    core = inspector(root)
    old = core.module(core.pinned(root, core.OLD, core.OLD_SHA), 'gesture_retained_image_identity')
    return old.image_identity(root, path)


def platform_supplement_predecessor(root):
    verify(root, replay=False)
    core = inspector(root)
    legacy = core.module(core.pinned(root, core.OLD, core.OLD_SHA), 'gesture_retained_platform_provenance')
    old = legacy.api(root)
    certificate = legacy.read(root / old.CERTIFICATE)
    identity = legacy.read(legacy.reference(root, certificate['identity']))
    original = old.parent(root, root / identity['predecessorSourcesPath']).parent(root).load_parent(root).previous
    return original.safe_root(root / original.FOLDER / 'Baseline/RuntimeKit/Artifacts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--contract', type=Path)
    parser.add_argument('--built-app', type=Path)
    parser.add_argument('--platform')
    parser.add_argument('--configuration')
    parser.add_argument('--validate-qualification', type=Path)
    args = parser.parse_args()
    if args.validate_qualification:
        result = validate_qualification(args.root, inspector(args.root).read(args.validate_qualification))
    else:
        if args.contract is None:
            raise ValueError('The original overlay contract is required')
        contract = inspector(args.root).read(args.contract)
        result = check_built_app(args.root, contract, args.built_app, args.platform, args.configuration) if args.built_app else check(args.root, contract)
    print(json.dumps(result, sort_keys=True))
    print(MARKER)
