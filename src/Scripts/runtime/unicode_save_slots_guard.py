#!/usr/bin/env python3
"""Additive live-slot resource candidate; inspection never grants qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
CERTIFICATE_SHA256 = 'ab45575dd0e06ad5079eda6d0fbba548685733cec96638adcd280e7e1f4f34e6'
PARENT_GUARD = 'Scripts/runtime/engine_preferences_guard.py'
PARENT_GUARD_SHA256 = '14fe4065b7f14330432677721084081aa7245dee119afc9b059d024648abf203'
PARENT_CERTIFICATE = 'RuntimeKit/Patches/engine-preferences-20261111.json'
PARENT_CERTIFICATE_SHA256 = '11283b59a93d945720d059182489e946d5460abefba512dbb6f678f9329c1983'
FINAL_RECEIPT = 'RuntimeKit/Validation/SparkCompleteness20261110/final-verification.json'
FINAL_RECEIPT_SHA256 = '98c9b005f6cb98176ac6f271f82665d4312fd2db517a688ed05353afaaf1e39d'
HELPER_SHA256 = '8d7f7615b01838754a9e3d4c232ec563ed662586ad497eafb7ae9bcd622aaf7f'
ENGINE_HELPER_SHA256 = 'e86c1f0e53fd39a8fdf900d633a81521f6542dda71d0b57b58dee37962feb9aa'
SCOPE = 'extended live load names only; bounded double content verification; final stock open is not atomic'
MARKER = 'PASS: COMPONENT_UNQUALIFIED_HOST_UNQUALIFIED; global host/oldOS/physical scope is unchanged'


def sha(path):
    path = Path(path).absolute()
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Only regular, unlinked qualification inputs are accepted: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parent(root):
    if sha(root / PARENT_GUARD) != PARENT_GUARD_SHA256 or sha(root / PARENT_CERTIFICATE) != PARENT_CERTIFICATE_SHA256:
        raise ValueError('The published immutable engine-preferences parent changed')
    spec = importlib.util.spec_from_file_location('immutable_engine_preferences_parent', root / PARENT_GUARD)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    if module.CERTIFICATE_SHA256 != PARENT_CERTIFICATE_SHA256:
        raise ValueError('The parent qualification declaration changed')
    return module


def expected_main(data):
    text = data.decode('utf-8')
    marker = '_preferences = _preferences_module.Session(session, rr_host)\n'
    cleanup = 'finally:\n    _preferences.finish()\n'
    if text.count(marker) != 1 or 'rr_save_slots' in text or text.count(cleanup) != 1 or not text.endswith(cleanup):
        raise ValueError('Unknown predecessor trusted entry')
    text = text.replace(marker, marker + '_save_slots_module = _stock_module("rr_save_slots", "rr_save_slots.py")\n_save_slots = _save_slots_module.Session(session, rr_host)\n')
    return (text[:-len(cleanup)] + 'finally:\n    try:\n        _save_slots.finish()\n    finally:\n        _preferences.finish()\n').encode('utf-8')


def expected_tool(name, original):
    key=name.lower()
    if key=='scripts/check_app_artifacts.py':
        before=b'from runtime import engine_preferences_guard as capability_guard\n'
        if original.count(before)!=1 or b'unicode_save_slots_guard' in original:
            raise ValueError('Unknown predecessor artifact-check dispatcher')
        return original.replace(before,b'from runtime import unicode_save_slots_guard as capability_guard\n',1)
    if key=='scripts/prepare_legal_manifest.py':
        marker=b"            if (root / 'RuntimeKit/Patches/engine-preferences-20261111.json').is_file():\n"
        if original.count(marker)!=1 or b'unicode_save_slots_guard' in original:
            raise ValueError('Unknown predecessor legal dispatcher')
        branch=("            if (root / 'RuntimeKit/Patches/unicode-save-slots-20261111.json').is_file():\n"
                "                from runtime.unicode_save_slots_guard import platform_supplement_predecessor\n"
                "                from runtime.runtime_features_guard import NOTICE_NAMES as FEATURE_NOTICES\n"
                "                from runtime.legacy_compatibility_guard import NOTICE_NAMES as LEGACY_NOTICES\n"
                "                NOTICE_NAMES = (*FKEY_NOTICES, *FEATURE_NOTICES, *LEGACY_NOTICES)\n"
                "                predecessor = platform_supplement_predecessor(root)\n"
                "            elif (root / 'RuntimeKit/Patches/engine-preferences-20261111.json').is_file():\n").encode()
        return original.replace(marker,branch,1)
    raise ValueError('Unknown derived publication tool')


def expected_registry(parent_module, original, inline, runtimes):
    rows, shipped = parent_module.registry_rows(original), parent_module.registry_rows(inline)
    if len(rows) != 585 or len(shipped) != 36 or set(runtimes) != set(parent_module.VERSIONS):
        raise ValueError('The complete585 historical registry and17 runtime target are required')
    keys, additions, counts = {row[:3] for row in rows + shipped}, [], {}
    for version in parent_module.VERSIONS:
        runtime = ('renpy-' + version).encode()
        target = runtimes[version]['provenanceSHA256'].encode()
        origins = {row[i] for row in rows + shipped if row[0] == runtime for i in (1, 2)}
        origins.add(runtimes[version]['previousProvenanceSHA256'].encode())
        counts[version] = 0
        for origin in sorted(origins):
            key = (runtime, origin, target)
            if origin != target and key not in keys:
                additions.append('        .init(runtimeID: "%s", previousProvenanceSHA256: "%s", currentProvenanceSHA256: "%s", currentBaseFingerprint: "%s")' %
                    (runtime.decode(), origin.decode(), target.decode(), runtimes[version]['baseFingerprint']))
                keys.add(key); counts[version] += 1
    boundary = b'\n    ]\n}\n'
    if original.count(boundary) != 1 or len(additions) != 168:
        raise ValueError('The deterministic minimum168-edge successor changed')
    result = original.replace(boundary, b',\n' + ',\n'.join(additions).encode() + boundary, 1)
    if len(parent_module.registry_rows(result)) != 753:
        raise ValueError('The complete753-row successor is required')
    return result, counts


def inspect_candidate(root, identity, *, artifacts_root=None, source_root=None):
    old = parent(root)
    if identity.get('schemaVersion') != 1 or identity.get('kind') != 'unicodeSaveSlotsResourceSuccessor':
        raise ValueError('Unknown Unicode-slot identity')
    if sha(root / FINAL_RECEIPT) != FINAL_RECEIPT_SHA256:
        raise ValueError('The final predecessor closure changed')
    inputs = {name: old.ref(root, row) for name, row in identity['buildInputs'].items()}
    if set(inputs) != {'manifest','helper','builder'} or sha(inputs['helper']) != HELPER_SHA256:
        raise ValueError('The frozen helper/builder input set changed')
    manifest = old.read(inputs['manifest'])
    if (manifest.get('schemaVersion') != 1 or manifest.get('kind') != 'unicodeSaveSlotsResourceCandidate'
            or manifest.get('componentOnly') is not True or manifest.get('runtimeExecutionQualified') is not False
            or manifest.get('uiQualified') is not False or manifest.get('oldOSExecutionQualified') is not False
            or manifest.get('officialArtifactsUnchanged') is not True
            or manifest.get('parentGuard') != {'path':PARENT_GUARD,'sha256':PARENT_GUARD_SHA256}
            or manifest.get('parentCertificate') != {'path':PARENT_CERTIFICATE,'sha256':PARENT_CERTIFICATE_SHA256}
            or manifest.get('helperSHA256') != HELPER_SHA256 or manifest.get('candidateBuilderSHA256') != sha(inputs['builder'])
            or manifest.get('predecessorFinalReceipt') != {'path':FINAL_RECEIPT,'sha256':FINAL_RECEIPT_SHA256}):
        raise ValueError('The actual frozen candidate generation changed')
    predecessor = old.safe(root / identity['predecessorArtifactsPath'], directory=True)
    sources = old.safe(root / identity['predecessorSourcesPath'], directory=True)
    artifacts = old.safe(artifacts_root or root / identity['candidateArtifactsPath'], directory=True)
    current_sources = old.safe(source_root or root / identity['candidateSourcesPath'], directory=True)
    parent_cert = old.read(root / old.CERTIFICATE)
    parent_identity = old.read(old.ref(root, parent_cert['identity']))
    before, after = old.filemap(predecessor), old.filemap(artifacts)
    if (before != parent_identity['candidateArtifacts'] or before != manifest['predecessorArtifacts']
            or before != identity['predecessorArtifacts'] or after != identity['candidateArtifacts'] or after != manifest['candidateArtifacts']
            or old.filemap(sources) != identity['predecessorSources'] or old.filemap(sources) != manifest['predecessorSources']):
        raise ValueError('The real predecessor/candidate/source snapshot changed')
    if (old.directories(predecessor) != identity['artifactDirectories'] or old.directories(artifacts) != identity['artifactDirectories']
            or old.directories(sources) != identity['predecessorSourceDirectories']):
        raise ValueError('The complete snapshot directory inventory/modes changed')
    allowed, added = {'runtime-catalog.json'}, set()
    for version in old.VERSIONS:
        prefix = 'RenPy' + version.replace('.', '') + '.bundle/'
        allowed.update(prefix + name for name in ['base/main.py','runtime-profile.json','provenance.json'])
        added.add(prefix + 'base/rr_save_slots.py')
    changed = {name for name in after if before.get(name) != after[name]}
    if set(after) != set(before) | added or changed != allowed | added or len(changed) != 69:
        raise ValueError('Unexpected delta outside the deterministic69 resource leaves')
    if (manifest.get('allowedDelta') != {name:{'previous':before.get(name),'candidate':after[name]} for name in changed}
            or set(manifest.get('runtimes',[])) != set(old.VERSIONS) or len(manifest['runtimes']) != 17):
        raise ValueError('The exact69 delta receipt or17 runtime manifest changed')
    if set(identity['runtimes']) != set(old.VERSIONS):
        raise ValueError('The exact17 runtime set is required')
    for version in old.VERSIONS:
        original, actual = old.bundle(predecessor, version), old.bundle(artifacts, version)
        if ((actual/'base/main.py').read_bytes() != expected_main((original/'base/main.py').read_bytes())
                or sha(actual/'base/rr_save_slots.py') != HELPER_SHA256
                or sha(actual/'base/rr_engine_preferences.py') != ENGINE_HELPER_SHA256):
            raise ValueError('Trusted loader/helper exceeds the exact recipe: '+version)
        profile = old.read(original/'runtime-profile.json')
        profile.update(unicodeSaveSlotsSchemaVersion=1,unicodeSaveSlotsQualification='candidate-component-only')
        if (actual/'runtime-profile.json').read_bytes() != old.encoded(profile):
            raise ValueError('Profile exceeds the exact two fields: '+version)
        provenance = old.read(original/'provenance.json')
        provenance['unicodeSaveSlotsCandidate'] = dict(schemaVersion=1,
            previousProvenanceSHA256=sha(original/'provenance.json'),mainSHA256=sha(actual/'base/main.py'),helperSHA256=HELPER_SHA256,
            hostUnchangedSHA256=sha(original/'base/rr_host.py'),enginePreferencesUnchangedSHA256=ENGINE_HELPER_SHA256,
            status='component-unqualified',scope=SCOPE)
        if (actual/'provenance.json').read_bytes() != old.encoded(provenance):
            raise ValueError('Provenance exceeds the exact successor record: '+version)
        record=dict(previousProvenanceSHA256=sha(original/'provenance.json'),provenanceSHA256=sha(actual/'provenance.json'),
            baseFingerprint=old.fingerprint(actual/'base'),mainSHA256=sha(actual/'base/main.py'),hostSHA256=sha(actual/'base/rr_host.py'),
            profileSHA256=sha(actual/'runtime-profile.json'))
        if identity['runtimes'][version] != record:
            raise ValueError('Runtime identity differs from actual candidate bytes: '+version)
    catalog = old.read(predecessor/'runtime-catalog.json')
    for row in catalog['profiles']:
        row.update(unicodeSaveSlotsSchemaVersion=1,unicodeSaveSlotsQualification='candidate-component-only')
    if (artifacts/'runtime-catalog.json').read_bytes() != old.encoded(catalog):
        raise ValueError('Catalog exceeds the exact two fields')
    registry, counts = expected_registry(old, (sources/old.REGISTRY).read_bytes(), (sources/old.INLINE_REGISTRY).read_bytes(),identity['runtimes'])
    if ((current_sources/old.REGISTRY).read_bytes() != registry or sha(current_sources/old.REGISTRY) != identity['registrySHA256']
            or sha(sources/old.REGISTRY) != parent_identity['registrySHA256']):
        raise ValueError('The exact753 registry successor or585-row predecessor changed')
    for name, record in identity['predecessorSources'].items():
        path=current_sources/name
        if name.lower() in {'scripts/prepare_legal_manifest.py','scripts/check_app_artifacts.py'}:
            original=(sources/name).read_bytes()
            expected=expected_tool(name,original) if current_sources==old.safe(root,directory=True) else original
            if path.read_bytes()!=expected or path.stat().st_mode & 0o7777 != record['mode']:
                raise ValueError('The exact derived publication tool changed: '+name)
            continue
        if name == old.REGISTRY:
            continue
        if name.startswith('RuntimeKit/Notices/renpy-') and name.endswith('-provenance.json'):
            version=Path(name).name[len('renpy-'):-len('-provenance.json')]
            if version in old.VERSIONS:
                if path.read_bytes() != (old.bundle(artifacts,version)/'provenance.json').read_bytes():
                    raise ValueError('Current provenance notice differs: '+version)
                continue
        if sha(path) != record['sha256'] or path.stat().st_mode & 0o7777 != record['mode']:
            raise ValueError('Preserved source/gate/certificate changed: '+name)
    for folder in ['RuntimeKit/Native','RuntimeKit/Bridge']:
        if (old.filemap(current_sources/folder) != old.filemap(sources/folder)
                or old.directories(current_sources/folder) != old.directories(sources/folder)):
            raise ValueError('Native/Bridge complete inventory changed')
    return dict(passed=True,staticInspectionOnly=True,runtimeExecutionQualified=False,uiQualified=False,publicationQualified=False,
        runtimes=17,changedLeaves=69,nativePackagesUnchanged=True,registryRows=753,registryAddedDirectEdges=168,directEdgesByRuntime=counts)


def replay_predecessor(root, identity, *, replay=True):
    # Actual parent verifier, actual immutable old artifacts/sources. No masking.
    return parent(root).verify(root,artifacts_root=root/identity['predecessorArtifactsPath'],
        source_root=root/identity['predecessorSourcesPath'],replay=replay)


def derived_built_check(root, identity, *, verifier=None, artifacts=None):
    old=parent(root); value=old.read(root/old.CERTIFICATE); old_identity=old.read(old.ref(root,value['identity']))
    # Reuse the pinned parent's explicit verifier/artifact arguments. This is a
    # built-image comparator, never a substitute for the actual replay above.
    return old.derived_built_check(root,old_identity,verifier=verifier or verify,artifacts=artifacts)


def inspect_built_app(root, identity, app, platform, configuration):
    inspect_candidate(root,identity); replay_predecessor(root,identity,replay=False)
    def unqualified(_root, *, replay=False):
        return {'identity':identity}
    function,unused=derived_built_check(root,identity,verifier=unqualified,artifacts=root/identity['candidateArtifactsPath'])
    function(root,parent(root).read(root/'RuntimeKit/Patches/overlay-capability-853.json'),app,platform,configuration)
    return dict(passed=True,staticInspectionOnly=True,builtResourceAndNativeComparisonPassed=True,
        runtimeExecutionQualified=False,uiQualified=False,publicationQualified=False)


# Qualification is implemented separately from the immutable candidate-build
# inspector. No certificate is installed, and the declaration above stays None.
import plistlib
import re
import subprocess

CERTIFICATE = Path('RuntimeKit/Patches/unicode-save-slots-20261111.json')
PROBE_BASE = 'RuntimeKit/Candidates/UnicodeSaveSlots20261111/ActualSessionsProbe/'
PROBE_SOURCES = {PROBE_BASE+name for name in ['run_probe.py','UnicodeSlotsProbe.m','fixture.rpy','rr_unicode_fixture.py']} | {
    'RuntimeKit/Candidates/EnginePreferences20261111/ActualSessionsProbe/run_probe.py',
    'RuntimeKit/Bridge/RRRuntimeBridge.m','RuntimeKit/Bridge/RRRuntimeBridge.h',
    'RuntimeKit/Bridge/RRLive2DSelection.h','RuntimeKit/Native/RRAuxiliaryInput.h'}
UI_SOURCES = {'App/Core/ReaderLaunchMode.swift','App/Core/ReaderSaveLoadContext.swift',
              'App/ReaderStore+ReaderSaves.swift','App/Views/SaveManagerView.swift'}
UI_BUNDLE = 'dev.renreader.unicodeslots20261111'
UI_GROUP = 'group.dev.renreader.unicodeslots20261111'


def ndjson(path):
    # U+0085/U+2028 are legal JSON string contents, not NDJSON separators.
    data=Path(path).read_bytes()
    if data and not data.endswith(b'\n'):
        raise ValueError('Incomplete native event line')
    def unique(pairs):
        result={}
        for name,value in pairs:
            if name in result: raise ValueError('Duplicate native JSON key')
            result[name]=value
        return result
    result=[]
    for line in data.split(b'\n'):
        if not line: continue
        value=json.loads(line.decode('utf-8'),object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite native JSON number')))
        if type(value) is not dict: raise ValueError('A native event must be an object')
        result.append(value)
    return result


def strict(app):
    subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)


def admission_rejected(value):
    # Objective-C @(!BOOL) boxes an int 1 in this frozen probe. This exception
    # is only for its host-side Bridge return values, never ready capabilities.
    return value is True or (type(value) is int and value==1)


def verify_program(root, execution, identity, identity_sha):
    old=parent(root)
    refs={name:execution[name] for name in ['input','build','beforeInstall','installedBeforeLaunch']}
    paths={name:old.ref(root,value) for name,value in refs.items()}
    inputs,build,before,installed=[old.read(paths[name]) for name in refs]
    if (inputs.get('kind')!='unicodeSaveSlotsProbeInputs' or inputs.get('usedStubs') is not False
            or inputs.get('identity',{}).get('sha256')!=identity_sha or build.get('usedStubs') is not False
            or build.get('strictSignaturePassed') is not True or before.get('capturedBeforeFirstInstall') is not True
            or before.get('strictSignaturePassed') is not True or installed.get('matchesSignedBeforeFirstInstall') is not True
            or build.get('bundleIdentifier')!='dev.renreader.probe.unicodeslots20261111'):
        raise ValueError('The new native program is not bound before first installation')
    old.ref(root,inputs['identity'])
    if inputs.get('candidateArtifacts')!={n:r['sha256'] for n,r in identity['candidateArtifacts'].items()}:
        raise ValueError('The actual native program used another candidate resource tree')
    manifest=old.read(old.ref(root,inputs['candidateManifest']))
    if (manifest!=old.read(old.ref(root,identity['buildInputs']['manifest']))
            or inputs.get('allowedDelta')!=manifest['allowedDelta']):
        raise ValueError('The actual native program did not use the frozen69-leaf generation')
    if type(inputs.get('sources')) is not dict or set(inputs['sources'])!=PROBE_SOURCES:
        raise ValueError('The exact9 compiled native probe sources are required')
    for name,record in inputs['sources'].items():
        expected=(paths['input'].parent/'SourceInputs'/name).relative_to(root).as_posix()
        if type(record) is not dict or set(record)!={'sha256','frozenPath'} or record['frozenPath']!=expected:
            raise ValueError('The actual compiled source snapshot path changed: '+name)
        old.ref(root,{'path':record['frozenPath'],'sha256':record['sha256']})
        if name.startswith(('RuntimeKit/Bridge/','RuntimeKit/Native/')) and record['sha256']!=identity['predecessorSources'][name]['sha256']:
            raise ValueError('A probe Native/Bridge input changed')
    app=old.safe(root/build['appPath'],directory=True);leaves=old.program_inventory(app)
    app_info=plistlib.loads((app/'Info.plist').read_bytes())
    if (app_info.get('CFBundleExecutable')!='UnicodeSlotsProbe' or app_info.get('CFBundleIdentifier')!='dev.renreader.probe.unicodeslots20261111'
            or app_info.get('MinimumOSVersion')!='15.5' or app_info.get('RRUnicodePlans')!=inputs.get('plans')):
        raise ValueError('The actual native App executable/identity/plan changed')
    if (leaves!=build.get('signedAppLeaves') or leaves!=before.get('actualAppLeaves') or leaves!=installed.get('actualAppLeaves')
            or build.get('inputs')!=refs['input'] or before.get('build')!=refs['build']):
        raise ValueError('The actual program differs from its signed preinstall and installed inventories')
    for version in old.VERSIONS:
        prefix='RenPy'+version.replace('.','')+'.bundle/'
        expected={n[len(prefix):]:r['sha256'] for n,r in identity['candidateArtifacts'].items() if n.startswith(prefix)}
        actual={n[len(prefix):]:r['sha256'] for n,r in leaves.items() if n.startswith(prefix)}
        if actual!=expected: raise ValueError('An actually executed complete runtime bundle changed: '+version)
    if leaves.get('runtime-catalog.json',{}).get('sha256')!=identity['candidateArtifacts']['runtime-catalog.json']['sha256']:
        raise ValueError('The actual17 catalog differs')
    prior_cert=old.read(root/old.CERTIFICATE);prior_execution=old.read(old.ref(root,prior_cert['executionEvidence']))
    prior_build_ref=prior_execution['sessions'][0]['programEvidence']['build']
    if build.get('reusedFrameworkBuild')!=prior_build_ref:
        raise ValueError('Reused native signatures are not from the exact frozen parent build')
    prior=old.read(old.ref(root,prior_build_ref));artifacts=root/identity['candidateArtifactsPath']
    packages=sorted(artifacts.glob('*.xcframework'))
    names={p.name[:-len('.xcframework')]+'.framework' for p in packages}
    if len(names)!=21 or set(build.get('frameworkInputs',{}))!=names:
        raise ValueError('The complete21 unchanged native framework inputs are required')
    for package in packages:
        info=plistlib.loads((package/'Info.plist').read_bytes())
        library=next(r for r in info['AvailableLibraries'] if r.get('SupportedPlatformVariant')=='simulator' and 'arm64' in r['SupportedArchitectures'])
        source=package/library['LibraryIdentifier']/library['LibraryPath'];name=source.stem
        target=app/'Frameworks'/source.name;row=build['frameworkInputs'][source.name]
        raw=old.program_inventory(source);signed=old.program_inventory(target)
        prefix='Frameworks/'+source.name+'/'
        previous={n[len(prefix):]:r for n,r in prior['signedAppLeaves'].items() if n.startswith(prefix)}
        reused=old.safe(root/row['reusedSignedFramework'],directory=True)
        if (row.get('candidatePath')!=source.relative_to(artifacts).as_posix() or row.get('beforeSigning')!=raw
                or raw!=prior['frameworkInputs'][source.name]['beforeSigning'] or row.get('signedLeaves')!=previous
                or signed!=previous or old.program_inventory(reused)!=previous
                or old.image_identity(root,source/name)!=old.image_identity(root,target/name)):
            raise ValueError('A signed native image or its real raw source differs: '+name)
        seal='_CodeSignature/CodeResources'
        if set(raw)-set(signed) or set(signed)-set(raw)-{seal} or any(raw[n]!=signed[n] for n in raw if n not in {name,seal}):
            raise ValueError('A native non-signature resource changed: '+name)
    commands=build.get('commands')
    if (type(commands) is not list or not commands
            or any(type(c) is not dict or type(c.get('exitCode')) is not int or c['exitCode']!=0
                   or type(c.get('command')) is not list or not all(type(a) is str for a in c['command']) for c in commands)):
        raise ValueError('The actual build command recipe did not complete successfully')
    sdk_command=['xcrun','--sdk','iphonesimulator','--show-sdk-path']
    sdk_records=[c for c in commands if c['command']==sdk_command]
    if len(sdk_records)!=1 or type(sdk_records[0].get('stdout')) is not str:
        raise ValueError('The actual simulator SDK discovery command changed')
    sdk=sdk_records[0]['stdout'].strip()
    if not Path(sdk).is_absolute() or '/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator' not in sdk or not sdk.endswith('.sdk'):
        raise ValueError('The actual compiler did not select an iPhone simulator SDK')
    recipe=[]
    for package in packages:
        framework=package.stem+'.framework';target=app/'Frameworks'/framework
        preserved=root/prior['appPath']/'Frameworks'/framework
        if build['frameworkInputs'][framework]['reusedSignedFramework']!=preserved.relative_to(root).as_posix():
            raise ValueError('A signed framework copy did not come from the pinned prior App')
        recipe.extend([['cp','-cR',str(preserved),str(target)],['codesign','--verify','--strict',str(target)]])
    for bundle in sorted(artifacts.glob('*.bundle')):
        recipe.append(['cp','-cR',str(bundle),str(app/bundle.name)])
    recipe.append(['cp','-cR',str(root/'App/TranslationFonts'),str(app/'TranslationFonts')])
    recipe.append(sdk_command)
    frozen=paths['input'].parent/'SourceInputs'
    recipe.append(['xcrun','--sdk','iphonesimulator','clang','-arch','arm64','-isysroot',sdk,
        '-mios-simulator-version-min=15.5','-fobjc-arc','-fmodules','-Werror=unguarded-availability-new',
        '-I'+str(frozen/'RuntimeKit/Bridge'),str(frozen/'RuntimeKit/Bridge/RRRuntimeBridge.m'),
        str(frozen/PROBE_BASE/'UnicodeSlotsProbe.m'),'-framework','Foundation','-framework','UIKit',
        '-Wl,-rpath,@executable_path/Frameworks','-o',str(app/'UnicodeSlotsProbe')])
    recipe.extend([['codesign','--force','--sign','-',str(app)],['codesign','--verify','--deep','--strict',str(app)]])
    if [c['command'] for c in commands]!=recipe:
        raise ValueError('The exact source/arm64/15.5/compiler/link/signing recipe changed')
    strict(app)
    plans=inputs.get('plans')
    expected={(version,phase) for version in old.VERSIONS for phase in ['enhanced','minimal','native']}
    if type(plans) is not list or len(plans)!=51 or {(p.get('runtimeID'),p.get('phase')) for p in plans}!=expected:
        raise ValueError('The actual full17 x3 mode plan is required')
    return inputs


def verify_execution(root, value, identity):
    old=parent(root);execution=old.read(old.ref(root,value['executionEvidence']))
    if (execution.get('kind')!='unicodeSaveSlotsActualSessions' or execution.get('passed') is not True
            or execution.get('usedStubs') is not False or type(execution.get('sessionsCount')) is not int
            or execution['sessionsCount']!=51 or execution.get('profileCount')!=17
            or execution.get('actualSuccessfulLoads')!=238 or execution.get('rejectedLoads')!=595):
        raise ValueError('A new actual51-session/238-load/595-rejection native matrix is required')
    inputs=verify_program(root,execution,identity,value['identity']['sha256'])
    native=ndjson(old.ref(root,execution['nativeEvents']));host=ndjson(old.ref(root,execution['hostEvents']))
    if (any(e.get('type') in {'error','gameError','quarantined','saveFailed','enginePreferencesRetained'} for e in native)
            or any(e.get('type')=='unicodeProbeFailure' for e in host)
            or sum(e.get('type')=='unicodeProbePassed' for e in host)!=1):
        raise ValueError('Failure/quarantine events cannot qualify new save-slot support')
    sessions=execution.get('sessions')
    if type(sessions) is not list or len(sessions)!=51:
        raise ValueError('The exact51 new session records are required')
    identities=set();loads=rejections=0
    for index,(plan,session) in enumerate(zip(inputs['plans'],sessions)):
        if any(session.get(k)!=v for k,v in plan.items()) or type(session.get('epoch')) is not int or type(session.get('sessionID')) is not str:
            raise ValueError('An executed session does not match its actual plan')
        key=(session['sessionID'],session['epoch'])
        if key in identities: raise ValueError('Native session ownership was reused')
        identities.add(key)
        actual=[e for e in native if (e.get('sessionID'),e.get('epoch'))==key]
        recorded=[e for e in host if e.get('sessionIndex')==index]
        if old.read(old.ref(root,session['nativeEvents']))!=actual or old.read(old.ref(root,session['hostEvents']))!=recorded:
            raise ValueError('The per-session raw record differs from the global raw events')
        def one(kind):
            matches=[e for e in actual if e.get('type')==kind]
            if len(matches)!=1: raise ValueError('Missing/duplicate actual event '+kind)
            return matches[0]
        ready=one('ready');installed=one('unicodeSaveSlotsInstalled');closed=one('unicodeSaveSlotsClosed');prepared=one('unicodeFixturePrepared')
        enhanced=plan['phase']!='native'
        if (ready.get('runtimeVersion')!=plan['runtimeID'] or ready.get('launchMode')!=('nativeCompatibility' if not enhanced else plan['phase'])
                or ready.get('capabilities',{}).get('unicodeSaveSlotsV1') is not enhanced
                or ready.get('capabilities',{}).get('readingTools') is not enhanced
                or installed.get('unicodeSaveSlotsV1') is not enhanced or type(installed.get('schemaVersion')) is not int or installed['schemaVersion']!=1
                or installed.get('maximumFileBytes')!=512*1024*1024 or installed.get('state')!=('installed' if enhanced else 'bypassed')
                or type(closed.get('schemaVersion')) is not int or closed['schemaVersion']!=1
                or closed.get('state')!='closed' or one('threadAudit').get('remaining')!=[]):
            raise ValueError('An actual capability/reset/close does not match the negotiated mode')
        one('didReset')
        complete=[e for e in recorded if e.get('type')=='unicodeSessionComplete']
        stale=[e for e in recorded if e.get('type')=='unicodeStaleAdmissionChecked']
        if (len(complete)!=1 or complete[0].get('bridgeState')!='idle' or complete[0].get('sessionID')!=key[0]
                or complete[0].get('epoch')!=key[1] or len(stale)!=1
                or not admission_rejected(stale[0].get('wrongOwnerRejected')) or not admission_rejected(stale[0].get('wrongEpochRejected'))):
            raise ValueError('The actual owner/epoch admission or quiescent idle state was not proved')
        suffix=prepared.get('suffix');slots=prepared.get('slots')
        expected_names=['章节一','日本語_한국어','Caf\u00e9_e\u0301_\U0001f600','chapter 01 (manual)','a'*81,
                        'b'*(255-len(suffix.encode('utf-8'))) if type(suffix) is str else '', 'quick-legacy']
        if type(slots) is not list or len(slots)!=7 or [s.get('slot') for s in slots]!=expected_names or [s.get('marker') for s in slots]!=list(range(101,108)):
            raise ValueError('The seven real original save names/markers were not exercised')
        rejected_names=['不存在','链接槽','目录槽','../escape','a/b','a\\b','.','..','','a\n','a\u0085','c'*255]
        if prepared.get('rejectedSlots')!=rejected_names:
            raise ValueError('The actual invalid/path/control/file-kind/suffix-byte boundary cases changed')
        submitted=[e for e in recorded if e.get('type')=='unicodeCommandSubmitted'];finished=[e for e in recorded if e.get('type')=='unicodeTestComplete']
        expected_count=21 if enhanced else 7
        if len(submitted)!=expected_count or len(finished)!=expected_count or complete[0].get('testCount')!=expected_count:
            raise ValueError('The actual positive/negative command matrix is incomplete')
        if enhanced and [e.get('test',{}).get('payload') for e in submitted[7:]]!=([{'slot':s} for s in rejected_names]+[{'slot':'章节一','unexpected':True},{'slot':42}]):
            raise ValueError('The actual strict-payload/invalid-slot negative coverage changed')
        expected_markers=[];request_ids=set();accepted=rejected=0
        for step,(command,finish) in enumerate(zip(submitted,finished)):
            rid=command.get('requestID');test=command.get('test')
            if (type(rid) is not str or rid in request_ids or command.get('testIndex')!=step or finish.get('testIndex')!=step
                    or finish.get('requestID')!=rid or finish.get('test')!=test or type(test) is not dict or type(test.get('reject')) is not bool):
                raise ValueError('An actual command/response correlation changed')
            request_ids.add(rid);responses=[e for e in actual if e.get('requestID')==rid]
            expected_reject=not enhanced or step>=7
            if test['reject'] is not expected_reject:
                raise ValueError('The actual matrix relabeled a positive/negative request')
            if step<7 and (test.get('payload')!={'slot':expected_names[step]} or test.get('marker')!=101+step):
                raise ValueError('An actual original-name load payload changed')
            if expected_reject:
                if sum(e.get('type')=='commandRejected' for e in responses)!=1 or any(e.get('type')=='ack' for e in responses):
                    raise ValueError('A required negative request was not rejected')
                rejected+=1
            else:
                if sum(e.get('type')=='ack' and e.get('status')=='accepted' for e in responses)!=1 or any(e.get('type')=='commandRejected' for e in responses):
                    raise ValueError('An actual positive load was not accepted')
                accepted+=1;expected_markers.append(101+step)
        if [e.get('marker') for e in actual if e.get('type')=='unicodeFixtureLoaded']!=expected_markers:
            raise ValueError('Accepted commands did not actually restore the saved game markers')
        if session.get('actualSuccessfulLoads')!=accepted or session.get('rejectedLoads')!=rejected:
            raise ValueError('The native verifier relabeled the raw session totals')
        if sum(e.get('type')=='commandRejected' for e in actual)!=rejected:
            raise ValueError('An unexplained native command rejection occurred')
        loads+=accepted;rejections+=rejected
    if loads!=238 or rejections!=595: raise ValueError('The actual raw matrix totals changed')
    return execution


def verify_ui(root, value, identity):
    old=parent(root);ui=old.read(old.ref(root,value['uiEvidence']))
    if (ui.get('kind')!='unicodeSaveSlotsIndependentUIReview' or ui.get('passed') is not True
            or ui.get('reviewedActualUI') is not True or ui.get('historicalUIReused') is not False
            or ui.get('identitySHA256')!=value['identity']['sha256']):
        raise ValueError('A new independently reviewed actual Unicode UI run is required')
    evidence=ui.get('evidence')
    required={'candidateBuildInputs','candidateBuildVerification','uiRunInputs','fixtureLoads','testLog'}
    if type(evidence) is not dict or not required<=set(evidence):
        raise ValueError('The new UI build/run/actual-load proof closure is incomplete')
    paths={name:old.ref(root,record) for name,record in evidence.items()}
    build_inputs=old.read(paths['candidateBuildInputs']);build=old.read(paths['candidateBuildVerification']);run=old.read(paths['uiRunInputs'])
    bindings=ui.get('unicodeSourceSHA256')
    if type(bindings) is not dict or set(bindings)!=UI_SOURCES or run.get('unicodeSourceSHA256')!=bindings:
        raise ValueError('The exact4 Unicode App source bindings are required')
    for name,digest in bindings.items():
        if sha(root/name)!=digest or build_inputs.get(name)!=digest:
            raise ValueError('A Unicode App source differs from the actual reviewed build: '+name)
    # The parent certificate independently binds its original four Engine App
    # sources. New Unicode support does not rewrite that historical evidence.
    parent_certificate=old.read(root/old.CERTIFICATE)
    parent_ui=old.read(old.ref(root,parent_certificate['uiEvidence']))
    for name,digest in parent_ui['engineSourceSHA256'].items():
        if sha(root/name)!=digest or build_inputs.get(name)!=digest:
            raise ValueError('An immutable Engine App source changed: '+name)
    parent_identity=old.read(old.ref(root,parent_certificate['identity']))
    wrapper=old.parent(root,root/parent_identity['predecessorSourcesPath'])
    locked=wrapper.parent(root).load_parent(root).previous.LOCKED_SOURCES
    for name in locked:
        digest=identity['predecessorSources'][name]['sha256']
        if sha(root/name)!=digest or (name in build_inputs and build_inputs[name]!=digest):
            raise ValueError('A protected source differs from the actually reviewed App: '+name)
    if (build.get('passed') is not True or type(build.get('exitCode')) is not int or build['exitCode']!=0
            or build.get('inputsChanged')!=[] or build.get('minimumOS')!='15.5' or build.get('bundleID')!=UI_BUNDLE
            or run.get('bundleID')!=UI_BUNDLE or run.get('appGroup')!=UI_GROUP or run.get('displayName')!='RenReader Unicode QA'
            or run.get('status')!='PASS' or type(run.get('testExitCode')) is not int or run['testExitCode']!=0
            or run.get('postVerificationPassed') is not True or run.get('testSourceUnchangedAfterRun') is not True
            or run.get('runnerUnchangedAfterRun') is not True or run.get('fixturesUnchangedAfterRun') is not True
            or run.get('unicodeSourcesUnchangedAfterRun') is not True or run.get('qualificationInputsUnchangedAfterRun') is not True
            or run.get('originalDevAppContainerAccessed') is not False
            or run.get('only') not in (None,'testUnicodeLiveLoadsAndSaveBrowserPagination')):
        raise ValueError('The actual Unicode UI run/build/isolation did not complete successfully')
    qualifications=run.get('qualificationInputs')
    if type(qualifications) is not dict or set(qualifications)!={'candidateBuildInputs','candidateBuildVerification','identity'}:
        raise ValueError('The UI runner did not bind its actual qualification inputs')
    for name,path in [('candidateBuildInputs',paths['candidateBuildInputs']),('candidateBuildVerification',paths['candidateBuildVerification'])]:
        if qualifications[name]!={'path':str(path),'sha256':sha(path)}:
            raise ValueError('The UI run borrowed another completed build')
    if qualifications['identity']['sha256']!=value['identity']['sha256'] or sha(qualifications['identity']['path'])!=value['identity']['sha256']:
        raise ValueError('The UI run used another candidate identity')
    app=old.safe(build['product'],directory=True)
    if not app.is_relative_to(root) or str(app)!=run.get('sourceProduct'):
        raise ValueError('The actual reviewed UI product is not the frozen candidate App')
    leaves={n:r['sha256'] for n,r in old.filemap(app).items()}
    binaries=build.get('binaries')
    if (leaves!=build.get('signedLeaves') or type(binaries) is not dict or set(binaries)!={'RenReader','RenReader.debug.dylib'}
            or run.get('productSHA256')!=binaries or {n:sha(app/n) for n in binaries}!=binaries):
        raise ValueError('The reviewed UI binary/full signed resource inventory changed')
    info=plistlib.loads((app/'Info.plist').read_bytes())
    if info.get('CFBundleIdentifier')!=UI_BUNDLE or info.get('CFBundleDisplayName')!='RenReader Unicode QA' or info.get('RenReaderAppGroup')!=UI_GROUP:
        raise ValueError('The actual reviewed App/widget group isolation differs')
    for version in old.VERSIONS:
        prefix='RenPy'+version.replace('.','')+'.bundle/'
        expected={n:r['sha256'] for n,r in identity['candidateArtifacts'].items() if n.startswith(prefix)}
        if {n:digest for n,digest in leaves.items() if n.startswith(prefix)}!=expected:
            raise ValueError('The reviewed UI App packaged another exact runtime: '+version)
    for path_key,digest_key in [('testSourceSnapshot','testSourceSHA256'),('runnerSourceSnapshot','runnerSHA256')]:
        path=old.safe(run[path_key])
        if not path.is_relative_to(root) or sha(path)!=run[digest_key]:
            raise ValueError('The real UI test/runner snapshot changed')
    log=paths['testLog'].read_text()
    if not re.search(r'testUnicodeLiveLoadsAndSaveBrowserPagination[^\n]*passed',log):
        raise ValueError('The actual Unicode/pagination test did not pass')
    loads=old.read(paths['fixtureLoads'])
    if (loads.get('passed') is not True or loads.get('realRenPyAfterLoadConfirmed') is not True
            or loads.get('directSavedOriginalNames')!=46 or not loads.get('sessions')):
        raise ValueError('The actual App UI did not prove original-name game loads')
    names={'章节一','日本語_한국어','Caf\u00e9_e\u0301_\U0001f600','chapter 01 (manual)','a'*81,'quick-legacy'}|{'page-%02d'%n for n in range(1,41)}
    for session in loads['sessions']:
        originals=session.get('originalNameFiles')
        restored=[{'slot':r.get('slot'),'marker':r.get('marker')} for r in session.get('actualLoads',[])]
        if (type(originals) is not list or len(originals)!=46 or {r.get('slot') for r in originals}!=names
                or restored[-2:]!=[{'slot':'章节一','marker':101},{'slot':'a'*81,'marker':105}]
                or any(type(r.get('byteCount')) is not int or r['byteCount']<=0 or not re.fullmatch('[0-9a-f]{64}',r.get('sha256','')) for r in originals)):
            raise ValueError('The actual46 original-name saves/two restored markers changed')
    strict(app)
    def compared_identity(_root, *, replay=False):
        return {'identity':identity}
    function,unused=derived_built_check(root,identity,verifier=compared_identity,artifacts=root/identity['candidateArtifactsPath'])
    function(root,old.read(root/'RuntimeKit/Patches/overlay-capability-853.json'),app,'iphonesimulator','Debug')
    return ui


def normalized_guard(path):
    data=Path(path).read_bytes();pattern=rb'^CERTIFICATE_SHA256 = [^\n]+$'
    if len(re.findall(pattern,data,re.M))!=1:raise ValueError('Unexpected guard qualification declaration')
    return re.sub(pattern,b'CERTIFICATE_SHA256 = None',data,flags=re.M)


def validate_qualification(root, value, *, artifacts_root=None, source_root=None, replay=False):
    old=parent(root)
    flags={'passed':True,'runtimeExecutionQualified':True,'uiQualified':True,'nativePackagesUnchanged':True,
           'unicodeSaveSlotsQualified':True,'oldOSExecutionQualified':False,'legacyCoreQualified':False,
           'physicalEffectsQualified':False,'networkSandboxQualified':False}
    if (sys.flags.optimize or type(value.get('schemaVersion')) is not int or value['schemaVersion']!=1
            or value.get('kind')!='unicodeSaveSlotsResourceQualification' or any(value.get(k) is not v for k,v in flags.items())
            or value.get('parentGuardSHA256')!=PARENT_GUARD_SHA256 or value.get('parentCertificateSHA256')!=PARENT_CERTIFICATE_SHA256
            or value.get('predecessorFinalReceipt')!={'path':FINAL_RECEIPT,'sha256':FINAL_RECEIPT_SHA256}
            or value.get('guardTemplateSHA256')!=hashlib.sha256(normalized_guard(__file__)).hexdigest()):
        raise ValueError('The explicit current-simulator Unicode qualification scope changed')
    identity=old.read(old.ref(root,value['identity']))
    inspect_candidate(root,identity,artifacts_root=artifacts_root or root/'RuntimeKit/Artifacts',source_root=source_root or root)
    unused,derived=derived_built_check(root,identity)
    if value.get('derivedBuiltCheckSHA256')!=hashlib.sha256(derived.encode()).hexdigest():
        raise ValueError('The built-native comparator changed beyond its explicit successor inputs')
    verify_execution(root,value,identity);verify_ui(root,value,identity)
    replay_predecessor(root,identity,replay=replay)
    return dict(value,identity=identity)


def verify(root, *, replay=True):
    if CERTIFICATE_SHA256 is None or sha(root/CERTIFICATE)!=CERTIFICATE_SHA256:
        raise ValueError('Unicode save-slot successor remains UNQUALIFIED')
    old=parent(root);value=old.read(root/CERTIFICATE)
    # Published verification always inspects the real formal roots. Candidate
    # preview/mutation tests use the separate explicit validation API above.
    return validate_qualification(root,value,artifacts_root=root/'RuntimeKit/Artifacts',source_root=root,replay=replay)


def check(root,contract):
    old=parent(root);certificate=old.read(root/old.CERTIFICATE);identity=old.read(old.ref(root,certificate['identity']))
    old.parent(root,root/identity['predecessorSourcesPath']).parent(root).contract_is_original(root,contract)
    return verify(root)


def check_built_app(root,contract,app,platform,configuration):
    value=verify(root,replay=False);function,unused=derived_built_check(root,value['identity'])
    return function(root,contract,app,platform,configuration)


def image_identity(root,path):
    return parent(root).image_identity(root,path)


def platform_supplement_predecessor(root):
    # New formal resources are verified here; the old validators are only
    # invoked on the actual retained old trees by verify/replay_predecessor.
    verify(root,replay=False)
    old=parent(root);certificate=old.read(root/old.CERTIFICATE)
    identity=old.read(old.ref(root,certificate['identity']))
    original=old.parent(root,root/identity['predecessorSourcesPath']).parent(root).load_parent(root).previous
    return original.safe_root(root/original.FOLDER/'Baseline/RuntimeKit/Artifacts')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--identity',type=Path)
    parser.add_argument('--inspect-candidate',action='store_true');parser.add_argument('--replay-predecessor',action='store_true')
    parser.add_argument('--inspect-built-app',action='store_true');parser.add_argument('--built-app',type=Path)
    parser.add_argument('--platform');parser.add_argument('--configuration');parser.add_argument('--contract',type=Path)
    parser.add_argument('--validate-execution',type=Path)
    args=parser.parse_args();root=args.root.absolute();old=parent(root)
    if args.validate_execution:
        if not args.identity:parser.error('--identity is required')
        identity=old.read(args.identity)
        value={'identity':{'path':args.identity.absolute().relative_to(root).as_posix(),'sha256':sha(args.identity)},
               'executionEvidence':{'path':args.validate_execution.absolute().relative_to(root).as_posix(),'sha256':sha(args.validate_execution)}}
        verify_execution(root,value,identity)
        print(json.dumps(dict(passed=True,actualNativeExecutionGatePassed=True,uiQualified=False,publicationQualified=False),sort_keys=True))
    elif args.inspect_candidate or args.replay_predecessor or args.inspect_built_app:
        if not args.identity:parser.error('--identity is required')
        identity=old.read(args.identity);result=inspect_candidate(root,identity)
        if args.replay_predecessor:replay_predecessor(root,identity);result['fullImmutablePredecessorReplayPassed']=True
        if args.inspect_built_app:
            if not args.built_app or not args.platform or not args.configuration:parser.error('Built-app parameters are required')
            result.update(inspect_built_app(root,identity,args.built_app,args.platform,args.configuration))
        print(json.dumps(result,sort_keys=True));print(MARKER)
    elif args.built_app:
        check_built_app(root,old.read(args.contract),args.built_app,args.platform,args.configuration);print(MARKER)
    elif args.contract:
        check(root,old.read(args.contract));print(MARKER)
    else:
        verify(root);print(MARKER)
