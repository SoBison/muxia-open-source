#!/usr/bin/env python3
"""Replace only exact SDL2.0.20 input objects in official archives."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
from prepare_sdl_gate import prepare

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / 'RuntimeKit'
CACHE = KIT / '.cache/sdl-gate'
SOURCE = CACHE / 'SDL-release-2.0.20'

def command(args, **kwargs):
    subprocess.run(list(map(str, args)), check=True, **kwargs)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def defined(path):
    value = subprocess.check_output(['nm', '-gU', str(path)], text=True)
    return {line.split()[-1] for line in value.splitlines() if line.strip() and not line.endswith(':')}

def compile_gate(official_archive, platform, output_root=None):
    archive_input = CACHE / 'SDL-release-2.0.20.tar.gz'
    expected = '2a026753af9b03fca043824bca8341f74921a836d28729e0c31aa262202a83c6'
    if not archive_input.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve('https://codeload.github.com/libsdl-org/SDL/tar.gz/refs/tags/release-2.0.20', archive_input)
    if sha(archive_input) != expected:
        raise RuntimeError('Official SDL source archive SHA256 mismatch')
    if not SOURCE.exists():
        with tarfile.open(archive_input) as archive:
            archive.extractall(CACHE, filter='data')
    build_root = Path(output_root) if output_root is not None else CACHE
    patched = build_root / 'patched'
    prepare(SOURCE, patched)
    output = build_root / platform
    output.mkdir(parents=True, exist_ok=True)
    sysroot = subprocess.check_output(['xcrun', '--sdk', platform, '--show-sdk-path'], text=True).strip()
    deployment = '-mios-simulator-version-min=17.0' if platform == 'iphonesimulator' else '-miphoneos-version-min=17.0'
    flags = ['xcrun', '--sdk', platform, 'clang', '-arch', 'arm64', '-isysroot', sysroot, deployment,
             '-std=gnu11', '-fvisibility=hidden', '-O2', '-I', patched / 'include', '-I', patched / 'src', '-I', KIT / 'Native']
    thin = output / 'libSDL2-original-arm64.a'
    arches = subprocess.check_output(['lipo', '-archs', official_archive], text=True).split()
    if Path(official_archive).read_bytes()[:4] != b'!<ar':
        command(['lipo', official_archive, '-thin', 'arm64', '-output', thin])
    else:
        shutil.copy2(official_archive, thin)
    replaced = ('SDL_keyboard', 'SDL_events', 'SDL_mouse', 'SDL_video', 'SDL_virtualjoystick')
    for name in replaced:
        folder = 'joystick/virtual' if name == 'SDL_virtualjoystick' else 'video' if name == 'SDL_video' else 'events'
        command(flags + ['-c', patched / ('src/' + folder + '/' + name + '.c'), '-o', output / (name + '.o')])
        original = output / ('original-' + name + '.o')
        with original.open('wb') as file:
            command(['ar', '-p', thin, name + '.o'], stdout=file)
        missing = defined(original) - defined(output / (name + '.o'))
        if missing:
            raise RuntimeError('SDL object lost original API: ' + repr(sorted(missing)))
    command(flags + ['-c', KIT / 'Native/RRInputGate.c', '-o', output / 'RRInputGate.o'])
    command(flags + ['-c', KIT / 'Native/RRAuxiliaryInput.c', '-o', output / 'RRAuxiliaryInput.o'])
    archive = output / 'libSDL2-gated.a'
    shutil.copy2(thin, archive)
    command(['ar', '-d', archive, *[name + '.o' for name in replaced]])
    command(['ar', '-r', archive, *[output / (name + '.o') for name in replaced], output / 'RRAuxiliaryInput.o'])
    command(['ranlib', archive])
    records = {'SDLRelease': '2.0.20', 'sourceURL': 'https://github.com/libsdl-org/SDL/tree/release-2.0.20',
               'sourceArchiveSHA256': sha(CACHE / 'SDL-release-2.0.20.tar.gz'), 'officialArchiveSHA256': sha(official_archive),
               'patchedArchiveSHA256': sha(archive), 'replacedObjects': list(replaced),
               'hostSourceSHA256': {str(path.relative_to(ROOT)): sha(path) for path in [KIT / 'Native/RRPlatform.m', KIT / 'Native/RRInputGate.c', KIT / 'Native/RRInputGate.h', KIT / 'Native/RRAuxiliaryInput.c', KIT / 'Native/RRAuxiliaryInput.h', ROOT / 'Scripts/runtime/prepare_sdl_gate.py', Path(__file__)]},
               'patchSHA256': sha(patched / 'RenReader-input-gate.patch'), 'originalPublicSymbolsPreserved': True}
    (output / 'provenance.json').write_text(json.dumps(records, indent=2) + '\n')
    return archive, output / 'RRInputGate.o', patched
