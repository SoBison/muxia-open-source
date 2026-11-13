#!/usr/bin/env python3
"""Relink the 19 shipped arm64 iOS Native images from portable public inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def safe(base, name):
    rel = Path(name)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('Unsafe relative path: ' + name)
    path = base / rel
    if path.resolve() != path or not path.is_file():
        raise ValueError('Input missing or aliased: ' + str(path))
    return path


def check(path, row):
    if not path.is_file() or path.is_symlink() or path.stat().st_size != row['size'] or sha(path) != row['sha256']:
        raise ValueError('Input content mismatch: ' + str(path))


def image(path):
    data = path.read_bytes()
    magic, cpu, subtype, kind, count, extent, flags, reserved = struct.unpack_from('<8I', data)
    if (magic, cpu, kind) != (0xfeedfacf, 0x100000c, 6):
        raise ValueError('Expected thin arm64 dylib: ' + str(path))
    offset = 32
    sections, dylibs, floors, uuid = {}, [], [], None
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, offset)
        item = data[offset:offset + size]
        if size < 8 or offset + size > 32 + extent:
            raise ValueError('Invalid Mach-O load command')
        if command == 0x19:
            for i in range(struct.unpack_from('<I', item, 64)[0]):
                sec = item[72 + i * 80:72 + (i + 1) * 80]
                name = sec[16:32].split(b'\0')[0].decode() + '/' + sec[:16].split(b'\0')[0].decode()
                address, length, start = struct.unpack_from('<QQI', sec, 32)
                sf = struct.unpack_from('<I', sec, 64)[0]
                value = {'size': length, 'flags': sf}
                if sf & 255 not in (1, 12, 18):
                    if start + length > len(data):
                        raise ValueError('Truncated Mach-O section')
                    value['sha256'] = hashlib.sha256(data[start:start + length]).hexdigest()
                sections[name] = value
        elif command in (12, 13, 0x80000018, 0x8000001f, 0x80000023):
            start = struct.unpack_from('<I', item, 8)[0]
            dylibs.append({'command': command, 'name': item[start:].split(b'\0')[0].decode(),
                           'versions': list(struct.unpack_from('<II', item, 16))})
        elif command == 0x32:
            floors.append(list(struct.unpack_from('<4I', item, 8)))
        elif command == 0x1b:
            uuid = item[8:24].hex()
        offset += size
    if offset != 32 + extent:
        raise ValueError('Incomplete load commands')
    return {'cpu': cpu, 'subtype': subtype, 'kind': kind, 'sections': sections,
            'dylibs': dylibs, 'buildVersions': floors, 'uuid': uuid}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kit', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--sources', type=Path, required=True)
    p.add_argument('--providers', type=Path, required=True)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--clang', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--framework', action='append', help='Select one or more names; default all 19')
    p.add_argument('--replace', action='append', default=[], metavar='LOGICAL_PATH=FILE',
                   help='Use a deliberately modified static library; record its SHA instead of requiring the supplied SHA')
    a = p.parse_args()
    kit, sources, providers, sdk, clang = [x.resolve() for x in (a.kit, a.sources, a.providers, a.sdk, a.clang)]
    m = json.loads((kit / 'native-manifest.json').read_text())
    inventory = json.loads((sources / 'inventory.json').read_text())
    entries = {r['logicalPath']: r for r in inventory['entries']}
    if len(entries) != len(inventory['entries']):
        raise ValueError('Duplicate logical input paths')
    tc = m['toolchain']
    for name in ('clang', 'ld', 'nm'):
        if sha(clang if name == 'clang' else clang.parent / name) != tc[name]['sha256']:
            raise ValueError('Install the documented Xcode toolchain: ' + name)
    if sha(sdk / 'SDKSettings.json') != tc['sdkSettingsSHA256']:
        raise ValueError('Install the documented iOS SDK')
    replacements = {}
    allowed = {x['logicalPath'] for r in m['links'] for x in r['inputs'] if x['kind'] == 'archive'}
    for value in a.replace:
        logical, physical = value.split('=', 1)
        if logical not in allowed or logical in replacements:
            raise ValueError('Replacement must identify one supplied static library: ' + logical)
        physical = Path(physical).resolve()
        if not physical.is_file():
            raise ValueError('Missing replacement: ' + str(physical))
        replacements[logical] = physical
    out = a.output.absolute()
    if out.exists() or out.resolve() != out or any(out.is_relative_to(x) for x in (kit, sources, providers)):
        raise ValueError('Use a fresh separate output directory')
    out.mkdir(parents=True)
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    checked, materialized, results = {}, {}, []
    selected = a.framework or [r['framework'] for r in m['links']]
    if len(selected) != len(set(selected)) or not set(selected) <= {r['framework'] for r in m['links']}:
        raise ValueError('Unknown or repeated framework')
    for name, row in m['kitFiles'].items():
        path = safe(kit, name); check(path, row); checked[str(path)] = row['sha256']
    for name, row in m['providers'].items():
        path = safe(providers, name + '.framework/' + name)
        check(path, row); checked[str(path)] = row['sha256']

    def materialize(row):
        logical = row['logicalPath']
        if logical in materialized:
            return materialized[logical]
        if logical in replacements:
            source = replacements[logical]
            replacement = True
        else:
            entry = entries.get(logical)
            if not entry or any(entry.get(k) != row[k] for k in ('sha256', 'size')):
                raise ValueError('Sources inventory input differs: ' + logical)
            source = safe(sources, entry['object'])
            check(source, row); checked[str(source)] = row['sha256']
            replacement = False
        digest = sha(source)
        target = out / 'Inputs' / digest / Path(logical).name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            # APFS clone keeps the standalone replay small; no hard links to source materials.
            status = subprocess.run(['/bin/cp', '-c', str(source), str(target)], capture_output=True)
            if status.returncode:
                shutil.copyfile(source, target)
            target.chmod(0o644)
        materialized[logical] = target
        return target

    for row in m['links']:
        if row['framework'] not in selected:
            continue
        name = row['framework']; work = out / name; work.mkdir()
        paths = {x['logicalPath']: materialize(x) for x in row['inputs']}
        values = {'SDK': str(sdk), 'PROVIDERS': str(providers), 'KIT': str(kit), 'WORK': str(work)}
        argv = [str(clang)]
        for value in row['argv']:
            if value.startswith('@INPUT:') and value.endswith('@'):
                value = str(paths[value[7:-1]])
            else:
                for key, replacement in values.items():
                    value = value.replace('@' + key + '@', replacement)
            if '@INPUT:' in value or any('@' + key + '@' in value for key in values):
                raise ValueError('Unmapped command token')
            argv.append(value)
        # Preserve __FILE__ in the retained own source under relocation.
        for source in row['sourcePrefixMaps']:
            argv.append('-ffile-prefix-map=' + str(paths[source['logicalPath']]) + '=' + source['originalPath'])
        argv += ['-MD', '-MF', str(work / 'actual.d'), '-fmodules-cache-path=' + str(out / 'Modules')]
        log = work / 'link.log'; before = time.monotonic()
        env = os.environ.copy(); env['SDKROOT'] = str(sdk)
        with log.open('w') as f:
            status = subprocess.run(argv, cwd=work, env=env, stdout=f, stderr=subprocess.STDOUT)
        result = {'framework': name, 'argv': argv, 'cwd': str(work), 'exitCode': status.returncode,
                  'seconds': round(time.monotonic() - before, 3), 'logSHA256': sha(log)}
        if status.returncode == 0:
            target = work / name; actual = image(target); base = row['baseline']
            exports = sorted(set(subprocess.check_output([str(clang.parent / 'nm'), '-gjU', str(target)], text=True).splitlines()))
            difference = sorted(k for k in set(actual['sections']) | set(base['sections']) if actual['sections'].get(k) != base['sections'].get(k))
            no_core = not any('live2dcore' in x['name'].lower() for x in actual['dylibs'])
            abi = (actual['cpu'], actual['subtype'], actual['kind'], actual['dylibs'], actual['buildVersions'], exports) == (base['cpu'], base['subtype'], base['kind'], base['dylibs'], base['buildVersions'], row['exports'])
            modified = any(x['logicalPath'] in replacements for x in row['inputs'])
            result.update({'sha256': sha(target), 'image': actual, 'exports': exports,
                           'changedSections': difference, 'uuidEqual': actual['uuid'] == base['uuid'],
                           'abiLoadsFloorExportsEqual': abi, 'noCoreLoad': no_core,
                           'unmodifiedSectionsEqual': not difference,
                           'modifiedLibraryMode': modified,
                           'binaryIdentity': sha(target) == row['baselineSHA256'],
                           'passed': abi and no_core})
        else:
            result['passed'] = False
        results.append(result)
        (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: result[k] for k in ('framework', 'exitCode', 'seconds', 'passed')}), flush=True)
    for path, digest in checked.items():
        if sha(path) != digest:
            raise ValueError('Input changed during relink: ' + path)
    receipt = {'schemaVersion': 1, 'startedUTC': started, 'endedUTC': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
               'scope': '19 public device arm64 native links; unsigned outputs only',
               'manifestSHA256': sha(kit / 'native-manifest.json'), 'sourcesInventorySHA256': sha(sources / 'inventory.json'),
               'parameters': {k: str(v) for k, v in vars(a).items()},
               'replacements': {k: {'path': str(v), 'sha256': sha(v), 'size': v.stat().st_size} for k, v in replacements.items()},
               'links': results, 'checkedInputs': checked, 'inputsUnchanged': True,
               'passed': all(r['passed'] for r in results), 'runtimeExecutionQualified': False,
               'sourceDeliveryComplete': False, 'publicationQualified': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not receipt['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
