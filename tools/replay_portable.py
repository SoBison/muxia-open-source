#!/usr/bin/env python3
"""Replay the final App objects from a relocated kit and explicit providers."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def executable(path):
    data=Path(path).read_bytes()
    magic,cpu,subtype,kind,count,extent,flags,reserved=struct.unpack_from('<8I',data)
    if (magic,cpu,kind)!=(0xfeedfacf,0x100000c,2):raise ValueError('Expected thin arm64 executable')
    offset=32;sections={};dylibs=[];floors=[];uuid=None;signature=False
    for _ in range(count):
        command,size=struct.unpack_from('<II',data,offset);item=data[offset:offset+size]
        if size<8 or offset+size>32+extent:raise ValueError('Invalid Mach-O load command')
        if command==0x19:
            for i in range(struct.unpack_from('<I',item,64)[0]):
                sec=item[72+i*80:72+(i+1)*80]
                name=sec[16:32].split(b'\0')[0].decode()+'/'+sec[:16].split(b'\0')[0].decode()
                address,length,start=struct.unpack_from('<QQI',sec,32);sf=struct.unpack_from('<I',sec,64)[0]
                value={'size':length,'flags':sf}
                if sf&255 not in (1,12,18):
                    if start+length>len(data):raise ValueError('Truncated Mach-O section')
                    value['sha256']=hashlib.sha256(data[start:start+length]).hexdigest()
                sections[name]=value
        elif command in (12,0x80000018,0x8000001f,0x80000023):
            start=struct.unpack_from('<I',item,8)[0];dylibs.append({'command':command,'name':item[start:].split(b'\0')[0].decode()})
        elif command==0x32:floors.append(list(struct.unpack_from('<4I',item,8)))
        elif command==0x1b:uuid=item[8:24].hex()
        elif command==0x1d:signature=True
        offset+=size
    if offset!=32+extent:raise ValueError('Incomplete Mach-O table')
    return {'cpu':cpu,'subtype':subtype,'kind':kind,'sections':sections,'dylibs':dylibs,'uuid':uuid,'buildVersions':floors,'hasCodeSignature':signature}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kit',type=Path,default=Path(__file__).resolve().parent)
    for option in ['artifact-root','sdk','clang','output']:p.add_argument('--'+option,type=Path,required=True)
    p.add_argument('--manifest-sha',required=True)
    p.add_argument('--modified-components',action='store_true',help='Permit a deliberately modified component to change the image; hashes still must match your updated manifest.')
    args=p.parse_args();kit=args.kit.resolve();manifest=kit/'portable-manifest.json'
    if sha(manifest)!=args.manifest_sha:raise ValueError('Portable manifest SHA mismatch')
    m=json.loads(manifest.read_text());checked={}

    def check(path,digest):
        path=Path(path)
        if not path.is_file() or sha(path)!=digest:raise ValueError('Input SHA mismatch: '+str(path))
        checked[str(path)]=digest

    def package(name):
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts:raise ValueError('Unsafe kit path')
        result=kit/rel
        if result.resolve()!=result:raise ValueError('Kit input may not be an alias')
        return result

    for name,row in m['packageFiles'].items():check(package(name),row['sha256'])
    clang=args.clang.resolve();sdk=args.sdk.resolve();tc=clang.parents[2]
    strip=clang.parent/'strip';ld=clang.parent/'ld'
    for name,path in [('clang',clang),('strip',strip),('ld',ld),('nm',clang.parent/'nm')]:check(path,m['toolchain'][name]['sha256'])
    version=subprocess.check_output([str(clang),'--version'],text=True)
    if [x for x in version.splitlines() if not x.startswith('InstalledDir:')] != m['toolchain']['clangVersionIdentity']:raise ValueError('Clang version differs')
    check(sdk/'SDKSettings.json',m['toolchain']['sdkSettingsSHA256'])
    for row in m['toolchain']['physicalProviders']:
        check((sdk if row['base']=='sdk' else tc)/row['relativePath'],row['sha256'])
    artifact=args.artifact_root.resolve()
    if set(m['publicFrameworks']) & {'RRLive2DCore','RRLive2DLegacyCore'}:raise ValueError('Excluded SDK provider in no-Live2D kit')
    frameworks={};search=[]
    for name,row in m['publicFrameworks'].items():
        fw=artifact/(name+'.framework')
        if not fw.is_dir():
            xc=artifact/(name+'.xcframework');info=plistlib.loads((xc/'Info.plist').read_bytes())
            variants=[v for v in info['AvailableLibraries'] if v['SupportedPlatform']=='ios' and not v.get('SupportedPlatformVariant') and 'arm64' in v['SupportedArchitectures']]
            if len(variants)!=1 or variants[0]['LibraryPath']!=name+'.framework':raise ValueError('Ambiguous public framework slice')
            v=variants[0];fw=xc/v['LibraryIdentifier']/v['LibraryPath']
        check(fw/name,row['sha256']);frameworks[name]=str(fw)
        if fw.parent not in search:search.append(fw.parent)
    # Check the actual first search-path resolution for every explicit public provider.
    for name,row in m['publicFrameworks'].items():
        candidates=[d/(name+'.framework')/name for d in search if (d/(name+'.framework')/name).is_file()]
        if not candidates:raise ValueError('Unresolved explicit framework: '+name)
        check(candidates[0],row['sha256'])
    out=args.output.absolute()
    if out.exists() or out.resolve()!=out or out.is_relative_to(kit) or out.is_relative_to(artifact):raise ValueError('Use a fresh separate output')
    out.mkdir(parents=True);(out/'BeforeStrip').mkdir();(out/'AfterStrip').mkdir()
    filelist=out/'RenReader.LinkFileList';filelist.write_text('\n'.join(str(package(n)) for n in m['objectOrder'])+'\n')
    before=out/'BeforeStrip/RenReader';after=out/'AfterStrip/RenReader'
    old=m['originalPaths'];exact={old['clang']:str(clang),old['filelist']:str(filelist),old['module']:str(package(m['module'])),
        old['output']:str(before),old['dependency']:str(out/'RenReader_dependency_info.dat'),old['lto']:str(out/'RenReader_lto.o'),
        '-Wl,-force_load,'+old['sevenzip']:'-Wl,-force_load,'+str(package(m['sevenzip'])),
        '-Wl,-unexported_symbols_list,'+old['symbolMask']:'-Wl,-unexported_symbols_list,'+str(package(m['symbolMask']))}
    argv=[];remaps=[];inserted=False
    for value in m['originalLinkArgv']:
        if value.startswith('-F') and old['root'] in value:
            if not inserted:argv+=['-F'+str(d) for d in search];inserted=True
            remaps.append({'original':value,'action':'explicit-verified-framework-providers'});continue
        if value.startswith('-L') and old['root'] in value:
            remaps.append({'original':value,'action':'remove-original-build-product-search-root; no physical -l provider there in actual ld graph'});continue
        if value in exact:
            new=exact[value]
        else:
            new=value.replace(old['sdk'],str(sdk)).replace(old['toolchain'],str(tc))
            if old['root'] in value:raise ValueError('Unmapped original workspace dependency: '+value)
        if new!=value:remaps.append({'original':value,'actual':new})
        argv.append(new)
    if not inserted:raise ValueError('Actual framework search was not reconstructed')
    log=out/'link.log'
    with log.open('w') as f:result=subprocess.run(argv,cwd=out,stdout=f,stderr=subprocess.STDOUT)
    if result.returncode:raise ValueError('Actual relocated link failed; see '+str(log))
    before_sha=sha(before);shutil.copyfile(before,after)
    strip_argv=[str(strip),'-D',str(after)];strip_log=out/'strip.log'
    with strip_log.open('w') as f:status=subprocess.run(strip_argv,cwd=out,stdout=f,stderr=subprocess.STDOUT)
    if status.returncode:raise ValueError('Actual relocated strip failed')
    image=executable(after);base=m['comparisonBaseline']
    exports=sorted(set(subprocess.check_output([str(clang.parent/'nm'),'-gjU',str(after)],text=True).splitlines()))
    passed=image['sections']==base['sections'] and image['dylibs']==base['dylibs'] and image['buildVersions']==base['buildVersions'] and exports==m['exports'] and not image['hasCodeSignature'] and not any('live2d' in x['name'].lower() for x in image['dylibs'])
    modified_ok=args.modified_components and image['cpu']==base['cpu'] and image['subtype']==base['subtype'] and image['kind']==base['kind'] and image['buildVersions']==base['buildVersions'] and not image['hasCodeSignature'] and not any('live2d' in x['name'].lower() for x in image['dylibs'])
    successful=passed or modified_ok
    for path,digest in checked.items():
        if sha(path)!=digest:raise ValueError('Provider/kit input changed during replay')
    receipt={'schemaVersion':1,'scope':'Actual no-Live2D path-remapped own-object App relink/strip; no signing, publication or full-native source-completeness qualification',
        'manifest':{'sha256':args.manifest_sha,'path':str(manifest)},'parameters':{k:str(v) for k,v in vars(args).items()},
        'commands':[{'argv':argv,'cwd':str(out),'exit':result.returncode,'logSHA256':sha(log)},{'argv':strip_argv,'cwd':str(out),'exit':status.returncode,'logSHA256':sha(strip_log)}],
        'remapping':remaps,'verifiedProviders':checked,'publicFrameworks':frameworks,'excludedCoreBodiesCopied':False,'sdkOrToolBodiesCopied':False,
        'beforeStrip':{'path':str(before),'sha256':before_sha},'afterStrip':{'path':str(after),'sha256':sha(after)},
        'mainMachO':image,'exports':exports,'comparisonPassed':passed,'modifiedComponentMode':args.modified_components,'relinkSucceeded':successful,'uuidEqual':image['uuid']==base['uuid'],
        'coreLoadCommands':[x for x in image['dylibs'] if 'live2d' in x['name'].lower()],
        'inputsUnchanged':True,'sourceDeliveryComplete':False,'relinkDeliveryComplete':False,'publicationQualified':False}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'comparisonPassed':passed,'uuidEqual':receipt['uuidEqual'],'sections':len(image['sections']),'dylibs':len(image['dylibs']),
        'coreLoadCommands':receipt['coreLoadCommands'],'receiptSHA256':sha(out/'receipt.json')}))
    if not successful:raise SystemExit(1)


if __name__=='__main__':main()
