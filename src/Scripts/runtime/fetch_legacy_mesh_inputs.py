#!/usr/bin/env python3
"""Obtain exact public build inputs for the three missing Mesh setter ABIs."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[2]
CACHE=ROOT/'RuntimeKit/.cache/legacy-mesh-build'
VERSIONS={'7.4.11':('7.4.11.2266','2.7.18'),'7.5.3':('7.5.3.22090809','2.7.18'),'8.0.3':('8.0.3.22090809','3.9.10')}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def download(url,target,expected=None):
 target.parent.mkdir(parents=True,exist_ok=True)
 if not target.exists() or expected and sha(target)!=expected:
  partial=target.with_suffix(target.suffix+'.part')
  with urllib.request.urlopen(url,timeout=60) as response,partial.open('wb') as out:shutil.copyfileobj(response,out,1024*1024)
  if expected and sha(partial)!=expected:raise ValueError('Official download SHA256 mismatch: '+url)
  partial.replace(target)
 return {'url':url,'sha256':sha(target)}

def native(version):
 tag,python=VERSIONS[version];folder=CACHE/version;folder.mkdir(parents=True,exist_ok=True)
 metadata=json.loads((ROOT/'RuntimeKit/.cache/official'/version/'paths.json').read_text())
 name='renpy-'+version+'-renios.zip';archive=folder/name
 record=download('https://www.renpy.org/dl/'+version+'/'+name,archive,metadata['sha256'][name])
 sdk=folder/('renpy-'+version+'-sdk')
 if not (folder/'renios-extracted').exists():
  with zipfile.ZipFile(archive) as source:
   for name in source.namelist():
    if name.endswith('/') or not ('/prebuilt/' in name and name.endswith('.a') or name.endswith('prototype.xcodeproj/project.pbxproj')):continue
    target=sdk/name
    if not target.resolve().is_relative_to(sdk.resolve()):raise ValueError('Unsafe archive path')
    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read(name))
  (folder/'renios-extracted').write_text(record['sha256']+'\n')
 code=folder/'renpy-source.tar.gz';source_record=download('https://codeload.github.com/renpy/renpy/tar.gz/refs/tags/'+tag,code)
 source_folder=folder/'source'
 if not source_folder.exists():
  source_folder.mkdir()
  with tarfile.open(code) as source:
   for member in source.getmembers():
    relative=Path(*Path(member.name).parts[1:])
    if member.isfile() and (str(relative).startswith('renpy/') and relative.suffix in ('.pxd','.pyx','.h','.py') or str(relative)=='LICENSE.txt'):
     target=source_folder/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.extractfile(member).read())
 (folder/'inputs.json').write_text(json.dumps({'runtimeID':version,'tag':tag,'pythonVersion':python,'renios':record,'renpySource':source_record,'sdk':str(sdk),'source':str(source_folder)},indent=2)+'\n')
 return version

def python_headers(version):
 target=CACHE/('Python-'+version+'.tgz');record=download('https://www.python.org/ftp/python/'+version+'/Python-'+version+'.tgz',target)
 folder=CACHE/('Python-'+version)
 if not folder.exists():
  with tarfile.open(target) as source:source.extractall(CACHE,filter='data')
 # Configure only the exact headers. No Python interpreter is built or used
 # to run game code. 2.7 predates Apple's arm64 arch spelling; the tiny patch
 # merely chooses its libtool architecture name while configure measures sizes.
 configure=folder/'configure';original=configure.read_text()
 patch=''
 if version=='2.7.18':
  old='    \tcase `/usr/bin/arch` in\n    \ti386)'
  new='    \tcase `/usr/bin/arch` in\n        arm64) MACOSX_DEFAULT_ARCH="arm64" ;;\n    \ti386)'
  if old in original:
   assert original.count(old)==2
   patched=original.replace(old,new)
   import difflib
   patch=''.join(difflib.unified_diff(original.splitlines(keepends=True),patched.splitlines(keepends=True),fromfile='a/configure',tofile='b/configure'))
   configure.write_text(patched)
  else:
   assert 'arm64) MACOSX_DEFAULT_ARCH="arm64"' in original
 arguments=['./configure']+(['--enable-unicode=ucs2'] if version=='2.7.18' else [])
 if not (folder/'pyconfig.h').exists():
  with (folder/'configure-headers.log').open('w') as log:
   subprocess.run(arguments,cwd=folder,stdout=log,stderr=subprocess.STDOUT,check=True)
 record.update(headerConfigureArguments=arguments,headerConfigSHA256=sha(folder/'pyconfig.h'),hostArchitecture='arm64',runtimeInterpreterBuilt=False)
 (folder/'source-record.json').write_text(json.dumps(record,indent=2)+'\n')
 if patch:(folder/'arm64-header-configure.patch').write_text(patch)
 return version

def cython_source(version):
 metadata=json.load(urllib.request.urlopen('https://pypi.org/pypi/Cython/'+version+'/json',timeout=60))
 item=next(x for x in metadata['urls'] if x['packagetype']=='sdist')
 archive=CACHE/('Cython-'+version+'.tar.gz')
 record=download(item['url'],archive,item['digests']['sha256'])
 folder=CACHE/('Cython-'+version)
 if not folder.exists():
  with tarfile.open(archive) as source:source.extractall(CACHE,filter='data')
 (CACHE/('cython-'+version+'-source.json')).write_text(json.dumps(record,indent=2)+'\n')
 return 'Cython '+version

def pygame_headers():
 # Exact official header sources for the sole 7411 texture-extent correction.
 folder=CACHE/'7.4.11';name='pygame_sdl2-2.1.0-for-renpy-7.4.11.tar.gz'
 record=download('https://www.renpy.org/dl/7.4.11/'+name,folder/name,'ff497cb2f2406b08d99a4e720cab0f42b31e714e427b70b5e93225618262bb5b')
 source=folder/'pygame-source'
 with tarfile.open(folder/name) as archive:
  for member in archive.getmembers():
   if not member.isfile():continue
   rel=Path(*Path(member.name).parts[1:]);target=source/rel
   if not target.resolve().is_relative_to(source.resolve()):raise ValueError('Unsafe source path')
   target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(member).read())
 with tarfile.open(folder/'renpy-source.tar.gz') as archive:
  for member in archive.getmembers():
   rel=Path(*Path(member.name).parts[1:])
   if member.isfile() and str(rel).startswith('module/') and rel.suffix in ('.h','.pxd','.py'):
    target=folder/'source'/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(member).read())
 import os
 output=folder/'pygame-api';output.mkdir(exist_ok=True)
 env=dict(os.environ,PYTHONPATH=str(CACHE/'Cython-0.29.20'))
 for name in ('rwobject','surface','display'):
  subprocess.run(['/usr/bin/python3','-c','from Cython.Compiler.Main import main; main(command_line=True)','-I',str(source/'src'),'-I',str(source/'include'),'-o',str(output/('pygame_sdl2.'+name+'.c')),str(source/'src/pygame_sdl2'/(name+'.pyx'))],env=env,check=True)
 record.update(checksumURL='https://www.renpy.org/dl/7.4.11/checksums.txt',scope='Generate exact public C API headers only; do not replace pygame implementation')
 (folder/'pygame-source.json').write_text(json.dumps(record,indent=2)+'\n')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--version',action='append',choices=list(VERSIONS));args=parser.parse_args()
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
  tasks=[pool.submit(native,v) for v in args.version or VERSIONS]+[pool.submit(python_headers,p) for p in ['2.7.18','3.9.10']]+[pool.submit(cython_source,p) for p in ['0.29.20','0.29.25']]
  for task in concurrent.futures.as_completed(tasks):print('Verified source inputs:',task.result(),flush=True)

 if not args.version or '7.4.11' in args.version:pygame_headers()
