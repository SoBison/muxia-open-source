#!/usr/bin/env python3
"""Isolated, exact-source public Mesh setter backport; no .pxd/layout change."""
import argparse
import difflib
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import build_runtime
ROOT=Path(__file__).resolve().parents[2]
KIT=ROOT/'RuntimeKit'
CACHE=KIT/'.cache/legacy-mesh-build'
PROFILES={'7.4.11':('2.7.18','0.29.20'),'7.5.3':('2.7.18','0.29.20'),'8.0.3':('3.9.10','0.29.25')}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,**kwargs):subprocess.run(list(map(str,args)),check=True,**kwargs)

def backport(source, target):
    text=source.read_text()
    # The three Python-visible methods were added upstream in 7.6.3. No cdef
    # method, class member or pxd/vtable is added, so all existing consumers
    # keep exactly their profile's original Mesh extension type layout.
    methods=(KIT/'Validation/RendererProductionCandidate/LegacyMeshAPI/7.6.3.23091805/gl2mesh.pyx').read_text()
    methods=methods[methods.index('    def set_geometry_data'):methods.index('    def get_triangles')]
    # Protect the public copy operations from partial rows/indices even though
    # our renderer always supplies properly aligned, validated arrays.
    methods=methods.replace('        points = len(geometry) // self.point_size','''        if len(geometry) % self.point_size:
            raise ValueError("Incomplete geometry point.")
        points = len(geometry) // self.point_size''')
    methods=methods.replace('        if len_attributes > self.allocated_points * self.layout.stride:', '''        if self.layout.stride and len_attributes % self.layout.stride:
            raise ValueError("Incomplete attribute row.")
        if len_attributes > self.allocated_points * self.layout.stride:''')
    methods=methods.replace('        if len_triangles > self.allocated_triangles * 3:', '''        if len_triangles % 3:
            raise ValueError("Incomplete triangle.")
        if len_triangles > self.allocated_triangles * 3:''')
    methods=methods.replace('            self.triangle[i] = triangles[i]', '''            if triangles[i] < 0 or triangles[i] >= self.points or triangles[i] > 65535:
                raise ValueError("Invalid triangle index.")
            self.triangle[i] = triangles[i]''')
    marker='cdef class Mesh:\n'
    assert text.count(marker)==1 and 'def set_geometry_data' not in text
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(text.replace(marker,marker+'\n'+methods,1))
    return hashlib.sha256(methods.encode()).hexdigest()

def static_names(path, name):
    ccode=path.read_text()
    ccode=re.sub(r'Py_InitModule4\("([^\"]+)"',r'Py_InitModule4("renpy.gl2.\1"',ccode)
    ccode=re.sub(r'(__pyx_moduledef.*?\")'+re.escape(name)+'"',r'\1renpy.gl2.'+name+'"',ccode,count=1,flags=re.DOTALL)
    ccode=re.sub(r'^__Pyx_PyMODINIT_FUNC init', '__Pyx_PyMODINIT_FUNC initrenpy_gl2_', ccode, flags=re.MULTILINE)
    ccode=re.sub(r'^__Pyx_PyMODINIT_FUNC PyInit_', '__Pyx_PyMODINIT_FUNC PyInit_renpy_gl2_', ccode, flags=re.MULTILINE)
    path.write_text(ccode)


def texture_source(folder, source, env):
    original=source/'renpy/gl2/gl2texture.pyx'
    text=original.read_text();marker='        cw, ch = draw.draw_to_virt.transform(tw, th)'
    assert text.count(marker)==1
    text=text.replace(marker,'        if not properties.get("rr_live2d_preserve_extent", False):\n    '+marker,1)
    text+='\n# Scoped public property/API for the new Live2D renderer only.\nrr_live2d_texture_extent_api = 1\n'
    pyx=folder/'source/renpy/gl2/gl2texture.pyx';pyx.write_text(text)
    generated=folder/'renpy.gl2.gl2texture.c'
    run(['/usr/bin/python3','-c','from Cython.Compiler.Main import main; main(command_line=True)','--embed-positions','-I',folder/'source','-I',source/'module/include','-o',generated,pyx],env=env)
    static_names(generated,'gl2texture')
    api=CACHE/'7.4.11/pygame-api';headers=folder/'texture-include/pygame_sdl2';headers.mkdir(parents=True,exist_ok=True)
    pygame=CACHE/'7.4.11/pygame-source'
    shutil.copy2(pygame/'src/pygame_sdl2/pygame_sdl2.h',headers/'pygame_sdl2.h')
    for p in api.glob('*_api.h'):shutil.copy2(p,headers/p.name)
    patch=''.join(difflib.unified_diff(original.read_text().splitlines(keepends=True),text.splitlines(keepends=True),fromfile='a/renpy/gl2/gl2texture.pyx',tofile='b/renpy/gl2/gl2texture.pyx'))
    record={'apiVersion':1,'property':'rr_live2d_preserve_extent','scope':'Only explicitly marked new Live2D renderer RTT nodes preserve logical extent; ordinary and legacy paths keep original behavior','upstreamFix':'https://github.com/renpy/renpy/blob/7.5.3.22090809/renpy/gl2/gl2texture.pyx','originalSourceSHA256':sha(original),'unchangedPXDSHA256':sha(source/'renpy/gl2/gl2texture.pxd'),'patchedSourceSHA256':sha(pyx),'generatedCSHA256':sha(generated),'patchSHA256':hashlib.sha256(patch.encode()).hexdigest(),'pygameSource':json.loads((CACHE/'7.4.11/pygame-source.json').read_text()),'publicCAPIHeaderSHA256':{p.name:sha(p) for p in headers.glob('*.h')}}
    (folder/'Texture-extent-backport.patch').write_text(patch)
    return generated,record

def build(version, output, texture_extent=False):
    pyversion,cython=PROFILES[version];inputs=json.loads((CACHE/version/'inputs.json').read_text())
    folder=output/version;folder.mkdir(parents=True,exist_ok=True)
    source=Path(inputs['source']);patched=folder/'source'
    if not patched.exists():shutil.copytree(source,patched)
    original=source/'renpy/gl2/gl2mesh.pyx';pyx=patched/'renpy/gl2/gl2mesh.pyx'
    patch_sha=backport(original,pyx)
    generated=folder/'renpy.gl2.gl2mesh.c'
    env=dict(os.environ,PYTHONPATH=str(CACHE/('Cython-'+cython)))
    run(['/usr/bin/python3','-c','from Cython.Compiler.Main import main; main(command_line=True)','--embed-positions','-I',patched,'-o',generated,pyx],env=env)
    # The complete-name fix follows this exact profile's module/setuplib.py.
    static_names(generated,'gl2mesh')
    texture,texture_record=texture_source(folder,source,env) if version=='7.4.11' and texture_extent else (None,None)
    python=CACHE/('Python-'+pyversion)
    if not (python/'pyconfig.h').exists():raise ValueError('Configure exact Python headers first')
    sdk=Path(inputs['sdk']);frameworks=[];slices=[]
    for platform,mode in build_runtime.PLATFORMS:
        work=folder/platform;work.mkdir(exist_ok=True)
        prebuilt=sdk/'renios/prototype/prebuilt'/mode
        archive=work/'librenpy.a'
        run(['xcrun','lipo',prebuilt/'librenpy.a','-thin','arm64','-output',archive])
        obj=work/'renpy.gl2.gl2mesh.o'
        sysroot=subprocess.check_output(['xcrun','--sdk',platform,'--show-sdk-path'],text=True).strip()
        deployment='-mios-simulator-version-min=17.0' if platform=='iphonesimulator' else '-miphoneos-version-min=17.0'
        run(['xcrun','--sdk',platform,'clang','-arch','arm64','-isysroot',sysroot,deployment,'-O2','-fPIC','-fvisibility=hidden','-Wno-deprecated-declarations','-I',python,'-I',python/'Include','-I',source,'-c',generated,'-o',obj])
        run(['xcrun','ar','-r',archive,obj]);run(['xcrun','ranlib',archive])
        if texture is not None:
            texture_object=work/'renpy.gl2.gl2texture.o'
            run(['xcrun','--sdk',platform,'clang','-arch','arm64','-isysroot',sysroot,deployment,'-O2','-fPIC','-fvisibility=hidden','-Wno-deprecated-declarations','-I',python,'-I',python/'Include','-I',source,'-I',source/'module','-I',folder/'texture-include','-I',KIT/'.cache/sdl-gate/SDL-release-2.0.20/include','-c',texture,'-o',texture_object])
            run(['xcrun','ar','-r',archive,texture_object]);run(['xcrun','ranlib',archive])

        name='RRRuntime'+version.replace('.','');framework=work/(name+'.framework');framework.mkdir(exist_ok=True)
        platform_framework=output/'Artifacts/RRPlatform.xcframework'/('ios-arm64-simulator' if platform=='iphonesimulator' else 'ios-arm64')
        dependencies=[lib for lib in build_runtime.libraries(sdk,pyversion.rsplit('.',1)[0]) if lib not in ('-lrenpython','-lSDL2','-lSDL2_image')]
        args=build_runtime.clang_args(platform,name)+['-Wl,-exported_symbol,_RR'+version.replace('.','')+'Run','-DRR_RUNTIME_RUN=RR'+version.replace('.','')+'Run','-DRR_PYTHON_MAJOR='+pyversion[0],'-DRR_PYTHON_VERSION="'+pyversion.rsplit('.',1)[0]+'"','-L',work,'-L',prebuilt,'-F',platform_framework,KIT/'Native/RRRuntime.m',*dependencies,'-framework','RRPlatform']
        for system in build_runtime.SYSTEM_FRAMEWORKS:args+=['-framework',system]
        run(args+['-o',framework/name]);build_runtime.finish_framework(framework,name,version,platform)
        frameworks.append(framework);slices.append({'platform':platform,'objectSHA256':sha(obj),'binarySHA256':sha(framework/name)})
    record={'runtimeID':version,'scope':'isolated candidate; exact original .pxd layout preserved','inputs':inputs,'cythonVersionUsed':cython,'pythonHeadersVersion':pyversion,'unicodeWidth':2 if pyversion.startswith('2') else None,'originalPYXSHA256':sha(original),'patchedPYXSHA256':sha(pyx),'unchangedPXDSHA256':sha(source/'renpy/gl2/gl2mesh.pxd'),'backportedMethodsSHA256':patch_sha,'generatedCSHA256':sha(generated),'slices':slices}
    record['hostSourceSHA256']={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),KIT/'Native/RRRuntime.m',ROOT/'Scripts/runtime/privacy_manifests.py']}
    record['compilerSource']=json.loads((CACHE/('cython-'+cython+'-source.json')).read_text())
    record['pythonSource']=json.loads((python/'source-record.json').read_text())
    if texture_record is not None:record['textureExtentPatch']=texture_record
    record['pythonHeaderConfigSHA256']=sha(python/'pyconfig.h')
    record['pythonIncludeSHA256']={str(p.relative_to(python/'Include')):sha(p) for p in sorted((python/'Include').rglob('*.h'))}
    patch=''.join(difflib.unified_diff(original.read_text().splitlines(keepends=True),pyx.read_text().splitlines(keepends=True),fromfile='a/renpy/gl2/gl2mesh.pyx',tofile='b/renpy/gl2/gl2mesh.pyx'))
    record['backportPatchSHA256']=hashlib.sha256(patch.encode()).hexdigest()
    license_path=KIT/('Artifacts/RenPy'+version.replace('.','')+'.bundle/LICENSE.txt')
    record['officialSDKLicenseSHA256']=sha(license_path)
    for framework in frameworks:
        shutil.copy2(license_path,framework/'RenPy-LICENSE.txt')
        (framework/'Mesh-API-backport.patch').write_text(patch)
        if texture_record is not None:shutil.copy2(folder/'Texture-extent-backport.patch',framework/'Texture-extent-backport.patch')
        (framework/'mesh-backport-provenance.json').write_text(json.dumps(record,indent=2)+'\n')
    artifact=output/'Artifacts'/('RRRuntime'+version.replace('.','')+'.xcframework')
    if artifact.exists():shutil.rmtree(artifact)
    run(['xcodebuild','-create-xcframework',*[part for f in frameworks for part in ('-framework',f)],'-output',artifact])
    (folder/'result.json').write_text(json.dumps(record,indent=2)+'\n');print('Built candidate exact Mesh API:',version,flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--version',action='append',choices=PROFILES);parser.add_argument('--texture-extent',action='store_true');parser.add_argument('--output',type=Path,default=KIT/'Validation/RendererProductionCandidate/LegacyBuild');args=parser.parse_args()
    # Link against a clone of the existing shared platform; no shared platform
    # or production framework is modified by this extension-only build.
    target=args.output/'Artifacts/RRPlatform.xcframework'
    if not target.exists():shutil.copytree(KIT/'Artifacts/RRPlatform.xcframework',target)
    for version in args.version or PROFILES:build(version,args.output,args.texture_extent)
