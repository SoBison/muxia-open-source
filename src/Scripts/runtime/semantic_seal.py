#!/usr/bin/env python3
"""Verify a device product against a reviewed, signature-envelope-independent seal.

Only the main CodeDirectory resource slot and the CMS signature envelopes may
vary. All signed resources, code directories, signers and architectures remain
bound. This is not certificate-chain validation or device-runtime evidence.
"""
import hashlib,json,os,pathlib,plistlib,re,stat,struct,subprocess,tempfile

FRAMEWORKS=('MetalANGLE','RRLive2DCore','RRPlatform','RRRuntime7411','RRRuntime753','RRRuntime763','RRRuntime773','RRRuntime787','RRRuntime803','RRRuntime813','RRRuntime823','RRRuntime837','RRRuntime841','RRRuntime853')
NESTED={**{name:'Frameworks/'+name+'.framework/'+name for name in FRAMEWORKS},'Widget':'PlugIns/RenReaderWidgets.appex/RenReaderWidgets'}
MAIN='RenReader';SEAL='_CodeSignature/CodeResources'

def sha(data):return hashlib.sha256(data).hexdigest()
def filehash(path,algorithm='sha256'):
 d=hashlib.new(algorithm)
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):d.update(b)
 return d.digest()
def require(ok,message):
 if not ok:raise ValueError(message)

def slices(data):
 require(len(data)>=8,'Truncated Mach-O')
 magic=struct.unpack_from('>I',data,0)[0]
 if magic not in (0xcafebabe,0xcafebabf):return {'native':data}
 count=struct.unpack_from('>I',data,4)[0];width=32 if magic==0xcafebabf else 20
 require(0<count<=16 and 8+count*width<=len(data),'Invalid fat architecture table')
 result={};intervals=[]
 for i in range(count):
  start=8+i*width
  if width==20:cpu,sub,offset,size,align=struct.unpack_from('>5I',data,start)
  else:cpu,sub,offset,size,align,_=struct.unpack_from('>IIQQII',data,start)
  require(size>0 and offset>=8+count*width and offset+size<=len(data) and align<=30 and offset%(1<<align)==0,'Invalid fat slice bounds')
  key=hex(cpu)+':'+hex(sub);require(key not in result,'Duplicate fat architecture');result[key]=data[offset:offset+size];intervals.append((offset,offset+size))
 require(all(a[1]<=b[0] for a,b in zip(sorted(intervals),sorted(intervals)[1:])), 'Overlapping fat slices')
 return result

def container_layout(data):
 magic=struct.unpack_from('>I',data,0)[0]
 if magic not in (0xcafebabe,0xcafebabf):return {'kind':'thin'}
 # Reuse strict slice-table validation before recording every non-slice byte.
 slices(data);count=struct.unpack_from('>I',data,4)[0];width=32 if magic==0xcafebabf else 20;end=8+count*width;intervals=[]
 for i in range(count):
  start=8+i*width
  if width==20:_,_,offset,size,_=struct.unpack_from('>5I',data,start)
  else:_,_,offset,size,_,_=struct.unpack_from('>IIQQII',data,start)
  intervals.append((offset,offset+size))
 intervals.sort();cursor=end;gaps=[]
 for begin,finish in intervals:
  gaps.append({'length':begin-cursor,'sha256':sha(data[cursor:begin])});cursor=finish
 gaps.append({'length':len(data)-cursor,'sha256':sha(data[cursor:])})
 return {'kind':'fat','headerSHA256':sha(data[:end]),'gaps':gaps}

def signature_info(raw,resource=None):
 require(len(raw)>=32,'Truncated Mach-O header');magic=struct.unpack_from('<I',raw)[0];header=32 if magic==0xfeedfacf else 28 if magic==0xfeedface else None
 require(header is not None,'Unsupported Mach-O magic');ncmds=struct.unpack_from('<I',raw,16)[0];command_bytes=struct.unpack_from('<I',raw,20)[0];require(ncmds<=65536 and header+command_bytes<=len(raw),'Invalid load-command table')
 pos=header;sig=None
 for _ in range(ncmds):
  require(pos+8<=header+command_bytes,'Truncated load command');command,size=struct.unpack_from('<II',raw,pos);require(size>=8 and pos+size<=header+command_bytes,'Invalid load command')
  if command==0x1d:
   require(sig is None and size==16,'Duplicate or malformed code signature command');sig=struct.unpack_from('<II',raw,pos+8)
  pos+=size
 require(pos==header+command_bytes and sig is not None,'Missing code signature command');start,length=sig;require(start+length<=len(raw) and length>=12,'Invalid signature bounds')
 block=raw[start:start+length];magic,total,count=struct.unpack_from('>III',block);require(magic==0xfade0cc0 and 12+8*count<=total<=len(block) and count<=64,'Invalid signature superblob')
 indices={};intervals=[]
 for i in range(count):
  slot,offset=struct.unpack_from('>II',block,12+i*8);require(slot not in indices and offset>=12+8*count and offset+8<=total,'Duplicate or invalid signature slot');kind,size=struct.unpack_from('>II',block,offset);require(size>=8 and offset+size<=total,'Invalid signature slot length');indices[slot]=(kind,block[offset:offset+size],offset);intervals.append((offset,offset+size))
 require(all(a[1]<=b[0] for a,b in zip(sorted(intervals),sorted(intervals)[1:])), 'Overlapping signature slots')
 require(0 in indices and 0x10000 in indices and indices[0x10000][0]==0xfade0b01,'Missing CodeDirectory or CMS')
 directories={};other={};envelope=bytearray(block)
 for slot,(kind,data,slot_offset) in indices.items():
  if kind==0xfade0c02:
   require(slot==0 or 0x1000<=slot<0x1006,'Unexpected CodeDirectory slot');require(len(data)>=44,'Truncated CodeDirectory')
   _,size,version,flags,hashoff,identoff,special,count,limit,hsize,htype,platform,power,spare=struct.unpack_from('>9I4BI',data)
   require(size==len(data) and special<=64 and count<=100000 and power<=20 and limit==start and hashoff>=special*hsize and hashoff+count*hsize<=len(data),'Invalid CodeDirectory bounds')
   require((htype,hsize) in ((1,20),(2,32)),'Unsupported CodeDirectory hash')
   require(identoff<len(data) and b'\0' in data[identoff:hashoff-special*hsize],'Invalid CodeDirectory identifier')
   page=1<<power;expected_count=(limit+page-1)//page;require(expected_count==count,'CodeDirectory page count mismatch')
   algorithm='sha1' if htype==1 else 'sha256'
   for i in range(count):
    expected=hashlib.new(algorithm,raw[i*page:min((i+1)*page,limit)]).digest()
    require(data[hashoff+i*hsize:hashoff+(i+1)*hsize]==expected,'CodeDirectory page hash mismatch')
   normalized=bytearray(data)
   if resource is not None:
    require(special>=3 and htype==2 and hsize==32,'Unsupported main resource seal')
    value=data[hashoff-3*hsize:hashoff-2*hsize];require(value==hashlib.sha256(resource).digest(),'Main resource slot mismatch');normalized[hashoff-3*hsize:hashoff-2*hsize]=bytes(hsize);envelope[slot_offset+hashoff-3*hsize:slot_offset+hashoff-2*hsize]=bytes(hsize)
   directories[str(slot)]=sha(normalized)
  elif slot==0x10000:envelope[slot_offset+8:slot_offset+len(data)]=bytes(len(data)-8)
  else:other[str(slot)]={'magic':kind,'sha256':sha(data)}
 require('0' in directories,'Missing primary CodeDirectory')
 return {'directories':directories,'otherSlots':other,'slotTypes':sorted(indices),'normalizedEnvelopeSHA256':sha(envelope),'trailingBytesSHA256':sha(raw[start+length:]),'trailingBytesLength':len(raw)-start-length}

def component_signature(bundle,arch):
 cmd=['codesign','-d','--verbose=4']+([] if arch=='native' else ['--arch',arch])+[str(bundle)];detail=subprocess.check_output(cmd,stderr=subprocess.STDOUT,text=True);team=re.search(r'^TeamIdentifier=(\S+)$',detail,re.M);identifier=re.search(r'^Identifier=(\S+)$',detail,re.M);require(team is not None and identifier is not None,'Missing nested signer identity')
 with tempfile.TemporaryDirectory() as temp:
  prefix=str(pathlib.Path(temp)/'cert');subprocess.run(['codesign','-d']+([] if arch=='native' else ['--arch',arch])+['--extract-certificates='+prefix,str(bundle)],capture_output=True,check=True);leaf=pathlib.Path(prefix+'0').read_bytes()
 return {'team':team.group(1),'identifier':identifier.group(1),'certificateSHA256':sha(leaf),'certificateFingerprint':hashlib.sha1(leaf).hexdigest().upper()}

def arch_name(key):
 if key=='native':return 'native'
 cpu=int(key.split(':')[0],16)
 if cpu==0xc:return 'armv7'
 if cpu==0x100000c:return 'arm64'
 raise ValueError('Unsupported fat CPU')

def inventory(app):
 result={}
 for p in [app,*sorted(app.rglob('*'))]:
  k='.' if p==app else p.relative_to(app).as_posix();s=p.lstat();m=stat.S_IMODE(s.st_mode)
  if p.is_symlink():result[k]=['link',m,os.readlink(p)]
  elif p.is_dir():result[k]=['dir',m]
  elif p.is_file():result[k]=['file',m,s.st_size,filehash(p).hex()]
  else:raise ValueError('Unexpected special product file')
 return result

def normalized_resources(data,app):
 value=plistlib.loads(data);paths=set(NESTED.values());normalized=data
 for key,algorithm in [('files','sha1'),('files2','sha256')]:
  table=value[key];require(isinstance(table,dict),'Invalid resource seal table')
  for name in paths:
   require(name in table,'Missing nested resource seal entry')
   item=table[name];actual=filehash(app/name,algorithm)
   if key=='files':require(isinstance(item,bytes) and item==actual,'Nested SHA-1 resource seal mismatch');table[name]=bytes(len(item));middle=rb'\s*<data>'
   else:require(isinstance(item,dict) and set(item)=={'hash2'} and item['hash2']==actual,'Nested SHA-256 resource seal mismatch');table[name]={'hash2':bytes(len(item['hash2']))};middle=rb'\s*<dict>\s*<key>hash2</key>\s*<data>'
   pattern=rb'(<key>'+re.escape(name.encode())+rb'</key>'+middle+rb')([A-Za-z0-9+/=\s]+)(</data>)'
   def mask(match):return match.group(1)+re.sub(rb'[A-Za-z0-9+/=]',b'X',match.group(2))+match.group(3)
   normalized,count=re.subn(pattern,mask,normalized);require(count==1,'Ambiguous resource seal encoding: '+name)
 return {'canonicalSHA256':sha(plistlib.dumps(value,fmt=plistlib.FMT_BINARY,sort_keys=True)),'rawNormalizedSHA256':sha(normalized)}

def collect_baseline(app):
 subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True,capture_output=True);resource=(app/SEAL).read_bytes();items={};containers={}
 for name,relative in {MAIN:MAIN,**NESTED}.items():
  binary=app/relative;bundle=app if name==MAIN else app/'PlugIns/RenReaderWidgets.appex' if name=='Widget' else app/'Frameworks'/(name+'.framework');arches={};raw_file=binary.read_bytes();containers[name]=container_layout(raw_file)
  for arch,raw in slices(raw_file).items():
   parsed=signature_info(raw,resource if name==MAIN else None);parsed['signer']=component_signature(bundle,arch_name(arch));arches[arch]=parsed
  items[name]=arches
 return {'schemaVersion':1,'scope':'device-static-build-signing-only','physicalDeviceExecution':False,'nestedPaths':NESTED,'main':items.pop(MAIN),'nested':items,'containers':containers,'normalizedResources':normalized_resources(resource,app),'codeResourcesSHA256':sha(resource)}

def verify_semantic_seal(root,app,binding,pre,static,*,image_identity,checked_reference):
 seal=binding['semanticSeal'];baseline_path=checked_reference(root,seal['baseline']);resources_path=checked_reference(root,seal['codeResources']);baseline=json.loads(baseline_path.read_bytes());original=resources_path.read_bytes()
 require(baseline.get('schemaVersion')==1 and baseline.get('scope')=='device-static-build-signing-only' and baseline.get('physicalDeviceExecution') is False,'Semantic seal scope mismatch')
 require(baseline['nestedPaths']==NESTED and set(baseline['nested'])==set(NESTED),'Semantic nested code inventory mismatch')
 team=static['profiles'][0]['authorization']['signatureTeamIdentifier'];certificate=static['profiles'][0]['leafCertificateSHA256']
 for component in [baseline['main'],*baseline['nested'].values()]:
  for item in component.values():
   signer=item['signer'];require(signer['team']==team and signer['certificateSHA256']==certificate and signer['certificateFingerprint']==pre['certificateFingerprint'],'Semantic signer does not match authorized team and certificate')
 expected_inv=json.loads(checked_reference(root,binding['signedInventory']).read_bytes());actual_inv=inventory(app);require(set(expected_inv)==set(actual_inv),'Signed product path inventory differs')
 allowed=set(NESTED.values())|{MAIN,SEAL}
 for path,expected in expected_inv.items():
  observed=actual_inv[path]
  if path in allowed:require(expected[0]=='file' and observed[0]=='file' and expected[1]==observed[1],'Signed product code/seal mode differs: '+path)
  else:require(expected==observed,'Signed product resource differs: '+path)
 require(sha(original)==baseline['codeResourcesSHA256'] and expected_inv[SEAL][3]==sha(original),'Baseline CodeResources mismatch')
 current=(app/SEAL).read_bytes();require(normalized_resources(current,app)==baseline['normalizedResources'],'Signed product CodeResources differs')
 subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True,capture_output=True)
 for name,relative in {MAIN:MAIN,**NESTED}.items():
  path=app/relative;bundle=app if name==MAIN else app/'PlugIns/RenReaderWidgets.appex' if name=='Widget' else app/'Frameworks'/(name+'.framework')
  subprocess.run(['codesign','--verify','--strict','--all-architectures',str(bundle)],check=True,capture_output=True)
  observed={};raw_file=path.read_bytes();require(container_layout(raw_file)==baseline['containers'][name],'Signed product fat container differs: '+name)
  for arch,raw in slices(raw_file).items():
   parsed=signature_info(raw,current if name==MAIN else None);parsed['signer']=component_signature(bundle,arch_name(arch));observed[arch]=parsed
  expected=baseline['main'] if name==MAIN else baseline['nested'][name]
  require(observed==expected,'Signed product CodeDirectory or signer differs: '+name)
  if name!=MAIN:require(image_identity(root,path)==pre['imageIdentities'][relative],'Signed nested image identity differs: '+name)
