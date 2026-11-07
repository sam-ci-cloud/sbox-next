#!/usr/bin/env python3
"""Private-reference leak gate. Reports paths/counts only, never matched values."""
from pathlib import Path
import argparse,base64,gzip,io,json,re,sys,subprocess,tarfile,urllib.parse
ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);ap.add_argument('--reference-yaml',type=Path,required=True);ap.add_argument('--reference-state',type=Path,action='append',default=[]);ap.add_argument('--private-manager',type=Path,required=True);ap.add_argument('--secret-file',type=Path,action='append',default=[]);ap.add_argument('--git-history',type=Path,help='Also scan every reachable Git blob in this local clone');a=ap.parse_args()
import yaml
values=set()
def visit(x,key=''):
 if isinstance(x,dict):
  for k,v in x.items():visit(v,k)
 elif isinstance(x,list):
  for v in x:visit(v,key)
 elif isinstance(x,str):
  if key.lower().replace('-','_') in ('server','sni','servername','path') and len(x)>=8 and not (key.lower() in ('sni','servername') and x in ('www.apple.com','www.microsoft.com','www.cloudflare.com')):values.add(x.encode())
  if re.search(r'(?:^|_)(?:password|token|secret|key|cookie|csrf|hash)$',key.lower().replace('-','_')) or key.lower().replace('-','_') in ('uuid','password','private_key','public_key','short_id','password_hash','secret','cookie','csrf','token','access_token','api_key','session','session_id','totp_secret','recovery_codes','recovery','codes','bootstrap_password','stats_token','hash','totp','pending_totp','token_hash','auth_key','stats_auth_key','recovery_hashes') and len(x)>=8:values.add(x.encode())
  # Subscription records often contain complete URLs rather than a token key.
  for token in re.findall(r'/sub/((?:v1\.)?[A-Za-z0-9_\-]{43})',x):values.add(urllib.parse.unquote(token).encode())
visit(yaml.safe_load(a.reference_yaml.read_text()))
for ref in a.reference_state:visit(json.loads(ref.read_text()))
for v in re.findall(r'''["'](?:private_key|password|uuid|short_id)["']\s*:\s*["']([A-Za-z0-9_+./=\-]{12,})["']''',a.private_manager.read_text()):values.add(v.encode())
for p in a.secret_file:
 raw=p.read_bytes();values.add(raw);values.add(raw.strip())
values={v for v in values if len(v)>=8};bad=[];count=0
def check(data,name,label):
 blocks=[data]
 if Path(name).name in ('install.sh','sbox-installer.sh'):
  m=re.search(rb"<<'SBOX_GENERIC_PAYLOAD'\n(.*?)\nSBOX_GENERIC_PAYLOAD",data,re.S)
  if m:blocks.append(gzip.decompress(base64.b64decode(m[1])))
 # Shared runtime files are nested inside a second base64/gzip archive. Scan
 # their decoded bytes too, including when a source manager is checked alone.
 for block in list(blocks):
  match=re.search(rb"blob=base64\.b64decode\('([A-Za-z0-9+/=]{40,})'",block)
  if not match:continue
  packed=base64.b64decode(match[1],validate=True)
  require_size=16*1024*1024
  assert len(packed)<=require_size,'Oversized embedded application archive'
  total=0
  with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as archive:
   for member in archive:
    name=Path(member.name);total+=member.size
    assert member.isfile() and not name.is_absolute() and '..' not in name.parts and total<=require_size,'Unsafe embedded application archive'
    blocks.append(archive.extractfile(member).read())
 if any(v in b for v in values for b in blocks):bad.append(label)
for p in sorted(a.root.rglob('*')):
 if not p.is_file() or any(x in p.parts for x in ('.git','.cache','__pycache__','.build')):continue
 count+=1;check(p.read_bytes(),p.name,str(p.relative_to(a.root)))
history_count=0
if a.git_history:
 objects=subprocess.check_output(['git','-C',str(a.git_history),'rev-list','--objects','--all'],text=True).splitlines()
 batch=subprocess.Popen(['git','-C',str(a.git_history),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
 try:
  for obj in objects:
   oid,_,name=obj.partition(' ');batch.stdin.write((oid+'\n').encode());batch.stdin.flush()
   fields=batch.stdout.readline().split();assert len(fields)==3, 'Git object header missing'
   data=batch.stdout.read(int(fields[2]));assert batch.stdout.read(1)==b'\n', 'Git object truncated'
   if fields[1]==b'blob':history_count+=1;check(data,name,'git:'+oid+':'+name)
 finally:
  batch.stdin.close();batch.wait(timeout=10)
print(json.dumps({'files_scanned':count,'reachable_history_blobs_scanned':history_count,'private_values_checked':len(values),'leaking_paths':bad,'status':'FAIL' if bad else 'PASS'},indent=2))
sys.exit(bool(bad))
