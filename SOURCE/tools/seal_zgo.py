#!/usr/bin/env python3
"""Seal a LOCAL private original; never put the original/unlock in the public tree."""
import argparse,hashlib,hmac,json,os,subprocess,sys
from pathlib import Path
from build import ROOT,integrate,packed,sha
ap=argparse.ArgumentParser();ap.add_argument('--manager',type=Path,required=True);ap.add_argument('--unlock-file',type=Path,required=True);ap.add_argument('--legacy-yaml-file',type=Path,required=True);a=ap.parse_args()
for p in (a.manager,a.unlock_file,a.legacy_yaml_file):
 if p.resolve().is_relative_to(ROOT):raise SystemExit('Private input must be outside the public tree')
secret=a.unlock_file.read_bytes().splitlines()[0]
if len(secret)<32:raise SystemExit('Distribution unlock must contain at least 32 random characters')
legacy=a.legacy_yaml_file.read_bytes()
import yaml
nodes=yaml.safe_load(legacy).get('proxies',[])
if len(nodes)!=6 or sorted(n.get('type') for n in nodes)!=['anytls','hysteria2','tuic','tuic','vless','vmess']:raise SystemExit('Expected the six-node original owner document')
manager=integrate(a.manager.read_text(),'zgocloud',legacy_yaml=legacy);salt=os.urandom(32)
# Supply passphrase by descriptor; stdin carries compressed plaintext.
r,w=os.pipe();os.write(w,secret+b'\n');os.close(w)
try:p=subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','400000','-md','sha256','-pass',f'fd:{r}'],pass_fds=(r,),input=packed(manager),capture_output=True,check=True)
finally:os.close(r)
header=b'SBOXETM1'+salt;key=hashlib.pbkdf2_hmac('sha256',secret,salt,400000,32);data=header+hmac.new(key,header+p.stdout,'sha256').digest()+p.stdout
(ROOT/'assets/zgocloud.enc').write_bytes(data);(ROOT/'assets/zgocloud.json').write_text(json.dumps({'format':'SBOXETM1: AES-256-CBC/PBKDF2-SHA256 + encrypt-then-HMAC-SHA256, independent salt, 400000 iterations each','manager_sha256':sha(manager)},sort_keys=True,indent=2)+'\n')
print('Sealed private manager; no private inputs copied to the public tree.')
