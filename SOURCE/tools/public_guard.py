#!/usr/bin/env python3
"""Fail-closed publication guard. Optional private literal files stay outside Git.

Usage: python3 SOURCE/tools/public_guard.py [--secrets /private/literals.json]
       [--denylist /private/repository-identities.json] [--artifact PACKAGE]
Scans tracked bytes, all reachable Git blobs and commit metadata, nested archives
and recognized embedded payloads. Reports paths and classes only, never matches.
"""
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
from identity import canonical,foreign_reference
from verify_full_delivery import expand,text_of
ROOT=Path(__file__).resolve().parents[2]
FORBIDDEN={'PRIVATE','PROMPTS','BASELINE','EVIDENCE','OWNER_PRIVATE','WORKSPACE','.env','.ssh'}
def main():
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--root',type=Path,default=ROOT);a.add_argument('--secrets',type=Path);a.add_argument('--denylist',type=Path);a.add_argument('--artifact',type=Path,action='append',default=[]);x=a.parse_args();root=x.root.resolve();repo=canonical(root/'SOURCE')
 secrets=json.loads(x.secrets.read_text()) if x.secrets else [];denied=json.loads(x.denylist.read_text()) if x.denylist else []
 git=lambda *args:subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.DEVNULL)
 names=[n for n in git('ls-files','-z').decode().split('\0') if n];objects=[(n,(root/n).read_bytes()) for n in names]
 for n in names:
  if FORBIDDEN.intersection(Path(n).parts) or (root/n).is_symlink() or n.endswith(('.sboxetm','SOURCE_HISTORY.bundle')):raise ValueError('Private boundary violation: '+n)
 try:oids=git('rev-list','--objects','--all').decode().splitlines()
 except subprocess.CalledProcessError:oids=[]
 for row in oids:
  oid=row.split(' ',1)[0]
  if git('cat-file','-t',oid).strip()==b'blob':objects.append(('git:'+oid,git('cat-file','blob',oid)))
 if oids:objects.append(('git:metadata',git('log','--all','--format=%an%n%ae%n%cn%n%ce%n%B')))
 objects.extend((str(p),p.read_bytes()) for p in x.artifact);seen=set();count=0
 for label,data in objects:
  for inner,body in expand(label,data):
   sha=hashlib.sha256(body).digest()
   if sha in seen:continue
   seen.add(sha);count+=1
   if any(s and s.encode() in body for s in secrets):raise ValueError('Secret literal in '+label)
   if re.search(rb'gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{64,}-----END (?:OPENSSH |RSA |EC )?PRIVATE KEY-----',body):raise ValueError('Credential pattern in '+label)
   if any(d.encode().lower() in body.lower() for d in denied) or foreign_reference(text_of(body),repo):raise ValueError('Repository identity in '+label)
 print(json.dumps({'status':'PASS','repository':repo,'tracked_files':len(names),'unique_expanded_objects':count,'history_objects':len(oids),'private_literals_supplied':len(secrets),'private_denylist_supplied':len(denied)}))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,subprocess.CalledProcessError) as e:print(json.dumps({'status':'FAIL','reason':str(e)}));sys.exit(1)
