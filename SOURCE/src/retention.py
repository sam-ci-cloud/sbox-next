#!/usr/bin/env python3
"""Explicit, fail-closed retention for native backups and client-policy snapshots."""
import argparse,hashlib,json,os,shutil,stat,tarfile
from pathlib import Path,PurePosixPath

def valid_backup(path):
 try:
  with tarfile.open(path) as tf:
   members=tf.getmembers()
   if len(members)>5000 or sum(m.size for m in members)>600*1024**2:return False
   files={}
   for m in members:
    p=PurePosixPath(m.name)
    if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='payload' or not(m.isfile() or m.isdir()):return False
    if m.isfile():
     key=str(p.relative_to('payload'))
     if key in files:return False
     files[key]=m
   if not {'state.json','sing-box','SHA256SUMS'}<=set(files):return False
   listed={}
   for line in tf.extractfile(files['SHA256SUMS']).read().decode().splitlines():
    digest,name=line.split('  ',1);name=name.removeprefix('./')
    if name in listed or name not in files or len(digest)!=64:return False
    stream=tf.extractfile(files[name]);actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual!=digest:return False
    listed[name]=digest
   return set(listed)==set(files)-{'SHA256SUMS','backup-auth.json'}
 except (OSError,ValueError,tarfile.TarError,KeyError,UnicodeError):return False

def valid_policy(path):
 try:
  expected=json.loads((path/'hashes.json').read_text());observed={}
  for p in path.rglob('*'):
   if p.is_symlink() or not(p.is_file() or p.is_dir()):return False
   if p.is_file() and p.name!='hashes.json':observed[str(p.relative_to(path))]=hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
  return bool(expected) and expected==observed
 except (OSError,ValueError):return False

def retain(backup_root,base,keep_backups=10,keep_policies=20,prune=False):
 root,base=Path(backup_root),Path(base)
 if not all(type(n) is int and 1<=n<=1000 for n in (keep_backups,keep_policies)):raise ValueError('Retention counts must be1–1000; at least one validated item is always kept')
 if root.is_symlink() or not root.is_dir():raise ValueError('Backup root must be a regular directory')
 protected=set();pointers=[root/'PRE-UPGRADE-BACKUP',root/'.policy-journal.json',Path('/var/lib/sbox-manager/transaction.json')]
 # features.pending itself never matches policy-* or sbox-*.tar.gz and is never pruned.
 def walk(x):
  if isinstance(x,dict):
   for v in x.values():walk(v)
  elif isinstance(x,list):
   for v in x:walk(v)
  elif isinstance(x,str) and x.startswith('/'):
   p=Path(x)
   if p.is_relative_to(root):protected.add(p)
 for p in pointers:
  if not p.exists() and not p.is_symlink():continue
  if p.is_symlink() or not p.is_file():raise ValueError('Unsafe active recovery pointer; no pruning')
  try:walk(json.loads(p.read_text()) if p.suffix=='.json' else p.read_text().strip())
  except (OSError,ValueError) as exc:raise ValueError('Unreadable active recovery pointer; no pruning') from exc
 report={'mode':'prune' if prune else 'dry-run','keep_backups':keep_backups,'keep_policies':keep_policies,'protected':[],'would_remove':[],'removed':[]}
 candidates=list(root.iterdir())
 if len(candidates)>2000:raise ValueError('Too many backup objects; inspect manually before pruning')
 selected=[]
 for kind,keep,check in [('backup',keep_backups,valid_backup),('policy',keep_policies,valid_policy)]:
  group=[p for p in candidates if (p.name.startswith('sbox-') and p.name.endswith('.tar.gz'))] if kind=='backup' else [p for p in candidates if p.name.startswith('policy-')]
  valid=[]
  for p in group:
   if p.is_symlink() or not check(p):report['protected'].append({'path':str(p),'reason':'unvalidated/unsupported; preserve evidence'});continue
   valid.append(p)
  valid.sort(key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True)
  for i,p in enumerate(valid):
   if i<keep or any(q==p or p in q.parents for q in protected):report['protected'].append({'path':str(p),'reason':'retained newest validated or active recovery pointer'})
   else:selected.append((p,p.stat().st_ino,p.stat().st_mtime_ns))
 for p,inode,mtime in selected:
  report['would_remove'].append(str(p))
  if prune:
   info=p.lstat()
   if stat.S_ISLNK(info.st_mode) or info.st_ino!=inode or info.st_mtime_ns!=mtime:raise ValueError('Backup changed since inventory; remaining pruning stopped')
   if p.is_dir():shutil.rmtree(p)
   else:p.unlink()
   report['removed'].append(str(p))
 return report

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',default='/var/backups/sbox-manager');ap.add_argument('--base',default='/etc/sbox-manager');ap.add_argument('--keep-backups',type=int);ap.add_argument('--keep-policies',type=int);ap.add_argument('--prune',action='store_true');a=ap.parse_args()
 config=Path(a.base)/'retention.json';cfg=json.loads(config.read_text()) if config.exists() else {}
 try:print(json.dumps(retain(a.root,a.base,a.keep_backups if a.keep_backups is not None else cfg.get('keep_backups',10),a.keep_policies if a.keep_policies is not None else cfg.get('keep_policies',20),a.prune),indent=2))
 except (ValueError,OSError) as exc:ap.exit(1,str(exc)+'\n')
if __name__=='__main__':main()
