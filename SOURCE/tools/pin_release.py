#!/usr/bin/env python3
"""Synchronize and verify local delivery metadata; never publishes or fetches."""
from pathlib import Path
import argparse, hashlib, json, sys

ROOT=Path(__file__).resolve().parents[1]

def sha(data):return hashlib.sha256(data).hexdigest()
def load(path):return json.loads(path.read_text())
def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def tree_identity(root=ROOT):
    raw=(root/'install.sh').read_bytes();return sha(raw),len(raw)
def sync_tree(root=ROOT):
    digest,size=tree_identity(root);release_path=root/'assets/release.json';release=load(release_path)
    release['components']=load(root/'BUILD.json');release['installer_sha256']=digest;release['installer_bytes']=size
    release.pop('repository',None);dump(release_path,release)
    (root/'install.sh.sha256').write_text(digest+'  install.sh\n')
    path=root/'assets/distribution.json';data=load(path)
    data.update(schema=1,version=release['version'],installer_sha256=digest,installer_bytes=size)
    data.pop('repository',None);data.pop('source_commit',None);dump(path,data)
    print('local delivery metadata synchronized',digest,size)
    return digest,size
def check(root=ROOT):
    try:
        from check_docs import distribution
        distribution(root)
    except (AssertionError,KeyError,ValueError,OSError) as error:return [str(error)]
    return []
def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--sync-tree',action='store_true');ap.add_argument('--check',action='store_true');ap.add_argument('--root',default=str(ROOT))
    args,unknown=ap.parse_known_args(argv)
    if any(x=='--commit' or x.startswith('--commit=') or x=='--channel' or x.startswith('--channel=') for x in unknown):
        ap.error('GitHub commit/channel pinning is disabled; only local delivery metadata is supported')
    if unknown:ap.error('unrecognized arguments: '+' '.join(unknown))
    root=Path(args.root).resolve()
    if args.sync_tree:sync_tree(root)
    if args.check or not args.sync_tree:
        problems=check(root)
        if problems:print('\n'.join(problems),file=sys.stderr);return 1
        print('PASS local delivery installer identity; no repository or remote is required')
    return 0
if __name__=='__main__':sys.exit(main())
