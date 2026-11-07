#!/usr/bin/env python3
"""Complete checksums for editable public source; generated installer is shipped separately."""
import argparse,hashlib,sys
from pathlib import Path
from public_files import tracked_files
ROOT=Path(__file__).resolve().parents[1]
EXCLUDE={'SHA256SUMS','install.sh','core-source/sing-box-accounting'}
def expected(root):
 return ''.join(hashlib.file_digest(p.open('rb'),'sha256').hexdigest()+'  '+p.relative_to(root).as_posix()+'\n' for p in sorted(tracked_files(root),key=lambda p:p.relative_to(root).as_posix()) if p.relative_to(root).as_posix() not in EXCLUDE)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');ap.add_argument('--root',type=Path,default=ROOT);a=ap.parse_args();text=expected(a.root.resolve());p=a.root/'SHA256SUMS'
 if a.write:p.write_text(text)
 if p.read_text()!=text:raise SystemExit('Source manifest is incomplete/stale; run python3 tools/source_manifest.py --write after source/build metadata is frozen')
 print('PASS complete editable public source manifest:',len(text.splitlines()),'files')
if __name__=='__main__':main()
