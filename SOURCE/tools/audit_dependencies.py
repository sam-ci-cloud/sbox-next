#!/usr/bin/env python3
"""Official npm/OSV advisory APIs, exact pinned versions, no dependency execution.
SCA is not exploitability proof. Complement this with govulncheck -mode=binary.
"""
from pathlib import Path
import argparse,datetime,json,re,urllib.request
ROOT=Path(__file__).resolve().parents[1]
def post(url,value):
 request=urllib.request.Request(url,data=json.dumps(value).encode(),headers={'Content-Type':'application/json','User-Agent':'SINGBOX-dependency-audit'})
 with urllib.request.urlopen(request,timeout=60) as response:return json.load(response)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 bulk={}
 for path,value in json.loads((ROOT/'package-lock.json').read_text())['packages'].items():
  if path and 'version' in value:bulk.setdefault(value.get('name') or path.split('node_modules/')[-1],[]).append(value['version'])
 npm=post('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',bulk);queries=[];inside=False
 for line in (ROOT/'core-source/sing-box/go.mod').read_text().splitlines():
  if line.startswith('require ('):inside=True;continue
  if inside and line==')':inside=False;continue
  match=re.match(r'\s*(\S+)\s+(v\S+)',line if inside else line.removeprefix('require '))
  if match:queries.append({'package':{'ecosystem':'Go','name':match[1]},'version':match[2]})
 go=post('https://api.osv.dev/v1/querybatch',{'queries':queries});assert len(go['results'])==len(queries)
 findings=[{'query':q,'vulns':r['vulns']} for q,r in zip(queries,go['results']) if r.get('vulns')]
 report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'npm_packages':len(bulk),'npm_advisories':npm,'go_modules':len(queries),'go_findings':findings,'scope':'Pinned npm lock and declared Go modules; separate binary reachability scan required'};args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'npm_advisory_packages':len(npm),'go_advisory_modules':len(findings),'report':str(args.output)}));return bool(npm or findings)
if __name__=='__main__':raise SystemExit(main())
