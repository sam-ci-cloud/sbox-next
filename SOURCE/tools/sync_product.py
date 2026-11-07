#!/usr/bin/env python3
"""Generate current identity fields from VERSION.json. Run before build/pin/manifest.
Changing runtime or release metadata by hand cannot pass check_versions.py.
"""
from pathlib import Path
import json,re
from product_version import SOURCE,identity
s=SOURCE;r=s.parent;p=identity();v=p['version'];repo=p['repository']
def dump(path,data):path.write_text(json.dumps(data,indent=2)+'\n')
a=s/'assets/release.json';j=json.loads(a.read_text());j.update(version=v,products={'universal':v,'zgocloud':v+p['protected_suffix']});j['webui']['display_version']=v;dump(a,j)
for name in ['assets/distribution.json','package.json','package-lock.json']:
 path=s/name;j=json.loads(path.read_text());j['version']=v
 if name=='package-lock.json':j['packages']['']['version']=v
 dump(path,j)
path=s/'src/manager.sh';path.write_text(re.sub(r'^MANAGER_VERSION="[^"]+"','MANAGER_VERSION="'+v+'"',path.read_text(),flags=re.M))
path=s/'shared_webui/backend/common.py';path.write_text(re.sub(r"^VERSION = ['\"][^'\"]+['\"]","VERSION = '"+v+"'",path.read_text(),flags=re.M))
path=s/'shared_webui/api-spec/API.md';path.write_text(re.sub(r'panel/product version is [\d.]+','panel/product version is '+v,path.read_text()))
if (r/'PUBLIC_PAYLOAD.json').exists():
 from pin_bootstrap import payload,apply
 old=json.loads((r/'PUBLIC_PAYLOAD.json').read_text());apply(payload(repo,old['sha256'],old['bytes']),r)
 path=r/'PROVENANCE.json';dump(path,{'schema':1,'product':'SBOX','version':v,'repository':'https://github.com/'+repo,'release_naming':'versionless; packages are located by content digest (pkg-<sha256 prefix>)','history':'Independent fresh Git root; no previous owner repository is a build/runtime dependency','core_sha256':p['core_sha256'],'core_rebuilt_for_this_release':False,'components':{'universal_manager':v,'protected_manager':v+p['protected_suffix'],'sing-box':'1.14.4'},'attribution':'Retains upstream sing-box GPL licensing, original accounting contract and owner-authorized protected compatibility. Detailed historical development lineage is retained in the encrypted owner handoff.'})
print('Generated product identity',v,repo)
