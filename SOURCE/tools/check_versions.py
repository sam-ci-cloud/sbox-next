#!/usr/bin/env python3
"""Offline identity gate. One canonical product version; API/core versions independent.
Use --root on a clean source extraction; --json writes a machine-readable report.
"""
from pathlib import Path
import argparse,ast,hashlib,json,re,sys
from product_version import identity,REPOSITORY

def check(root):
 s=root/'SOURCE';load=lambda p:json.loads(p.read_text());c=load(s/'VERSION.json');v=c['version'];repo=c['repository'];rows=[]
 def gate(name,condition):
  rows.append({'check':name,'status':'PASS' if condition else 'FAIL'})
 release=load(s/'assets/release.json');build=load(s/'BUILD.json');pin=load(root/'PUBLIC_PAYLOAD.json');bootstrap=(root/'install.sh').read_text();prov=load(root/'PROVENANCE.json');core=load(s/'shared_webui/backend/core_manifest.json')
 gate('canonical',c['schema']==1 and c['product']=='SBOX' and bool(REPOSITORY.fullmatch(repo)) and bool(re.fullmatch(r'\d+\.\d+\.\d+',v)))
 gate('release',release['version']==v and release['products']=={'universal':v,'zgocloud':v+'-zgocloud'} and release['webui']['display_version']==v)
 for n in ['package.json','package-lock.json','assets/distribution.json']:gate(n,load(s/n)['version']==v)
 gate('npm-root',load(s/'package-lock.json')['packages']['']['version']==v)
 gate('manager',bool(re.search(r'^MANAGER_VERSION="'+re.escape(v)+'"$',(s/'src/manager.sh').read_text(),re.M)))
 module=ast.parse((s/'shared_webui/backend/common.py').read_text());web=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets))
 gate('backend',web==v);gate('frontend','const PRODUCT_VERSION='+json.dumps(v)+';' in (s/'shared_webui/frontend/app.js').read_text())
 gate('sealed-manager',load(s/'assets/zgocloud.json').get('version')==v+'-zgocloud')
 gate('build',build.get('version')==v and build.get('repository')==repo)
 gate('bootstrap','version' not in pin and pin['tag']=='pkg-'+pin['sha256'][:16] and pin['url']==f'https://github.com/{repo}/releases/download/{pin["tag"]}/SING-BOX.tar.gz' and f"SBOX_SHA256='{pin['sha256']}'" in bootstrap and pin['bootstrap_url']==f'https://raw.githubusercontent.com/{repo}/main/install.sh' and pin['sha256'] in bootstrap and pin['url'] in bootstrap)
 gate('provenance',prov['version']==v and prov['repository']=='https://github.com/'+repo and prov['components']['universal_manager']==v and prov['components']['protected_manager']==v+'-zgocloud')
 for base in [root,s]:
  gate(str(base.relative_to(root))+'/README',bool(re.fullmatch(r'# SBOX(?: — [^0-9]*)?',(base/'README.md').read_text().splitlines()[0].strip())));bom=load(base/'SBOM.json');gate(str(base.relative_to(root))+'/SBOM',bom['metadata']['component']['version']==v and next(x for x in bom['components'] if x['bom-ref']=='product')['version']==v)
 gate('API-product',('panel/product version is '+v) in (s/'shared_webui/api-spec/API.md').read_text())
 gate('frozen-core',core['sha256']==c['core_sha256']==build['core_sha256']==prov['core_sha256'] and core['go_sum_sha256']==hashlib.sha256((s/'core-source/sing-box/go.sum').read_bytes()).hexdigest())
 d=load(s/'core-source/BUILD_PROVENANCE.json');gate('core-provenance',d['sha256']==core['sha256'] and d['go_sum_sha256']==core['go_sum_sha256'])
 import importlib.util
 spec=importlib.util.spec_from_file_location('core_policy',s/'shared_webui/backend/core_resolver.py');policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
 gate('core-security',core['security_policy']==policy.SECURITY_POLICY and policy.security_qualified(core) and core['go_version'].split()[2]==policy.TOOLCHAIN_VERSION)
 return {'version':v,'repository':repo,'checks':rows,'passed':all(x['status']=='PASS' for x in rows)}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);ap.add_argument('--json',type=Path);a=ap.parse_args()
 try:report=check(a.root.resolve())
 except (ValueError,KeyError,OSError,StopIteration) as e:report={'passed':False,'error':str(e)}
 if a.json:a.json.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2));sys.exit(0 if report['passed'] else 1)
