#!/usr/bin/env python3
"""Deterministic CycloneDX inventory from corresponding-core buildinfo and npm lock."""
from pathlib import Path
import json,uuid
S=Path(__file__).resolve().parents[1];R=S.parent;release=json.loads((S/'assets/release.json').read_text());core=json.loads((S/'shared_webui/backend/core_manifest.json').read_text());inventory=json.loads((S/'core-source/SBOM.json').read_text());lock=json.loads((S/'package-lock.json').read_text())
product={'type':'application','name':'SBOX','version':release['version'],'bom-ref':'product','licenses':[{'expression':'GPL-3.0-or-later'}]}
components=[product,{'type':'application','name':'sing-box-accounting','version':core['version'],'bom-ref':'core','hashes':[{'alg':'SHA-256','content':core['sha256']}],'licenses':[{'expression':'GPL-3.0-or-later'}],'properties':[{'name':'compiler','value':core['go_version']},{'name':'corresponding-source','value':'core-source/sing-box + sbox-accounting.patch + security-dependencies.patch'}]}];linked=[]
for m in inventory['modules']:
 if not m['linked_in_embedded_core']:continue
 ref='go:'+m['module']+'@'+m['version'];linked.append(ref);components.append({'type':'library','name':m['module'],'version':m['version'],'bom-ref':ref,'properties':[{'name':'go.module.h1','value':m.get('sum') or 'not recorded'},{'name':'license-notices','value':', '.join(m['license_files'])}]})
for p,m in sorted(lock['packages'].items()):
 if not p:continue
 name=m.get('name') or p.split('node_modules/')[-1];ref='npm:'+name+'@'+m['version'];components.append({'type':'library','name':name,'version':m['version'],'bom-ref':ref,'scope':'excluded','properties':[{'name':'usage','value':'browser test dependency, not installed on VPS'},{'name':'lock-integrity','value':m.get('integrity','')}]})
bom={'bomFormat':'CycloneDX','specVersion':'1.5','serialNumber':'urn:uuid:'+str(uuid.uuid5(uuid.NAMESPACE_URL,'https://github.com/'+json.loads((S/'VERSION.json').read_text())['repository']+'/'+release['version']+'/'+core['sha256'])),'version':1,'metadata':{'timestamp':'2026-11-04T00:00:00Z','component':product,'tools':[{'vendor':'SBOX','name':'update_sbom.py','version':'1'}]},'components':components,'dependencies':[{'ref':'product','dependsOn':['core']},{'ref':'core','dependsOn':linked}]}
for path in [S/'SBOM.json',R/'SBOM.json']:path.write_text(json.dumps(bom,indent=2)+'\n')
print('SBOM generated:',len(components),'components,',len(linked),'linked Go modules')
