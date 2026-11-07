"""Actual generated nodes, URI round-trips and native-core config checks."""
import copy,base64,json,subprocess,sys,tempfile,unittest,urllib.parse as url
from pathlib import Path
import yaml
import reality_fixture as fx
sys.path[:0]=[str(fx.ROOT/'shared_webui/backend'),str(fx.ROOT/'shared_webui/privileged-bridge')]
from network_policy import select_endpoint,endpoint_options,patch_state,listen_for
from export_json import convert
from controller import candidate,preview
class Exports(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  private,public=fx.reality_keypair();cls.s=fx.trusted_certificate(fx.base_state(private,public));cls.s['server'].update(mode='dual',scope='internal',ipv4='127.0.0.1',ipv6='::1',listen='::');cls.s['sing_box']['version']='1.14.4'
  for p in cls.s['protocols'].values():p['enabled']=True
 def test_five_protocols_three_endpoint_types_uri_json_yaml(self):
  for choice,host in [('domain',fx.DOMAIN),('ipv4','127.0.0.1'),('ipv6','::1')]:
   with self.subTest(endpoint=choice):
    s=select_endpoint(self.s,choice);out=fx.render(s);doc=yaml.safe_load((out/'mihomo-internal.yaml').read_text());self.assertEqual(len(doc['proxies']),5)
    for n in doc['proxies']:self.assertEqual(n['server'],host);self.assertFalse(n.get('skip-cert-verify',False))
    native=convert(doc);p=out/'client.json';p.write_text(json.dumps(native));check=subprocess.run([str(fx.core_binary()),'check','-c',str(p)],capture_output=True,text=True);self.assertEqual(check.returncode,0,check.stderr)
    links=[l for l in (out/'links.txt').read_text().splitlines() if '://' in l];self.assertEqual(len(links),5)
    for line in links:
     if line.startswith('vmess://'):
      v=json.loads(base64.b64decode(line.split('://',1)[1]));self.assertEqual(v['add'],host);self.assertEqual(v['sni'],fx.DOMAIN);self.assertEqual(v['path'],'/lab-vm');self.assertEqual(v['host'],fx.DOMAIN)
     else:
      parsed=url.urlsplit(line);self.assertEqual(parsed.hostname,host);self.assertIsNotNone(parsed.port);self.assertTrue(parsed.username);self.assertIn('sni',url.parse_qs(parsed.query));self.assertNotIn('%25',parsed.hostname)
    if choice=='ipv6':self.assertTrue(doc['ipv6']);self.assertTrue(all('[' not in n['server'] for n in doc['proxies']))
 def test_credentials_with_uri_delimiters_roundtrip(self):
  s=copy.deepcopy(self.s);secret='reserved@:/?#&%+=0123456789'
  for key in ['hy2','tuic','anytls']:s['protocols'][key]['password']=secret
  lines=(fx.render(select_endpoint(s,'ipv6'))/'links.txt').read_text().splitlines()
  for line in lines:
   if line.startswith(('hysteria2://','anytls://')):self.assertEqual(url.unquote(url.urlsplit(line).username),secret)
   if line.startswith('tuic://'):self.assertEqual(url.unquote(url.urlsplit(line).password),secret)
 def test_client_preferences_and_native_strategies(self):
  for choice in ['prefer_ipv4','prefer_ipv6']:
   s=copy.deepcopy(self.s);s['server']['policies']={'inbound':'dual','egress':'ipv4','dns':'ipv4','client':choice};doc=yaml.safe_load((fx.render(s)/'mihomo-global.yaml').read_text());self.assertTrue(doc['ipv6']);self.assertFalse(doc['dns']['ipv6']);self.assertEqual(doc['proxies'][0]['ip-version'],choice.replace('prefer_','')+'-prefer');self.assertEqual(convert(doc)['outbounds'][0]['domain_resolver']['strategy'],choice)
 def test_disallowed_family_and_protected_overrides_rejected(self):
  s=patch_state(self.s,{'mode':'ipv4'})
  with self.assertRaises(ValueError):select_endpoint(s,'ipv6')
  s['zgo_legacy_compat']=True
  with self.assertRaises(ValueError):select_endpoint(s,'domain')
  with self.assertRaises(ValueError):patch_state(s,{'mode':'dual'})
 def test_network_preview_preserves_all_identity_fields(self):
  s=copy.deepcopy(self.s);s['managed_users']=[{'id':'a'*32,'name':'Alice','enabled':True,'tags':[],'protocols':{'tuic':{'password':'UNCHANGED-SYNTHETIC'}},'quota':{'quota_bytes':12345}}];request={'kind':'network','data':{'mode':'ipv6','panel_family':'ipv6'}};after=candidate(s,request,'universal');summary=preview(s,after,request,'universal')['summary'];self.assertEqual(s['managed_users'],after['managed_users']);self.assertEqual(s['protocols'],after['protocols']);self.assertEqual(summary['protected_identity'],'unchanged');self.assertEqual(summary['network']['after']['inbound'],'ipv6');self.assertEqual(listen_for(after['server'],'ipv6'),'::1');self.assertNotIn('UNCHANGED-SYNTHETIC',json.dumps(summary))
 def test_legacy_default_panel_keeps_existing_binding(self):
  self.assertIsNone(listen_for({},'preserve'));self.assertEqual(patch_state(self.s,{'mode':'ipv4'})['server'].get('panel_family','preserve'),'preserve')
if __name__=='__main__':unittest.main(verbosity=2)
