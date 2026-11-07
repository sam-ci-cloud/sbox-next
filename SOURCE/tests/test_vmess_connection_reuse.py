"""VMess connection reuse (sing-mux + WebSocket early data) across every generated layer."""
import copy,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
import yaml
import reality_fixture as fx
sys.path[:0]=[str(fx.ROOT/'shared_webui/backend'),str(fx.ROOT/'shared_webui/privileged-bridge')]
from export_json import convert
from controller import candidate
from common import Problem
ED={'max_early_data':2048,'early_data_header_name':'Sec-WebSocket-Protocol'}
class VmessReuse(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  private,public=fx.reality_keypair();cls.s=fx.trusted_certificate(fx.base_state(private,public))
  for p in cls.s['protocols'].values():p['enabled']=True
 def rendered(self,flag):
  s=copy.deepcopy(self.s)
  if flag is not None:s['protocols']['vmess']['multiplex']=flag
  return fx.render(s)
 def vmess_inbound(self,out):return next(i for i in json.loads((out/'server.json').read_text())['inbounds'] if i['type']=='vmess')
 def vmess_proxy(self,out,name='mihomo.yaml'):return next(p for p in yaml.safe_load((out/name).read_text())['proxies'] if p['type']=='vmess')
 def test_absent_and_false_render_identically(self):
  a,b=self.rendered(None),self.rendered(False)
  for f in ('server.json','mihomo.yaml','mihomo-global.yaml','mihomo-cn.yaml','mihomo-internal.yaml','links.txt'):
   self.assertEqual((a/f).read_bytes(),(b/f).read_bytes(),f)
  self.assertNotIn('multiplex',self.vmess_inbound(a));self.assertNotIn('smux',self.vmess_proxy(a))
 def test_enabled_server_accepts_mux_and_early_data(self):
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);cert=Path(td.name)/'certs';ca,leaves=fx.lab_certificates(cert);(cert/'live').mkdir()
  shutil.copy2(leaves[fx.DOMAIN][0],cert/'live/fullchain.pem');shutil.copy2(leaves[fx.DOMAIN][1],cert/'live/privkey.pem')
  s=copy.deepcopy(self.s);s['protocols']['vmess']['multiplex']=True;out=fx.render(s,cert_dir=str(cert));ib=self.vmess_inbound(out)
  self.assertEqual(ib['multiplex'],{'enabled':True})
  for k,v in ED.items():self.assertEqual(ib['transport'][k],v)
  check=subprocess.run([str(fx.core_binary()),'check','-c',str(out/'server.json')],capture_output=True,text=True);self.assertEqual(check.returncode,0,check.stderr)
 def test_enabled_profiles_and_unchanged_links(self):
  on,off=self.rendered(True),self.rendered(None)
  for name in ('mihomo.yaml','mihomo-global.yaml','mihomo-cn.yaml','mihomo-internal.yaml'):
   p=self.vmess_proxy(on,name);self.assertEqual(p['smux'],{'enabled':True,'protocol':'h2mux','max-connections':1})
   self.assertEqual(p['ws-opts']['max-early-data'],2048);self.assertEqual(p['ws-opts']['early-data-header-name'],'Sec-WebSocket-Protocol')
  # URI/QR payload must not change: a "?ed=" path is read literally by some sing-box based apps.
  self.assertEqual((on/'links.txt').read_text(),(off/'links.txt').read_text())
  doc=yaml.safe_load((on/'mihomo-internal.yaml').read_text());native=convert(doc);vm=next(o for o in native['outbounds'] if o.get('type')=='vmess')
  self.assertEqual(vm['multiplex'],{'enabled':True,'protocol':'h2mux','max_connections':1});self.assertEqual(vm['transport']['max_early_data'],2048);self.assertEqual(vm['transport']['early_data_header_name'],'Sec-WebSocket-Protocol')
  p=on/'client.json';p.write_text(json.dumps(native));check=subprocess.run([str(fx.core_binary()),'check','-c',str(p)],capture_output=True,text=True);self.assertEqual(check.returncode,0,check.stderr)
 def test_converter_fails_closed_on_unrepresentable_fields(self):
  base={'name':'v','type':'vmess','server':'example.com','port':443,'uuid':'00000000-0000-4000-8000-000000000000','network':'ws','tls':True,'ws-opts':{'path':'/x'}}
  for bad in ({'smux':{'enabled':True,'padding':True}},{'smux':{'enabled':True,'protocol':'quic'}},{'ws-opts':{'path':'/x','v2ray-http-upgrade':True}}):
   with self.subTest(bad=bad):
    with self.assertRaises(ValueError):convert({'proxies':[{**base,**bad}]})
  off=convert({'proxies':[{**base,'smux':{'enabled':False}}]})['outbounds'][0];self.assertNotIn('multiplex',off)
 def test_panel_api_accepts_only_boolean_vmess_reuse(self):
  r=candidate(copy.deepcopy(self.s),{'kind':'inbounds','data':{'vmess':{'multiplex':True}}},'universal');self.assertIs(r['protocols']['vmess']['multiplex'],True)
  for data in ({'vmess':{'multiplex':'yes'}},{'reality':{'multiplex':True}},{'vmess':{'enabled':1}}):
   with self.subTest(data=data):
    with self.assertRaises(Problem):candidate(copy.deepcopy(self.s),{'kind':'inbounds','data':data},'universal')
  with self.assertRaises(Problem):candidate(copy.deepcopy(self.s),{'kind':'inbounds','data':{'vmess':{'multiplex':True}}},'zgocloud')
 def test_state_validator_rejects_non_boolean(self):
  s=copy.deepcopy(self.s);s['protocols']['vmess']['multiplex']='on'
  with self.assertRaises(Exception):fx.render(s)
if __name__=='__main__':unittest.main(verbosity=2)
