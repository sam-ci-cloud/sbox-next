"""Real HTTPS request boundary; synthetic root bridge session controls."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_panel_v2 import Panel
from common import Problem
class NodeQRAccess(Panel):
 def setUp(self):
  super().setUp();self.original=self.app.control;self.calls=[]
  def control(op,data=None):
   if op in ('portal-connection','portal-export'):
    self.calls.append((op,data))
    if data.get('session')!='synthetic-alice-session':raise Problem(401,'Unauthorized')
    if data.get('csrf')!='synthetic-alice-csrf':raise Problem(403,'CSRF')
    if op=='portal-connection':return {'id':'a'*32,'enabled':True}
    return {'content':'[VLESS]\nvless://synthetic-alice@vpn.example.test:443?security=reality\n'}
   return self.original(op,data)
  self.app.control=control;self.qr=self.app.qrencode;self.payloads=[];self.render=__import__('server').Handler.qr
  __import__('server').Handler.qr=lambda handler,text:self.payloads.append(text) or '<svg xmlns="http://www.w3.org/2000/svg"/>'
 def tearDown(self):
  self.app.control=self.original;self.app.qrencode=self.qr;__import__('server').Handler.qr=self.render
 def headers(self,session='synthetic-alice-session',csrf='synthetic-alice-csrf'):
  return {'Cookie':'sbox_portal_session='+session,'X-CSRF-Token':csrf}
 def test_session_and_csrf_required(self):
  body={'profile':'global','index':0}
  for headers,expected in [({},401),(self.headers('other'),401),(self.headers(csrf='wrong'),403)]:self.assertEqual(self.req('/api/v1/portal/me/node-qr',body,headers)[0],expected)
  self.assertEqual(self.payloads,[])
 def test_server_derives_node_payload_from_authenticated_export(self):
  code,headers,result=self.req('/api/v1/portal/me/node-qr',{'profile':'global','index':0},self.headers());self.assertEqual(code,200,result);self.assertEqual(headers['Cache-Control'],'no-store');self.assertEqual(self.payloads,['vless://synthetic-alice@vpn.example.test:443?security=reality']);self.assertEqual(self.calls[-1][1],{'session':'synthetic-alice-session','csrf':'synthetic-alice-csrf','profile':'global','format':'links','endpoint':'auto'})
 def test_client_cannot_choose_other_identity_or_arbitrary_payload(self):
  cases=[{'profile':'global','index':True},{'profile':'global','index':-1},{'profile':'global','index':99},{'profile':'global','index':0,'id':'b'*32},{'profile':'global','index':0,'text':'https://attacker.example.test'},{'profile':'../../private','index':0}]
  for body in cases:self.assertNotEqual(self.req('/api/v1/portal/me/node-qr',body,self.headers())[0],200)
  self.assertEqual(self.payloads,[])
if __name__=='__main__':unittest.main()
