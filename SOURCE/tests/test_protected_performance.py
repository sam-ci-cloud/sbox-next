"""Supported opt-ins render for protected state without changing identity fields."""
import json,tempfile,unittest
from pathlib import Path
import reality_fixture as fx
class ProtectedPerformance(unittest.TestCase):
 def test_protected_tfo_is_an_explicit_supported_optin(self):
  state=fx.base_state();state['zgo_legacy_compat']=True;state['protocols']['reality']['tcp_fast_open']=True
  with tempfile.TemporaryDirectory() as td:
   r=fx.state_tool('render',state,td);self.assertEqual(r.returncode,0,r.stderr)
   cfg=json.loads((Path(td)/'server.json').read_text());inbound=next(i for i in cfg['inbounds'] if i['type']=='vless');self.assertIs(inbound['tcp_fast_open'],True);self.assertEqual(inbound['users'][0]['uuid'],state['protocols']['reality']['uuid'])
 def test_invalid_tfo_remains_rejected(self):
  state=fx.base_state();state['zgo_legacy_compat']=True;state['protocols']['reality']['tcp_fast_open']='yes';self.assertNotEqual(fx.state_tool('validate',state).returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
