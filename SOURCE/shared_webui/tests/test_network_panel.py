"""Network-only HTTPS binding/firewall selection and transactional rollback."""
import sys,tempfile,json,unittest,types,os,subprocess
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
import network_policy as n
import firewall
from panel_backup import network_record
from common import Problem
class PanelNetwork(unittest.TestCase):
 def test_protected_network_page_never_invokes_generic_migration_cli(self):
  sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'privileged-bridge'))
  from bridge import Control
  c=Control(variant='zgocloud')
  with patch.object(c,'run',side_effect=AssertionError('Protected CLI must not be changed')):self.assertEqual(c.dispatch('network',{}),{'protected':True,'change_allowed':False})
 def test_firewall_family_and_narrow_destination(self):
  for address,tools in [('0.0.0.0',('iptables',)),('::',('iptables','ip6tables')),('2001:db8::1',('ip6tables',)),('192.0.2.1',('iptables',))]:
   cfg={'listen':address,'port':9443};self.assertEqual(firewall.tools(cfg),tools);self.assertTrue(firewall.public(cfg));rule=firewall.rule(cfg);self.assertEqual('-d' in rule,address not in ('::','0.0.0.0'))
  for address in ['127.0.0.1','::1']:self.assertFalse(firewall.public({'listen':address}))
 def test_failed_panel_family_change_restores_settings_and_service(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'settings.json';old={'listen':'0.0.0.0','port':9443,'origin':'https://unchanged.test:9443','other':'unchanged'};p.write_text(json.dumps(old));calls=[];writes=[]
   def write(path,cfg):writes.append(cfg.copy());path.write_text(json.dumps(cfg))
   def system(*args):
    calls.append(args)
    if args==('systemctl','start','sbox-webui.service') and len(writes)==1:raise RuntimeError('Injected startup failure')
   fake=types.SimpleNamespace(st_uid=0,st_mode=0o100600)
   # No root or systemd mutation; ownership, writer and service manager isolated.
   real_stat=Path.stat
   def stat(path,*a,**kw):return fake if path==p else real_stat(path,*a,**kw)
   with patch.object(Path,'stat',stat),patch.object(n,'_write_settings',write),patch.object(n,'_system',system),patch.object(n.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout='loaded\n')),patch.object(n.socket,'create_connection'):
    with self.assertRaisesRegex(RuntimeError,'Injected'):n.panel_apply({'server':{'panel_family':'dual'}},settings=p)
   self.assertEqual(json.loads(p.read_text()),old);self.assertEqual(writes[-1],old);self.assertEqual(calls[-1],('systemctl','start','sbox-webui.service'))
 def test_explicit_public_https_requires_trusted_chain(self):
  import importlib.util
  spec=importlib.util.spec_from_file_location('network_install',Path(__file__).resolve().parents[1]/'backend/install.py');installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);(p/'cert').write_text('invalid-untrusted-certificate');(p/'key').write_text('invalid-private-key');state={'domain':'public.test','certificate':{'mode':'static','source_fullchain':str(p/'cert'),'source_key':str(p/'key')}}
   def run(args,**kw):return types.SimpleNamespace(returncode=1 if 'verify' in args else 0,stdout='public.test does match certificate',stderr='')
   with patch.object(installer.subprocess,'run',side_effect=run):
    with self.assertRaises(Problem):installer.certificate({'listen':'2001:db8::1'},state)
 def test_retained_settings_without_unit_are_staged_without_service_calls(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'settings.json';p.write_text(json.dumps({'listen':'0.0.0.0','port':9443,'origin':'https://unchanged.test:9443'}));real_stat=Path.stat
   def stat(path,*a,**kw):return types.SimpleNamespace(st_uid=0,st_mode=0o100600) if path==p else real_stat(path,*a,**kw)
   def run(args,**kwargs):return types.SimpleNamespace(returncode=1 if 'show' in args else 3,stdout='not-found\n' if 'show' in args else '')
   def write(path,cfg):path.write_text(json.dumps(cfg))
   with patch.object(Path,'stat',stat),patch.object(n.subprocess,'run',side_effect=run),patch.object(n,'observed',return_value={'addresses':[{'address':'::1','usable':True}]}),patch.object(n,'_write_settings',side_effect=write),patch.object(n,'_system',side_effect=subprocess.CalledProcessError(5,['systemctl','stop','absent'])) as system:
    result=n.panel_apply({'server':{'panel_family':'ipv6','ipv6':'::1'}},settings=p)
    self.assertTrue(result['deferred_activation']);system.assert_not_called()
   self.assertEqual(json.loads(p.read_text())['listen'],'::1');self.assertEqual(json.loads(p.read_text())['origin'],'https://unchanged.test:9443')
 def test_backup_network_record_is_optional_strict_and_native(self):
  with tempfile.TemporaryDirectory() as td:
   db=Path(td)/'panel.db';db.touch();self.assertIsNone(network_record(db));p=db.with_name('network.json')
   for record in [{'listen':'::','port':9443},{'listen':'2001:db8::1','port':9443}]:p.write_text(json.dumps(record));self.assertEqual(network_record(db),record)
   for record in [{'listen':'ff02::1','port':9443},{'listen':'::ffff:192.0.2.1','port':9443},{'listen':'::','port':True}]:
    p.write_text(json.dumps(record))
    with self.assertRaises((Problem,ValueError)):network_record(db)
if __name__=='__main__':unittest.main(verbosity=2)
