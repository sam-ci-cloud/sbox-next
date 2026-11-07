"""Fail-first local guard visibility and scoped actions; no host firewall writes."""
import contextlib,http.client,json,os,shutil,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('backend','privileged-bridge')]
import webui_security as guard
from authorization import authorize
from bridge import Control
from common import Problem,digest
from server import App,Server

class Socket:
 def __init__(self,bans=(),drift=False):self.bans=list(bans);self.drift=drift
 def send(self,args):
  if args==['status',guard.NAME]:return (0,[])
  key=args[2]
  values={'banip':self.bans,'actions':['nftables'],'maxretry':6,'findtime':600,'bantime':600,'journalmatch':[['_SYSTEMD_UNIT=sbox-webui.service']]}
  if key=='action':
   properties={'port':'22' if self.drift else '9443','type':'multiport','protocol':'tcp','table':guard.TABLE,'table_family':'inet','chain':'sbox_webui_chain','chain_type':'filter','chain_hook':'input','chain_priority':'-19','blocktype':'drop'}
   return (0,properties[args[4]])
  return (0,values[key])
 def close(self):pass

class Snapshot(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.jail=self.root/'jail';self.filter=self.root/'filter';self.settings=self.root/'settings'
  self.settings.write_text(json.dumps({'port':9443}));jail,filt=guard.config(9443);self.jail.write_text(jail);self.filter.write_text(filt)
  self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close);self.addCleanup(self.tmp.cleanup)
  for key,value in [('JAIL',self.jail),('FILTER',self.filter),('SETTINGS',self.settings)]:self.stack.enter_context(patch.object(guard,key,value))
  self.stack.enter_context(patch.object(guard,'owned'))
 def snapshot(self,*,service='active',bans=(),drift=False,kernel=None,missing=False):
  def run(args,check=True):
   if args[0]=='systemctl':return subprocess.CompletedProcess(args,0,'ActiveState='+service+'\nLoadState=loaded\n','')
   if args[0]=='nft':return subprocess.CompletedProcess(args,0 if kernel else 1,json.dumps(kernel) if kernel else '','No such file or directory')
   raise AssertionError(args)
  with patch.object(guard.shutil,'which',return_value=None if missing else '/fixture/tool'),patch.object(guard,'run',side_effect=run),patch.object(guard,'client',return_value=Socket(bans,drift)):
   return guard.snapshot()
 def test_missing_fail2ban_is_unavailable_never_green(self):
  result=self.snapshot(missing=True);self.assertNotEqual(result['status'],'ok');self.assertEqual(result['service']['status'],'unavailable');self.assertEqual(result['network_verification']['status'],'unknown')
 def test_dead_service_never_green_even_if_socket_answers(self):
  result=self.snapshot(service='inactive');self.assertNotEqual(result['status'],'ok');self.assertEqual(result['service']['status'],'inactive')
 def test_lazy_kernel_creation_is_explicit_not_external_pass(self):
  result=self.snapshot();self.assertEqual(result['action']['status'],'configured');self.assertEqual(result['kernel']['status'],'idle');self.assertEqual(result['bans']['addresses'],[]);self.assertEqual(result['network_verification']['status'],'unknown')
 def test_running_jail_with_wrong_action_port_is_not_healthy(self):
  result=self.snapshot(drift=True);self.assertNotEqual(result['status'],'ok');self.assertEqual(result['action']['status'],'drift')
 def test_recorded_bans_without_kernel_table_are_degraded(self):
  result=self.snapshot(bans=['198.51.100.23']);self.assertNotEqual(result['status'],'ok');self.assertEqual(result['kernel']['status'],'missing');self.assertEqual(result['bans']['addresses'],['198.51.100.23'])
 def test_owned_config_drift_is_visible(self):
  self.jail.write_text(self.jail.read_text().replace('maxretry = 6','maxretry = 99'))
  result=self.snapshot();self.assertEqual(result['configuration']['status'],'drift');self.assertNotEqual(result['status'],'ok')
 def test_kernel_scope_and_ipv4_ipv6_bans_are_observed_independently(self):
  rows=[{'chain':{'name':'sbox_webui_chain','type':'filter','hook':'input','prio':-19}}]
  for family,name,address,kind in [('ip','addr-set-sbox-webui','198.51.100.23','ipv4_addr'),('ip6','addr6-set-sbox-webui','2001:db8::23','ipv6_addr')]:
   rows.append({'set':{'name':name,'type':kind,'elem':[address]}})
   rows.append({'rule':{'chain':'sbox_webui_chain','expr':[{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':9443}},{'match':{'op':'==','left':{'payload':{'protocol':family,'field':'saddr'}},'right':'@'+name}},{'drop':None}]}})
  observed=self.snapshot(bans=['198.51.100.23','2001:db8::23'],kernel={'nftables':rows})
  self.assertEqual(observed['kernel']['status'],'ready');self.assertTrue(observed['kernel']['scope_verified']);self.assertEqual(observed['network_verification']['status'],'unknown')
  rows[-1]['rule']['expr'][0]['match']['right']=22
  observed=self.snapshot(bans=['198.51.100.23','2001:db8::23'],kernel={'nftables':rows})
  self.assertEqual(observed['kernel']['status'],'drift');self.assertEqual(observed['kernel']['missing_bans'],['2001:db8::23']);self.assertNotEqual(observed['status'],'ok')
 def test_unban_validates_address_and_only_touches_own_jail(self):
  with patch.object(guard,'active',return_value=True),patch.object(guard,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
   guard.unban('2001:db8::23');self.assertEqual(run.call_args.args[0],['fail2ban-client','set','sbox-webui','unbanip','2001:db8::23'])
   with self.assertRaises(ValueError):guard.unban('198.51.100.23; reboot')
   self.assertEqual(run.call_count,1)
 def test_foreign_protection_files_are_not_adopted_for_unban(self):
  self.stack.close()
  with patch.object(guard,'owned',side_effect=RuntimeError('foreign')),patch.object(guard,'run') as run:
   with self.assertRaisesRegex(RuntimeError,'foreign'):guard.unban('198.51.100.23')
   run.assert_not_called()

class Routes(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.calls=[]
  def control(op,data=None):cls.calls.append((op,data));return {'status':'warning','service':{'status':'unavailable'}}
  cls.app=App({'database':str(Path(cls.tmp.name)/'panel.db'),'origin':'http://127.0.0.1','variant':'universal'},control)
  cls.server=Server(('127.0.0.1',0),cls.app);cls.app.cfg['origin']='http://127.0.0.1:'+str(cls.server.server_port)
  with cls.app.store.db() as db:
   for name,role in [('admin','admin'),('reader','reader')]:
    db.execute('INSERT INTO accounts(name,hash,role,reset) VALUES(?,?,?,0)',(name,'unused',role));ident=db.execute('SELECT id FROM accounts WHERE name=?',(name,)).fetchone()[0]
    db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)',(digest(name),ident,'csrf',time.time()+3600,time.time(),time.time()))
   ident=db.execute("SELECT id FROM accounts WHERE name='admin'").fetchone()[0]
   db.execute('INSERT INTO tokens VALUES(?,?,?,?,?)',(digest('write-token'),ident,'write','fixture',time.time()+3600))
  cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.app.store.close();cls.tmp.cleanup()
 def request(self,path,body=None,actor='admin',csrf='csrf'):
  connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5);headers={'Cookie':'sbox_session='+actor,'X-CSRF-Token':csrf,'Content-Type':'application/json'}
  try:
   connection.request('GET' if body is None else 'POST','/api/v1/'+path,None if body is None else json.dumps(body),headers);response=connection.getresponse();return response.status,json.loads(response.read())
  finally:connection.close()
 def test_reader_can_inspect_guard_but_not_repair(self):
  self.assertEqual(self.request('security/webui-guard',actor='reader')[0],200)
  self.assertEqual(self.request('actions',{'action':'webui-guard-repair','arguments':{}},actor='reader')[0],403)
 def test_admin_repair_and_unban_use_distinct_scoped_operations(self):
  self.assertEqual(self.request('actions',{'action':'webui-guard-repair','arguments':{}})[0],200)
  self.assertEqual(self.calls[-1],('webui-guard-repair',{}))
  self.assertEqual(self.request('actions',{'action':'webui-guard-unban','arguments':{'ip':'198.51.100.23'}})[0],200)
  self.assertEqual(self.calls[-1],('webui-guard-unban',{'ip':'198.51.100.23'}))
 def test_csrf_and_freshness_enforced_before_guard_mutation(self):
  self.assertEqual(self.request('actions',{'action':'webui-guard-repair','arguments':{}},csrf='wrong')[0],403)
  with self.app.store.db() as db:db.execute('UPDATE sessions SET fresh=? WHERE hash=?',(time.time()-301,digest('admin')))
  try:self.assertEqual(self.request('actions',{'action':'webui-guard-repair','arguments':{}})[0],428)
  finally:
   with self.app.store.db() as db:db.execute('UPDATE sessions SET fresh=? WHERE hash=?',(time.time(),digest('admin')))
 def test_root_read_allowlist_and_mutations_require_browser_reauthentication(self):
  path=self.app.cfg['database'];cfg={'monitor_key':'unused'}
  self.assertEqual(authorize('webui-guard',{}, {'kind':'browser','raw':'reader'},cfg,path)['kind'],'browser')
  for context in [{'kind':'browser','raw':'reader','csrf':'csrf'},{'kind':'browser','raw':'admin','csrf':'wrong'},{'kind':'monitor','key':'unused'},{'kind':'portal','session':'opaque'},{'kind':'token','raw':'write-token'}]:
   with self.subTest(context=context),self.assertRaises(Problem):authorize('webui-guard-repair',{},context,cfg,path)
  with self.app.store.db() as db:db.execute('UPDATE sessions SET fresh=? WHERE hash=?',(time.time()-301,digest('admin')))
  try:
   with self.assertRaises(Problem):authorize('webui-guard-repair',{}, {'kind':'browser','raw':'admin','csrf':'csrf'},cfg,path)
  finally:
   with self.app.store.db() as db:db.execute('UPDATE sessions SET fresh=? WHERE hash=?',(time.time(),digest('admin')))
 def test_bridge_does_not_route_webui_guard_unban_to_ssh(self):
  control=Control(base=self.tmp.name)
  with patch.object(guard,'unban') as unban,patch.object(guard,'snapshot',return_value={'status':'warning'}),patch.object(control,'run') as manager:
   control.dispatch('webui-guard-unban',{'ip':'198.51.100.23'});unban.assert_called_once_with('198.51.100.23');manager.assert_not_called()
  with self.assertRaises(Problem):control.dispatch('webui-guard-repair',{'command':'foreign'})
  with self.assertRaises(Problem) as invalid:control.dispatch('webui-guard-unban',{'ip':'not-an-IP'})
  self.assertEqual(invalid.exception.status,400)

@unittest.skipUnless(shutil.which('node'),'Node.js is required for guard card checks')
class Frontend(unittest.TestCase):
 def test_guard_card_states_and_actions(self):
  result=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('test_webui_guard_ui.cjs'))],capture_output=True,text=True,timeout=20)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
