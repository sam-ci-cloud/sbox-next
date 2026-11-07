"""Public listener, certificate and owned firewall regression contracts.
No host firewall mutations: subprocess firewall commands use a stateful fixture.
SBOX_WEBUI_ROOT permits fail-first execution against the supplied Claude tree.
"""
import importlib.util,json,os,pathlib,subprocess,sys,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(os.environ.get('SBOX_WEBUI_ROOT',pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT/'backend'))
import install
from common import Problem

class PublicAccess(unittest.TestCase):
 def test_no_certificate_does_not_silently_change_public_listener(self):
  with patch.object(install.os,'chown'), tempfile.TemporaryDirectory() as td, patch.object(install,'ETC',pathlib.Path(td)), patch.object(install.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_gid=os.getgid())):
   cfg={'variant':'universal','port':9443,'listen':'0.0.0.0','origin':'https://vpn.example.test:9443'}
   state={'domain':'vpn.example.test','certificate':{'mode':'none','source_fullchain':'','source_key':''}}
   with self.assertRaisesRegex(Problem,'certificate'):
    install.certificate(cfg,state)
   self.assertEqual(cfg['listen'],'0.0.0.0')

 def test_explicit_ipv6_loopback_is_preserved(self):
  with patch.object(install.os,'chown'),tempfile.TemporaryDirectory() as td,patch.object(install,'ETC',pathlib.Path(td)),patch.object(install.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_gid=os.getgid())):
   cfg={'variant':'universal','port':9443,'listen':'::1'}
   state={'domain':'vpn.example.test','certificate':{'mode':'none','source_fullchain':'','source_key':''}}
   install.certificate(cfg,state)
   self.assertEqual(cfg['listen'],'::1','Preserve an intentional listener override')

 def test_public_self_signed_certificate_is_rejected(self):
  with patch.object(install.os,'chown'), tempfile.TemporaryDirectory() as td,patch.object(install,'ETC',pathlib.Path(td)),patch.object(install.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_gid=os.getgid())):
   p=pathlib.Path(td);subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=vpn.example.test','-addext','subjectAltName=DNS:vpn.example.test','-keyout',str(p/'key'),'-out',str(p/'cert')],check=True,capture_output=True)
   cfg={'variant':'universal','port':9443,'listen':'0.0.0.0'}
   state={'domain':'vpn.example.test','certificate':{'mode':'existing','source_fullchain':str(p/'cert'),'source_key':str(p/'key')}}
   with self.assertRaisesRegex(Problem,'trusted'):
    install.certificate(cfg,state)

 def firewall(self):
  p=ROOT/'backend/firewall.py'
  self.assertTrue(p.is_file(),'The public panel needs an owned persistent firewall implementation')
  spec=importlib.util.spec_from_file_location('public_firewall',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

 def test_public_firewall_is_narrow_idempotent_and_preserves_foreign(self):
  m=self.firewall();rules=[];ufw=[];calls=[]
  def run(argv,**kwargs):
   calls.append(argv);text='';rc=0
   if argv[0].endswith('ufw'):
    if 'status' in argv:text='Status: active\n'+ '\n'.join(f'[{i+1:2}] {x}' for i,x in enumerate(ufw))
    elif 'allow' in argv:
     row='9443/tcp ALLOW IN Anywhere # sbox-webui'
     if row not in ufw:ufw.append(row)
    elif 'delete' in argv:ufw.pop(int(argv[-1])-1)
   elif '-S' in argv:text='-P INPUT DROP\n-A INPUT -j SBOX_INPUT\n-A INPUT -j foreign\n'
   elif '-C' in argv:rc=0 if tuple(argv[argv.index('-C')+1:]) in rules else 1
   elif '-I' in argv:rules.append(tuple([argv[argv.index('-I')+1]]+argv[argv.index('-I')+3:]))
   elif '-D' in argv:rules.remove(tuple(argv[argv.index('-D')+1:]))
   return subprocess.CompletedProcess(argv,rc,text,'')
  foreign='12345/tcp ALLOW IN 198.51.100.20 # foreign';ufw.append(foreign)
  with patch.object(m,'execute',side_effect=run),patch.object(m.shutil,'which',side_effect=lambda x:'/usr/sbin/'+x):
   cfg={'listen':'0.0.0.0','port':9443};state={'firewall':{'enabled':True}}
   m.apply(cfg,state);first=list(rules);m.apply(cfg,state)
   self.assertEqual(first,rules);self.assertEqual(len(rules),1);self.assertEqual(len(ufw),2)
   self.assertTrue(all(c[c.index('-I')+2]=='2' for c in calls if '-I' in c), 'Keep the manager firewall hook first, preserving its health invariant')
   self.assertIn('--dport',rules[0]);self.assertNotIn('-s',rules[0]);self.assertIn(foreign,ufw)
   m.remove(cfg);self.assertEqual(ufw,[foreign]);self.assertFalse(rules)
   self.assertFalse(any(x in c for c in calls for x in ['-F','flush','reset']))

 def test_drift_is_detected_read_only_and_repaired_by_apply(self):
  m=self.firewall();rules=[];ufw=[];calls=[];hook=['-A INPUT -j SBOX_INPUT']
  def run(argv,**kwargs):
   calls.append(argv);text='';rc=0
   if argv[0].endswith('ufw'):
    if 'status' in argv:text='Status: active\n'+'\n'.join(('[%2d] '%(i+1) if 'numbered' in argv else '')+x for i,x in enumerate(ufw))
    elif 'allow' in argv:
     row='9443/tcp ALLOW IN Anywhere # sbox-webui'
     if row not in ufw:ufw.append(row)
   elif '-S' in argv:text='-P INPUT DROP\n'+'\n'.join(hook+['-A INPUT '+' '.join(r[1:]) for r in rules])+'\n'
   elif '-C' in argv:rc=0 if tuple(argv[argv.index('-C')+1:]) in rules else 1
   elif '-I' in argv:rules.append(tuple([argv[argv.index('-I')+1]]+argv[argv.index('-I')+3:]))
   elif '-D' in argv:rules.remove(tuple(argv[argv.index('-D')+1:]))
   return subprocess.CompletedProcess(argv,rc,text,'')
  with patch.object(m,'execute',side_effect=run),patch.object(m.shutil,'which',side_effect=lambda x:'/usr/sbin/'+x):
   cfg={'listen':'0.0.0.0','port':9443};state={'firewall':{'enabled':True}}
   m.apply(cfg,state);self.assertEqual(m.check(cfg,state),[])
   rules.clear();ufw.clear();before=len(calls)   # foreign "ufw reload": owned rules gone, panel still listening
   self.assertEqual(m.check(cfg,state),['iptables panel INPUT rule missing','ufw panel allow missing'])
   self.assertFalse([c for c in calls[before:] if any(x in c for x in ('-I','-D','allow','delete'))],'check never mutates')
   m.apply(cfg,state);self.assertEqual(m.check(cfg,state),[],'apply restores both owned rules')
   self.assertEqual(m.check(cfg,{'firewall':{'enabled':False}}),[],'firewall disabled: nothing to check')
   self.assertEqual(m.check({'listen':'127.0.0.1','port':9443},state),[],'loopback panel: nothing to check')

 def test_repair_timer_is_installed_and_removed_with_the_panel(self):
  text=(ROOT/'backend/install.py').read_text()
  self.assertIn("firewall.py repair",text);self.assertIn("OnUnitActiveSec=2min",text)
  self.assertEqual(text.count("'sbox-webui-firewall-repair.timer'"),5,'written, enabled, started, disabled and removed')

 def test_loopback_has_no_public_firewall_rule(self):
  m=self.firewall()
  with patch.object(m,'execute') as call:
   m.apply({'listen':'127.0.0.1','port':9443},{'firewall':{'enabled':True}})
   call.assert_not_called()

 def test_explicit_start_recovers_systemd_start_limit(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);(p/'failed').touch()
   script=p/'run';script.write_text((ROOT/'privileged-bridge/manager_extension.sh').read_text()+"\nneed_root() { :; }\nsystemctl() { if [ \"$1\" = reset-failed ]; then rm -f \"$FIXTURE/failed\"; else [ ! -e \"$FIXTURE/failed\" ]; fi; }\nwebui_command start\n")
   result=subprocess.run(['bash',str(script)],env={**os.environ,'FIXTURE':td},capture_output=True,text=True)
   self.assertEqual(result.returncode,0,'Explicit start must recover a previously rate-limited unit: '+result.stderr)

 def test_missing_public_certificate_preserves_core_install_contract(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'run'
   p.write_text((ROOT/'privileged-bridge/manager_extension.sh').read_text().replace('/etc/sbox-webui/',td+'/etc/sbox-webui/').replace('/etc/systemd/system/',td+'/etc/systemd/system/')+"\nWEBUI_VARIANT=universal; STATE_FILE=/nonexistent\ncert_trusted() { return 1; }; jq() { echo missing; }; warn() { echo \"$*\"; }; webui_command() { echo INSECURE_PANEL; }\nwebui_install_if_enabled\n")
   result=subprocess.run(['bash',str(p)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0)
   self.assertNotIn('INSECURE_PANEL',result.stdout)
   self.assertIn('pending',result.stdout)

 def test_provider_guidance_opens_any_source_and_is_honest(self):
  m=self.firewall();text=m.guidance({'listen':'::','port':9443})
  for x in ('9443','0.0.0.0/0','::/0','unverified'):self.assertIn(x,text)

if __name__=='__main__':unittest.main(verbosity=2)
