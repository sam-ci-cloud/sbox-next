"""Regression for loss of the panel INPUT hook before hardening regeneration."""
import pathlib,re,subprocess,tempfile,json,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def function(path,name):
 text=path.read_text();m=re.search(r'^'+name+r'\(\) \{\n.*?^\}',text,re.M|re.S)
 if not m:raise AssertionError('Required shell function missing: '+name)
 return m.group()
class PanelFirewallReconcile(unittest.TestCase):
 def test_existing_panel_is_reconciled_before_hardening_collects_live_ports(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp);(p/'state.json').write_text(json.dumps({'firewall':{'enabled':True},'server':{'listen':'::'},'certificate':{'mode':'existing'}}))
   script='''set -eu
TRACE="$1/trace"; PANEL="$1/panel-hook"
firewall_preflight_file() { :; }
firewall_apply_family() { echo "$1" >> "$TRACE"; }
ipv6_available() { return 0; }
security_reconcile_optional() { echo security >> "$TRACE"; }
webui_firewall_reconcile() { touch "$PANEL"; echo panel >> "$TRACE"; }
hardening_reconcile_file() { if [ -f "$PANEL" ]; then echo hardening-with-panel >> "$TRACE"; else echo hardening-without-panel >> "$TRACE"; fi; }
'''+function(ROOT/'src/manager.sh','firewall_apply_file')+'\nfirewall_apply_file "$1/state.json"\n'
   r=subprocess.run(['bash','-c',script,'test',tmp],capture_output=True,text=True)
   self.assertEqual(r.returncode,0,r.stderr)
   self.assertEqual((p/'trace').read_text().splitlines(),['iptables','ip6tables','security','panel','hardening-with-panel'])
class PanelHelperSafety(unittest.TestCase):
 def run_helper(self,owner='0',mode=0o644,helper_exit=0,settings=True,symlink=False,dir_mode=0o755):
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp);lib=p/'lib';lib.mkdir();lib.chmod(dir_mode);helper=lib/'firewall.py';helper.write_text('# test helper\n');helper.chmod(mode)
   if symlink:
    helper.rename(lib/'real.py');helper.symlink_to(lib/'real.py')
   setting=p/'settings.json'
   if settings:setting.write_text('{}')
   text=function(ROOT/'shared_webui/privileged-bridge/manager_extension.sh','webui_firewall_reconcile').replace('/etc/sbox-webui/settings.json',str(setting))
   script='set -eu\nWEBUI_LIB="$1/lib"; CALLS="$1/calls"\nwarn() { :; }\nstat() { if [ "$2" = %u ]; then echo '+owner+'; else command stat "$@"; fi; }\npython3() { echo "$*" >> "$CALLS"; return '+str(helper_exit)+'; }\n'+text+'\nwebui_firewall_reconcile\n'
   r=subprocess.run(['bash','-c',script,'test',tmp],capture_output=True,text=True)
   r.calls=(p/'calls').read_text() if (p/'calls').exists() else ''
   return r
 def test_declared_panel_runs_owned_helper(self):
  r=self.run_helper();self.assertEqual(r.returncode,0,r.stderr);self.assertIn('firewall.py apply',r.calls)
 def test_without_panel_no_helper_execution(self):
  r=self.run_helper(settings=False);self.assertEqual(r.returncode,0);self.assertEqual(r.calls,'')
 def test_unsafe_helpers_are_refused(self):
  for kw in [{'owner':'1000'},{'mode':0o666},{'symlink':True},{'dir_mode':0o777},{'dir_mode':0o775}]:
   with self.subTest(**kw):
    r=self.run_helper(**kw);self.assertNotEqual(r.returncode,0);self.assertEqual(r.calls,'')
 def test_helper_failure_propagates(self):
  self.assertNotEqual(self.run_helper(helper_exit=7).returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
