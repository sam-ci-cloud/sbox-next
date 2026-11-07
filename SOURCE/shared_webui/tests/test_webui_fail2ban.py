"""Credentials never enter the fixed journal signal consumed by the UI jail."""
import contextlib,io,sys,tempfile,unittest,json,subprocess,shutil,re,datetime
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from store import Store
from common import Problem
class AuthSignal(unittest.TestCase):
 def test_failed_login_emits_only_validated_peer_not_user_input(self):
  with tempfile.TemporaryDirectory() as td:
   s=Store(Path(td)/'panel.db');output=io.StringIO()
   try:
    with contextlib.redirect_stdout(output),self.assertRaises(Problem):s.login('untrusted\\nSBOX_WEBUI_AUTH_FAILED ip=203.0.113.99','SYNTHETIC-DO-NOT-LOG','', '198.51.100.23')
    self.assertEqual(output.getvalue(),'SBOX_WEBUI_AUTH_FAILED ip=198.51.100.23 event=login\n')
   finally:s.close()
 def test_mapped_ipv4_and_invalid_peer_are_safe(self):
  from auth_events import auth_failure
  output=io.StringIO()
  with contextlib.redirect_stdout(output):
   self.assertTrue(auth_failure('::ffff:198.51.100.23','login'))
   self.assertFalse(auth_failure('198.51.100.23\nINJECTED','login'))
   self.assertFalse(auth_failure('198.51.100.23','untrusted-event'))
  self.assertEqual(output.getvalue(),'SBOX_WEBUI_AUTH_FAILED ip=198.51.100.23 event=login\n')
 def test_filter_and_scope(self):
  import webui_security as guard
  jail,filt=guard.config(9443)
  self.assertIn('type=multiport',jail);self.assertIn('port=9443, protocol=tcp',jail)
  self.assertIn('table=sbox_webui_f2b',jail);self.assertNotIn('allowlist',jail)
  self.assertIn('journalmatch = _SYSTEMD_UNIT=sbox-webui.service',filt)
  self.assertTrue(guard.FAILREGEX.startswith('^'));self.assertTrue(guard.FAILREGEX.endswith('$'))
  for value in (22,0,65536,'9443',True):
   with self.assertRaises(ValueError):guard.config(value)
 def test_invalid_config_restores_previous_files_before_activation(self):
  import webui_security as guard
  with tempfile.TemporaryDirectory() as td:
   jail=Path(td)/'jail.local';filt=Path(td)/'filter.conf';settings=Path(td)/'settings.json'
   jail.write_text('ORIGINAL JAIL');filt.write_text('ORIGINAL FILTER');settings.write_text(json.dumps({'port':9443}))
   with patch.object(guard,'JAIL',jail),patch.object(guard,'FILTER',filt),patch.object(guard,'SETTINGS',settings),patch.object(guard,'owned'),patch.object(guard,'active',return_value=True),patch.object(guard,'commands',side_effect=RuntimeError('invalid configuration')),patch.object(guard,'run',return_value=subprocess.CompletedProcess([],0,stdout='',stderr='')) as runner:
    with self.assertRaisesRegex(RuntimeError,'invalid configuration'):guard.setup()
    self.assertFalse(any(c.args[0][0]=='systemctl' for c in runner.call_args_list))
   self.assertEqual(jail.read_text(),'ORIGINAL JAIL');self.assertEqual(filt.read_text(),'ORIGINAL FILTER')
 def test_active_foreign_jail_without_owned_files_is_not_adopted(self):
  import webui_security as guard
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);jail=root/'jail.local';filt=root/'filter.conf';settings=root/'settings.json';settings.write_text(json.dumps({'port':9443}))
   def command(args,*a,**kw):return subprocess.CompletedProcess(args,1 if args[:2]==['nft','list'] else 0,stdout='',stderr='')
   with patch.object(guard,'JAIL',jail),patch.object(guard,'FILTER',filt),patch.object(guard,'SETTINGS',settings),patch.object(guard,'active',return_value=True),patch.object(guard,'commands',return_value=[]),patch.object(guard,'run',side_effect=command) as runner:
    with self.assertRaisesRegex(RuntimeError,'Foreign active WebUI jail'):guard.setup()
    self.assertFalse(jail.exists());self.assertFalse(filt.exists())
    self.assertFalse(any(c.args[0][0] in ('systemctl','fail2ban-client') for c in runner.call_args_list))
 def test_distribution_parser_matches_native_journal_prefix_and_rejects_injection(self):
  if not shutil.which('fail2ban-regex') or not Path('/etc/fail2ban/filter.d/common.conf').is_file():self.skipTest('Requires distribution Fail2Ban parser/common filter; run prepared root or CI suite')
  import webui_security as guard
  stamp=datetime.datetime.now().astimezone().isoformat();prefix=stamp+' fixture python3[123]: '
  lines=[prefix+'SBOX_WEBUI_AUTH_FAILED ip=198.51.100.10 event=login',prefix+'SBOX_WEBUI_AUTH_FAILED ip=2001:db8::10 event=portal',prefix+'user supplied SBOX_WEBUI_AUTH_FAILED ip=203.0.113.99 event=login',prefix+'SBOX_WEBUI_AUTH_FAILED ip=198.51.100.10 extra=invalid event=login']
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'common.conf').symlink_to('/etc/fail2ban/filter.d/common.conf');(root/'filter.conf').write_text(guard.config(9443)[1]);(root/'events.log').write_text('\n'.join(lines)+'\n')
   p=subprocess.run(['fail2ban-regex',str(root/'events.log'),str(root/'filter.conf')],capture_output=True,text=True,timeout=20)
   self.assertEqual(p.returncode,0,p.stderr);self.assertRegex(p.stdout,r'Lines: 4 lines, 0 ignored, 2 matched, 2 missed')
if __name__=='__main__':unittest.main(verbosity=2)
