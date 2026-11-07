"""Explicit OS gates and shared-helper refresh for a previously embedded manager."""
from protected_build_fixture import protected_template
from pathlib import Path
import importlib.util,re,subprocess,unittest
ROOT=Path(__file__).resolve().parents[1]
class Platform(unittest.TestCase):
 def gate(self,product,os,version):
  s=(ROOT/'src/install.template.sh').read_text();line=next(x for x in s.splitlines() if 'case "$VARIANT:$ID:$VERSION_ID"' in x)
  return subprocess.run(['bash','-c','die() { exit 91; };VARIANT=$1;ID=$2;VERSION_ID=$3;'+line,'fixture',product,os,version],capture_output=True).returncode
 def test_supported_matrix_is_explicit(self):
  for variant,versions in [('generic',('24.04','26.04','26.10')),('zgocloud',('24.04','26.04','26.10'))]:
   for v in versions:
    with self.subTest(product=variant,version=v):self.assertEqual(self.gate(variant,'ubuntu',v),0)
  self.assertEqual(self.gate('generic','debian','12'),0)
 def test_other_platforms_are_still_refused(self):
  for v in [('zgocloud','ubuntu','22.04'),('zgocloud','debian','12'),('generic','ubuntu','22.04'),('generic','debian','13'),('generic','alpine','3.22')]:
   with self.subTest(platform=v):self.assertNotEqual(self.gate(*v),0)
 def test_previously_embedded_helper_gets_current_common_source(self):
  spec=importlib.util.spec_from_file_location('release_builder',ROOT/'tools/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
  manager=b.integrate((ROOT/'src/manager.sh').read_text(),'universal').decode()
  self.assertEqual(manager.splitlines()[:12].count('set +xv'),1)
  for _ in range(15):manager=b.integrate(manager,'universal').decode()
  self.assertEqual(manager.splitlines()[:12].count('set +xv'),1)
  self.assertIn('# Managed by sbox-manager',manager.splitlines()[:12])
  current=(ROOT/'src/state.py').read_text();self.assertIn(current,manager)
  manager=manager.replace(current,'# deliberately stale common helper\n')
  updated=b.integrate(manager,'universal').decode()
  self.assertIn(current,updated);self.assertNotIn('# deliberately stale common helper',updated)
 def test_collector_restore_hooks_cover_templates_and_legacy_source(self):
  spec=importlib.util.spec_from_file_location('recovery_builder',ROOT/'tools/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
  source=(ROOT/'src/manager.sh').read_text()
  legacy=source.replace('@@COLLECTOR_RESTORE_PAUSE@@\n','').replace('@@COLLECTOR_RESTORE_RESUME@@\n','').replace('    accounting_start_ready\n','    python3 -B /usr/local/lib/sbox-accounting/current/accounting.py reconcile --inherited-lock >&2\n    systemctl enable --now sbox-accounting.service\n')
  for text in (source,legacy):
   manager=b.integrate(text,'universal').decode();again=b.integrate(manager,'universal').decode()
   for label in ('pause','resume'):
    hook=(ROOT/'src'/('collector_restore_'+label+'.inc')).read_text().rstrip('\n')
    self.assertEqual(manager.count(hook),1);self.assertEqual(again.count(hook),1)
   self.assertLess(manager.index("restore_attempt 'stop accounting"),manager.index("restore_attempt 'base tree'"))
   self.assertGreater(manager.index("restore_attempt 'accounting collector refresh'"),manager.index("restore_attempt 'VPN service restart'"))
   restore=manager[manager.index('restore_command()'):manager.index('renew_test_command()')]
   self.assertIn('    accounting_start_ready\n',restore);self.assertNotIn('enable --now sbox-accounting',restore)
 def test_private_variant_and_common_update_both_survive(self):
  spec=importlib.util.spec_from_file_location('private_merge',ROOT/'tools/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
  base='start\n'+''.join('stable line '+str(i)+'\n' for i in range(12))+'end\n'
  common=base.replace('start\n','updated common\n');variant=base.replace('end\n','private variant end\n')
  result=b.merge_helper(base,common,variant);self.assertIn('updated common',result);self.assertIn('private variant end',result)
  self.assertEqual(b.merge_helper(base,base,variant),variant)
 def test_original_document_hook_is_private_and_byte_exact(self):
  import base64,tempfile
  spec=importlib.util.spec_from_file_location('original_doc',ROOT/'tools/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
  value=b'# synthetic original\r\nproxies: []\r\n'
  text=(ROOT/'src/manager.sh').read_text().replace('@@WEBUI_INTEGRATION@@','@@WEBUI_INTEGRATION@@').replace('check_os() {','check_os() {')
  # A public fixture stands in for the old private platform guard.
  text=protected_template(text)
  manager=b.integrate(text,'zgocloud',legacy_yaml=value).decode()
  match=re.search(r"zgo_write_original_yaml\(\) \{.*?^\}",manager,re.M|re.S);self.assertIsNotNone(match)
  with tempfile.TemporaryDirectory() as td:
   target=Path(td)/'original.yaml';r=subprocess.run(['bash','-c',match[0]+'\nzgo_write_original_yaml \"$1\"','fixture',str(target)],capture_output=True)
   self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(target.read_bytes(),value);self.assertEqual(target.stat().st_mode&0o777,0o600)
  with self.assertRaises(ValueError):b.integrate((ROOT/'src/manager.sh').read_text(),'universal',legacy_yaml=value)
 def test_unrecognized_private_identity_guard_is_refused(self):
  spec=importlib.util.spec_from_file_location('strict_private_guard',ROOT/'tools/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
  with self.assertRaisesRegex(ValueError,'Protected identity guard not recognized'):
   b.integrate((ROOT/'src/manager.sh').read_text(),'zgocloud')
 def test_conflicting_private_variant_fails_without_disclosing_content(self):
  spec=importlib.util.spec_from_file_location('private_conflict',ROOT/'tools/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
  with self.assertRaises(ValueError) as ctx:b.merge_helper('base\n','common change\n','SYNTHETIC_PRIVATE_ONLY\n')
  self.assertNotIn('SYNTHETIC_PRIVATE_ONLY',str(ctx.exception))
if __name__=='__main__':unittest.main(verbosity=2)
