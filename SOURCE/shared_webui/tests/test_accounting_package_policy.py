"""Accounting staging must not restart unrelated VPS services through apt hooks."""
import ast,pathlib,unittest,subprocess,sys,tempfile,shutil
class Policy(unittest.TestCase):
 def test_isolated_installed_runtime_imports_all_dependencies(self):
  root=pathlib.Path(__file__).parents[1]/'backend';tree=ast.parse((root/'accounting_install.py').read_text())
  files=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='FILES' for t in n.targets))
  with tempfile.TemporaryDirectory() as tmp:
   for name in files:shutil.copyfile(root/name,pathlib.Path(tmp)/name)
   result=subprocess.run([sys.executable,'-I','-B','-c','import sys;sys.path.insert(0,sys.argv[1]);import accounting,portal_auth,accounting_restore,accounting_install',tmp],capture_output=True,text=True,timeout=30)
   self.assertEqual(result.returncode,0,result.stderr)
 def test_apt_is_unattended_and_keeps_foreign_services_running(self):
  tree=ast.parse((pathlib.Path(__file__).parents[1]/'backend/accounting_install.py').read_text())
  calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='run' and n.args and isinstance(n.args[0],ast.List) and any(isinstance(x,ast.Constant) and x.value=='apt-get' for x in n.args[0].elts)]
  self.assertEqual(len(calls),1)
  values={x.arg:ast.unparse(x.value) for x in calls[0].keywords}
  self.assertIn("'NEEDRESTART_MODE': 'l'",values.get('env',''))
  self.assertIn("'DEBIAN_FRONTEND': 'noninteractive'",values.get('env',''))
  self.assertEqual(values.get('stdin'),'subprocess.DEVNULL')
  self.assertIn('DPkg::Lock::Timeout=300',ast.unparse(calls[0].args[0]))
  self.assertEqual(values.get('timeout'),'600')
 def test_upgrade_preserves_verified_other_accounting_version(self):
  import hashlib,json
  sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/'backend'))
  from accounting_install import verify_installed_core
  from common import Problem
  with tempfile.TemporaryDirectory() as tmp:
   core=pathlib.Path(tmp)/'sing-box';raw=bytearray(64);raw[:6]=b'\x7fELF\x02\x01';raw[18:20]=(62).to_bytes(2,'little');core.write_bytes(raw)
   state={'sing_box':{'version':'1.13.14'},'accounting':{'enabled':True,'core_sha256':hashlib.sha256(raw).hexdigest(),'coverage':{p:True for p in ('reality','vmess','hy2','tuic','anytls')}}}
   verify_installed_core(state,{'version':'1.14.2'},core)
   core.write_bytes(raw+b'tampered')
   with self.assertRaises(Problem):verify_installed_core(state,{'version':'1.14.2'},core)
   core.write_bytes(raw);state['accounting']['coverage']['tuic']=False
   with self.assertRaises(Problem):verify_installed_core(state,{'version':'1.14.2'},core)
   state['accounting']['enabled']=False
   with self.assertRaises(Problem):verify_installed_core(state,{'version':'1.14.2'},core)
 def test_product_upgrade_moves_enabled_accounting_to_staged_engine(self):
  # 1.2.0 regression: an enabled install must be able to activate a newer
  # verified bundled engine; first activation still needs the exact version.
  import hashlib,json
  sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/'backend'))
  import accounting_install as ai
  from common import Problem
  def elf(tag):
   raw=bytearray(64);raw[:6]=b'\x7fELF\x02\x01';raw[18:20]=(62).to_bytes(2,'little');return bytes(raw)+tag
  with tempfile.TemporaryDirectory() as tmp:
   tmp=pathlib.Path(tmp);(tmp/'lib/current').mkdir(parents=True);(tmp/'etc').mkdir()
   old,new=elf(b'old'),elf(b'new')
   (tmp/'installed').write_bytes(old);(tmp/'lib/core-candidate').write_bytes(new)
   (tmp/'lib/current/core_manifest.json').write_text(json.dumps({'version':'1.14.4','sha256':hashlib.sha256(new).hexdigest()}))
   cov={p:True for p in ('reality','vmess','hy2','tuic','anytls')}
   saved=(ai.LIB,ai.BASE,ai.INSTALLED)
   ai.LIB,ai.BASE,ai.INSTALLED=tmp/'lib',tmp/'etc',tmp/'installed'
   try:
    (tmp/'etc/state.json').write_text(json.dumps({'sing_box':{'version':'1.14.2','channel':'fixed'},'accounting':{'enabled':True,'port':25001,'core_sha256':hashlib.sha256(old).hexdigest(),'coverage':cov}}))
    ai.candidate(tmp/'out.json');out=json.loads((tmp/'out.json').read_text())
    self.assertEqual(out['sing_box'],{'version':'1.14.4','channel':'fixed'})
    self.assertEqual(out['accounting']['core_sha256'],hashlib.sha256(new).hexdigest())
    # Tampered installed core: the forward move is refused.
    (tmp/'installed').write_bytes(old+b'x')
    with self.assertRaises(Problem):ai.candidate(tmp/'out2.json')
    # Initial activation with a different version stays refused.
    (tmp/'etc/state.json').write_text(json.dumps({'sing_box':{'version':'1.14.2','channel':'fixed'}}))
    with self.assertRaises(Problem):ai.candidate(tmp/'out3.json')
   finally:
    ai.LIB,ai.BASE,ai.INSTALLED=saved

if __name__=='__main__':unittest.main()
