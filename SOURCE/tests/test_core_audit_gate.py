import importlib.util,io,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('resolver',ROOT/'shared_webui/backend/core_resolver.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class CoreAuditGate(unittest.TestCase):
 def audit(self,go_report,module_vulns=False):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'go.mod').write_text('module example.test/core\nrequire example.test/module v1.0.0\n');binary=root/'sing-box';binary.write_bytes(b'synthetic')
   result={'results':[{'vulns':[{'id':'TEST-VULN'}]} if module_vulns else {}]}
   with patch.object(r.urllib.request,'urlopen',return_value=io.BytesIO(json.dumps(result).encode())),patch.object(r,'run') as run,patch.object(r.subprocess,'run',return_value=subprocess.CompletedProcess([],0,go_report,'')):
    with (root/'log').open('w') as log:return r.audit_source_and_binary(root,binary,root,'test-go',{},log)
 def test_empty_object_is_not_a_successful_binary_scan(self):
  with self.assertRaises(ValueError):self.audit('{}')
 def test_findings_cannot_be_ignored(self):
  report=json.dumps({'config':{'scan_mode':'binary','scanner_name':'govulncheck'}})+'\n'+json.dumps({'finding':{'osv':'TEST-VULN'}})
  with self.assertRaises(ValueError):self.audit(report)
 def test_module_advisories_reject_before_binary_scan(self):
  with self.assertRaises(ValueError):self.audit('',True)
 def test_floors_do_not_downgrade_newer_dependencies(self):
  raw='\n'.join(json.dumps({'Path':p,'Version':v}) for p,v in [('google.golang.org/grpc','v1.90.0'),('github.com/go-chi/chi/v5','v5.5.0')])
  with patch.object(r.subprocess,'check_output',return_value=raw),patch.object(r,'run') as command:
   self.assertEqual(r.apply_security_floors(Path('.'),'go',{},None),[]);command.assert_not_called()
 def test_floors_update_only_old_versions(self):
  raw='\n'.join(json.dumps({'Path':p,'Version':v}) for p,v in [('google.golang.org/grpc','v1.79.1'),('github.com/go-chi/chi/v5','v5.5.0')])
  with patch.object(r.subprocess,'check_output',return_value=raw),patch.object(r,'run') as command:
   self.assertEqual(r.apply_security_floors(Path('.'),'go',{},None),['google.golang.org/grpc@v1.83.2']);self.assertIn('google.golang.org/grpc@v1.83.2',command.call_args.args[0]);self.assertNotIn('github.com/go-chi/chi/v5@v5.4.0',command.call_args.args[0])
if __name__=='__main__':unittest.main(verbosity=2)
