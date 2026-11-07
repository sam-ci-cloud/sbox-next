"""Public leak gate must inspect versioned URLs and nested installer assets."""
from pathlib import Path
import base64,gzip,io,json,subprocess,sys,tarfile,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
class Scan(unittest.TestCase):
 def check_scan(self,public,reference,state=None):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);tree=base/'public';tree.mkdir();(tree/'install.sh').write_bytes(public)
   (base/'owner.yaml').write_text('password: '+reference+'\n');(base/'manager').write_text('')
   args=[sys.executable,str(ROOT/'tools/scan_public.py'),'--root',str(tree),'--reference-yaml',str(base/'owner.yaml'),'--private-manager',str(base/'manager')]
   if state:
    (base/'state.json').write_text(json.dumps(state));args+=['--reference-state',str(base/'state.json')]
   result=subprocess.run(args,capture_output=True,text=True,timeout=30);self.assertEqual(result.returncode,1,result.stdout+result.stderr);self.assertNotIn(reference,result.stdout);self.assertEqual(json.loads(result.stdout)['leaking_paths'],['install.sh'])
 def test_versioned_url_reference_is_not_missed(self):
  url='https://example.test/sub/v1.'+'A'*43+'/global.yaml'
  self.check_scan(url.encode(),'unrelated-private-reference',{'exports':{'yaml':url}})
 def test_nested_runtime_payload_is_inspected(self):
  secret='synthetic-private-owner-value-2026';buf=io.BytesIO()
  with tarfile.open(fileobj=buf,mode='w:gz') as t:
   data=secret.encode();m=tarfile.TarInfo('backend/accidental.py');m.size=len(data);t.addfile(m,io.BytesIO(data))
  manager=b"blob=base64.b64decode('"+base64.b64encode(buf.getvalue())+b"')"
  installer=b"<<'SBOX_GENERIC_PAYLOAD'\n"+base64.b64encode(gzip.compress(manager))+b'\nSBOX_GENERIC_PAYLOAD\n'
  self.check_scan(installer,secret)
if __name__=='__main__':unittest.main()
