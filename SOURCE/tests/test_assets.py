"""Execute the actual emitted asset writer with adversarial embedded archives."""
import base64,gzip,hashlib,io,json,pathlib,re,subprocess,sys,tarfile,tempfile
root=pathlib.Path(__file__).resolve().parents[1]/'.build';manager=(root/'src/manager.sh').read_text();writer=manager[manager.index('write_webui_assets() {'):];writer=writer[:writer.index('\n}\n')+3]
encoded=re.search(r"blob=base64.b64decode\('([^']+)'",writer)[1];blob=base64.b64decode(encoded);sha=hashlib.sha256(blob).hexdigest();rows=[]
def check(name,source,success=False):
 with tempfile.TemporaryDirectory() as tmp:
  p=pathlib.Path(tmp);dest=p/'out';dest.mkdir();script=p/'writer';script.write_text(source+'\nwrite_webui_assets "$1"\n');r=subprocess.run(['bash',str(script),str(dest)],capture_output=True,text=True)
  assert (r.returncode==0)==success,(name,r.returncode,r.stderr[-300:]);assert not (p/'ESCAPE').exists()
  rows.append({'test':name,'status':'PASS'})
check('Original embedded runtime verifies and extracts',writer,True)
check('Truncated embedded bytes reject before extraction',writer.replace(encoded,base64.b64encode(blob[:-20]).decode()))
check('Changed embedded bytes reject SHA256',writer.replace(encoded,base64.b64encode(blob+b'x').decode()))
def archive(kind):
 b=io.BytesIO()
 with tarfile.open(fileobj=b,mode='w') as t:
  data=b'test';name={'traversal':'../ESCAPE','absolute':'/tmp/ESCAPE'}.get(kind,'frontend/test.txt')
  for i in range(2 if kind=='duplicate' else 1):
   m=tarfile.TarInfo(name);m.size=len(data)
   if kind=='link':m.type=tarfile.SYMTYPE;m.linkname='../ESCAPE';m.size=0;t.addfile(m)
   else:t.addfile(m,io.BytesIO(data))
  manifest={'frontend/test.txt':hashlib.sha256(b'wrong' if kind=='component' else data).hexdigest()}
  data=json.dumps(manifest).encode();m=tarfile.TarInfo('MANIFEST.json');m.size=len(data);t.addfile(m,io.BytesIO(data))
 return gzip.compress(b.getvalue(),mtime=0)
for kind in ['traversal','absolute','link','duplicate','component']:
 data=archive(kind);new=writer.replace(encoded,base64.b64encode(data).decode()).replace(sha,hashlib.sha256(data).hexdigest());check('Reject '+kind+' archive',new)
print(json.dumps({'runtime_sha256':sha,'results':rows},indent=2))
