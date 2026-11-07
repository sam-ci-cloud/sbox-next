"""Disable an actual added user; prove all five old credentials fail packets."""
import json,os,pathlib,subprocess,sys
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
out=pathlib.Path(sys.argv[1]);fixture=sys.argv[2];out.mkdir(parents=True,exist_ok=True)
path=pathlib.Path('/etc/sbox-manager/state.json');old=json.loads(path.read_text());user=next(u for u in old['managed_users'] if u['name']=='VMContractRenamed')
def change(kind,data):
    p=subprocess.run(['sbox','_webui-control','prepare'],input=json.dumps({'kind':kind,'data':data,'id':user['id']}),capture_output=True,text=True,check=True)
    token=json.loads(p.stdout)['token']
    subprocess.run(['sbox','_webui-control','commit'],input=json.dumps({'token':token}),capture_output=True,text=True,check=True)
change('user-disable',{})
try:
    p=subprocess.run(['python3','/tmp/packet_users.py',str(out),fixture,'disabled-user','expect-rejected'],capture_output=True,text=True,timeout=180)
    assert p.returncode==0,'Some disabled-user credentials were accepted or packet harness failed'
finally:change('user-edit',{'enabled':True})
assert old['protocols']==json.loads(path.read_text())['protocols']
(out/'revocation.json').write_text(json.dumps({'status':'PASS','protocols_rejected':5,'legacy_identity_unchanged':True},indent=2)+'\n')
print('Disabled user rejected across all five protocol transports; legacy credentials unchanged.')
