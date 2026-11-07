"""CLI front end for the same root controller transactions used by the panel.
Passwords enter through stdin or a protected file, never through argv.
"""
import argparse,json,os,subprocess,sys
from pathlib import Path
from common import require
from accounting import Engine

def change(request):
 def call(op,value):
  p=subprocess.run(['/usr/local/bin/sbox','_webui-control',op],input=json.dumps(value),capture_output=True,text=True)
  if p.returncode:raise SystemExit(p.stderr[-6000:])
  return json.loads(p.stdout)
 preview=call('prepare',request);print(json.dumps({'preview':preview},ensure_ascii=False),file=sys.stderr)
 result=call('commit',{'token':preview['token']});print(json.dumps(result,ensure_ascii=False))
def main():
 require(os.geteuid()==0,'Root required',403)
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('kind',choices=['quota','portal']);ap.add_argument('action',choices=['show','set','reset','pause','resume','topup','account','disable','policy','bulk']);ap.add_argument('id',nargs='?');ap.add_argument('--ids-file');ap.add_argument('--bytes');ap.add_argument('--period',choices=['none','daily','weekly','monthly']);ap.add_argument('--timezone');ap.add_argument('--reset-day',type=int);ap.add_argument('--expires-at',type=float);ap.add_argument('--username');ap.add_argument('--password-stdin',action='store_true');ap.add_argument('--password-file');ap.add_argument('--poll-seconds',type=int);ap.add_argument('--failure-policy',choices=['open','closed']);a=ap.parse_args()
 engine=Engine();state=engine.state()
 if a.action=='show':
  rows=[u for u in state.get('managed_users',[]) if not a.id or u['id']==a.id];print(json.dumps({'health':engine.health(),'users':[{'id':u['id'],'name':u['name'],'usage':engine.store().view(u,engine.health()),'portal':{k:v for k,v in u.get('portal',{}).items() if k in ('username','enabled','reset')}} for u in rows]},indent=2));return
 if a.action=='policy':
  require(a.kind=='quota' and not a.id,'Use quota policy without a user ID');data={k:v for k,v in {'poll_seconds':a.poll_seconds,'failure_policy':a.failure_policy}.items() if v is not None};change({'kind':'accounting-policy','data':data});return
 if a.action=='bulk':
  require(a.kind=='quota' and a.ids_file and not a.id,'Use quota bulk --ids-file PATH [plan options]');path=Path(a.ids_file);require(path.is_file() and path.stat().st_size<=65536,'Invalid IDs file');ids=path.read_text().split();plan={k:v for k,v in {'quota_bytes':a.bytes,'period':a.period,'timezone':a.timezone,'reset_day':a.reset_day,'expires_at':a.expires_at}.items() if v is not None};change({'kind':'quota-bulk','data':{'ids':ids,'plan':plan}});return
 require(a.id and a.id!='legacy' and any(u['id']==a.id for u in state.get('managed_users',[])),'Select an existing managed user ID')
 if a.kind=='portal':
  require(a.action in ('account','disable'),'Use portal account|disable ID');data={'enabled':a.action!='disable'}
  if a.username:data['username']=a.username
  require(not (a.password_stdin and a.password_file),'Use one password source')
  if a.password_file:
   path=Path(a.password_file);require(not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'Password file must be root-owned mode 0600');data['password']=path.read_text().rstrip('\r\n')
  if a.password_stdin:data['password']=sys.stdin.read(257).rstrip('\r\n')
  change({'kind':'portal-account','id':a.id,'data':data});return
 require(a.action in ('set','reset','pause','resume','topup'),'Invalid quota action');data={'action':a.action}
 if a.action=='topup':require(a.bytes is not None,'--bytes requires an explicit unit');data['topup_bytes']=a.bytes
 elif a.action=='set':
  data.update({k:v for k,v in {'quota_bytes':a.bytes,'period':a.period,'timezone':a.timezone,'reset_day':a.reset_day,'expires_at':a.expires_at}.items() if v is not None})
 change({'kind':'quota','id':a.id,'data':data})
if __name__=='__main__':main()
