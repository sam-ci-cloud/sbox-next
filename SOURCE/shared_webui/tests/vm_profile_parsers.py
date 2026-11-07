"""All three personal profiles through real Mihomo and pinned native parsers."""
from pathlib import Path
import os,json,subprocess,shutil,sys,time
assert os.geteuid()==0 and Path('/root/lab-ready').is_file();os.umask(0o077)
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True);s=json.loads(Path('/etc/sbox-manager/state.json').read_text());uid=next(u['id'] for u in s['managed_users'] if u['enabled']);rows=[]
for profile in ['global','cn','internal']:
 d=out/profile;d.mkdir(exist_ok=True);shutil.copyfile('/tmp/Country.mmdb',d/'Country.mmdb')
 for fmt in ['yaml','json']:
  p=subprocess.run(['sbox','_webui-control','export'],input=json.dumps({'id':uid,'profile':profile,'format':fmt}),capture_output=True,text=True,check=True);f=d/('config.'+fmt);f.write_text(p.stdout)
  args=['/tmp/mihomo','-t','-d',str(d),'-f',str(f)] if fmt=='yaml' else ['/usr/local/lib/sbox-manager/sing-box','check','-c',str(f)]
  r=subprocess.run(args,capture_output=True,text=True,timeout=120);(d/(fmt+'-private.log')).write_text(r.stdout+r.stderr);rows.append({'profile':profile,'format':fmt,'status':'PASS' if r.returncode==0 else 'FAIL'});assert r.returncode==0,'Parser failed: '+profile+fmt
(out/'profile-parsers.json').write_text(json.dumps(rows,indent=2));print('PASS GLOBAL CN INTERNAL profiles: real Mihomo and sing-box parsers')
