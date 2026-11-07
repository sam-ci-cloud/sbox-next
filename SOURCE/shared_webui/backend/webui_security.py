"""Owned WebUI jail using Fail2Ban's native IPv4/IPv6 nftables multiport action.
No SSH settings, foreign jails, global rulesets, credentials or allowlists change.
"""
from pathlib import Path
import ast,ipaddress,json,os,shutil,stat,subprocess,sys,tempfile,time
OWNER='# Managed by sbox-webui authentication protection'
JAIL=Path('/etc/fail2ban/jail.d/sbox-webui.local')
FILTER=Path('/etc/fail2ban/filter.d/sbox-webui.conf')
SETTINGS=Path('/etc/sbox-webui/settings.json')
NAME='sbox-webui'
TABLE='sbox_webui_f2b'
FAILREGEX=r'^SBOX_WEBUI_AUTH_FAILED ip=<ADDR> event=(?:login|rate-limit|portal)$'
def run(args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30,env={**os.environ,'LC_ALL':'C'},stdin=subprocess.DEVNULL)
 if check and p.returncode:raise RuntimeError('Command failed: '+args[0]+' (exit '+str(p.returncode)+'): '+p.stderr[-1500:])
 return p

def owned(path):
 for parent in path.parents:
  if parent.is_symlink():raise RuntimeError('Symlink ancestor in protection path')
 if path.exists() or path.is_symlink():
  s=path.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or not path.read_text().startswith(OWNER+'\n'):raise RuntimeError('Foreign or unsafe protection file: '+str(path))

def atomic(path,text,mode=0o600):
 path.parent.mkdir(parents=True,exist_ok=True)
 fd,name=tempfile.mkstemp(prefix='.sbox-webui-',dir=path.parent)
 try:
  with os.fdopen(fd,'w') as f:f.write(text);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
  os.replace(name,path)
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 finally:
  if os.path.exists(name):os.unlink(name)

def config(port):
 if type(port) is not int or not 1024<=port<=65535:raise ValueError('Invalid HTTPS management port')
 jail=f'''{OWNER}
[{NAME}]
enabled = true
backend = systemd
filter = sbox-webui
usedns = no
maxretry = 6
findtime = 600
bantime = 600
port = {port}
protocol = tcp
action = nftables[type=multiport, name=sbox-webui, port={port}, protocol=tcp, table={TABLE}, chain=sbox_webui_chain, chain_type=filter, chain_hook=input, chain_priority=-19, blocktype=drop]
'''
 filt=f'''{OWNER}
[INCLUDES]
before = common.conf
[Definition]
_daemon = python3
failregex = ^%(__prefix_line)s{FAILREGEX[1:]}
ignoreregex =
journalmatch = _SYSTEMD_UNIT=sbox-webui.service
'''
 return jail,filt

def commands():
 run(['fail2ban-client','-t'])
 rows=[ast.literal_eval(line) for line in run(['fail2ban-client','-d']).stdout.splitlines() if line.startswith('[')]
 ours=[x for x in rows if len(x)>1 and x[1]==NAME]
 if not any(x[:3]==['add',NAME,'systemd'] for x in ours):raise RuntimeError('WebUI jail backend is not systemd')
 # Later .local overrides must not turn arbitrary text into a bannable peer.
 patterns=[x[3:] for x in ours if x[:3]==['set',NAME,'addfailregex']]
 if len(patterns)!=1 or len(patterns[0])!=1 or not patterns[0][0].startswith('^') or not patterns[0][0].endswith(FAILREGEX[1:]):raise RuntimeError('WebUI filter has an unexpected effective expression')
 matches=[x[3:] for x in ours if x[:3]==['set',NAME,'addjournalmatch']]
 if matches!=[['_SYSTEMD_UNIT=sbox-webui.service']]:raise RuntimeError('WebUI journal source is not the trusted service')
 return ours

def client():
 from fail2ban.client.csocket import CSocket
 from fail2ban.client.configreader import ConfigReader
 reader=ConfigReader(basedir='/etc/fail2ban')
 if not reader.read('fail2ban'):raise RuntimeError('Fail2Ban daemon settings unavailable')
 return CSocket(reader.get('Definition','socket'))

def active():return run(['fail2ban-client','status',NAME],False).returncode==0

def ask(sock,args):
 reply=sock.send(args)
 if not isinstance(reply,(tuple,list)) or len(reply)!=2 or reply[0]!=0:raise RuntimeError('Guard query unavailable')
 return reply[1]

def action_properties(port):
 return {'type':'multiport','port':str(port),'protocol':'tcp','table':TABLE,'table_family':'inet','chain':'sbox_webui_chain','chain_type':'filter','chain_hook':'input','chain_priority':'-19','blocktype':'drop'}

def kernel_snapshot(port,bans):
 result={'status':'unknown','table':TABLE,'addresses':[],'missing_bans':[],'scope_verified':False}
 if not shutil.which('nft'):return result
 try:
  observed=run(['nft','-j','list','table','inet',TABLE],False)
  if observed.returncode:
   if 'No such file or directory' in observed.stderr:result['status']='idle' if bans==[] else 'missing' if bans else 'unknown'
   return result
  if len(observed.stdout)>1048576:return result
  rows=json.loads(observed.stdout)['nftables'];sets={};rules=[];chain_ok=False
  for row in rows:
   if 'chain' in row:
    chain=row['chain'];chain_ok|=chain.get('name')=='sbox_webui_chain' and chain.get('hook')=='input' and chain.get('type')=='filter' and chain.get('prio')==-19
   if 'set' in row:
    item=row['set']
    if item.get('name') in ('addr-set-'+NAME,'addr6-set-'+NAME) and item.get('type') in ('ipv4_addr','ipv6_addr'):
     sets[item['name']]=[]
     for value in item.get('elem',[]):
      if isinstance(value,dict) and 'elem' in value:value=value['elem'].get('val')
      if isinstance(value,str):sets[item['name']].append(ipaddress.ip_network(value,strict=False))
      elif isinstance(value,dict) and 'prefix' in value:sets[item['name']].append(ipaddress.ip_network(str(value['prefix']['addr'])+'/'+str(value['prefix']['len']),strict=False))
      else:raise ValueError('Unsupported guard set element')
   if 'rule' in row and row['rule'].get('chain')=='sbox_webui_chain':rules.append(row['rule'])
  guarded=set()
  for rule in rules:
   port_match=False;source_set=None;drop=False
   for expr in rule.get('expr',[]):
    if 'drop' in expr:drop=True
    match=expr.get('match',{});left=match.get('left',{});right=match.get('right')
    if match.get('op')!='==':continue
    if left=={'payload':{'protocol':'tcp','field':'dport'}} and right in (port,{'set':[port]}):port_match=True
    if left in ({'payload':{'protocol':'ip','field':'saddr'}},{'payload':{'protocol':'ip6','field':'saddr'}}) and isinstance(right,str) and right.startswith('@'):source_set=right[1:]
   if port_match and drop and source_set in sets:guarded.add(source_set)
  addresses=[str(network) for name in guarded for network in sets[name]]
  missing=[] if bans is None else [address for address in bans if not any(ipaddress.ip_address(address).version==network.version and ipaddress.ip_address(address) in network for name in guarded for network in sets[name])]
  result.update(status='ready' if chain_ok and guarded and not missing else 'drift',scope_verified=bool(chain_ok and guarded),addresses=addresses,missing_bans=missing)
 except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):pass
 return result

def snapshot():
 """Read-only local observations. A configured action is never a packet-path PASS."""
 result={'status':'warning','sampled_at':time.time(),'port':None,'protocol':'tcp','scope':'Admin and personal portal login only; not VPN authentication or SSH','configuration':{'status':'unknown'},'service':{'status':'unknown'},'jail':{'status':'unknown','name':NAME},'action':{'status':'unknown'},'kernel':{'status':'unknown'},'bans':{'status':'unknown','addresses':[]},'network_verification':{'status':'unknown','reason':'Independent remote ban/unban verification is required; local state cannot prove every network path.'}}
 try:
  port=json.loads(SETTINGS.read_text())['port'];expected=config(port);result['port']=port
  for path in (JAIL,FILTER):owned(path)
  result['configuration']['status']='missing' if not all(path.is_file() for path in (JAIL,FILTER)) else 'ok' if (JAIL.read_text(),FILTER.read_text())==expected else 'drift'
 except (OSError,ValueError,KeyError,TypeError,RuntimeError):result['configuration']['status']='unsafe'
 if not shutil.which('fail2ban-client'):
  result.update(status='unavailable',service={'status':'unavailable'},jail={'status':'unavailable','name':NAME});return result
 try:
  service=run(['systemctl','show','fail2ban.service','--property=ActiveState,LoadState'],False)
  values=dict(line.split('=',1) for line in service.stdout.splitlines() if '=' in line)
  result['service']['status']='unavailable' if values.get('LoadState')=='not-found' else values.get('ActiveState','unknown') if service.returncode==0 else 'unknown'
 except (OSError,subprocess.SubprocessError):pass
 bans=None;sock=None
 try:
  sock=client();ask(sock,['status',NAME]);result['jail']['status']='active'
  for field in ('maxretry','findtime','bantime'):
   value=ask(sock,['get',NAME,field])
   if type(value) is int and 0<=value<=31536000:result['jail'][field]=value
   if value!={'maxretry':6,'findtime':600,'bantime':600}[field]:result['jail']['status']='drift'
  values=ask(sock,['get',NAME,'banip'])
  if not isinstance(values,(list,tuple)) or len(values)>5000:raise ValueError('Invalid guard ban list')
  bans=sorted({str(ipaddress.ip_address(str(value))) for value in values});result['bans']={'status':'available','addresses':bans}
  actions=ask(sock,['get',NAME,'actions'])
  if actions!=['nftables']:result['action']['status']='drift'
  elif result['port'] is not None:
   properties={key:str(ask(sock,['get',NAME,'action','nftables',key])) for key in action_properties(result['port'])}
   journal=ask(sock,['get',NAME,'journalmatch'])
   valid=properties==action_properties(result['port']) and journal==[['_SYSTEMD_UNIT=sbox-webui.service']]
   result['action']={'status':'configured' if valid else 'drift','name':'nftables','port':result['port'],'protocol':'tcp','table':TABLE}
 except (ImportError,OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError):
  if result['jail']['status']!='active':result['jail']['status']='unavailable'
 finally:
  if sock is not None:sock.close()
 if result['port'] is not None:result['kernel']=kernel_snapshot(result['port'],bans)
 if result['configuration']['status']=='ok' and result['service']['status']=='active' and result['jail']['status']=='active' and result['action']['status']=='configured' and result['kernel']['status'] in ('ready','idle'):result['status']='ok'
 return result

def unban(address):
 address=str(ipaddress.ip_address(address))
 for path in (JAIL,FILTER):
  owned(path)
  if not path.is_file():raise RuntimeError('Owned WebUI protection files are missing')
 if not active():raise RuntimeError('WebUI jail is unavailable')
 run(['fail2ban-client','set',NAME,'unbanip',address])

def setup():
 for p in (JAIL,FILTER):owned(p)
 existed=JAIL.exists();was_active=active()
 if was_active and not (JAIL.exists() and FILTER.exists()):
  raise RuntimeError('Foreign active WebUI jail; owned configuration missing; no changes made')
 table=run(['nft','list','table','inet',TABLE],False)
 if table.returncode==0 and not (JAIL.exists() and FILTER.exists() and was_active):raise RuntimeError('Foreign/unclaimed WebUI nft table; no changes made')
 previous={p:(p.read_text(),p.stat().st_mode&0o777) if p.exists() else None for p in (JAIL,FILTER)}
 cfg=json.loads(SETTINGS.read_text());jail,filt=config(cfg['port']);changed=False
 try:
  atomic(FILTER,filt);atomic(JAIL,jail);parsed=commands()
  run(['systemctl','enable','--now','fail2ban.service'])
  for _ in range(40):
   if run(['fail2ban-client','ping'],False).returncode==0:break
   time.sleep(.1)
  if active():run(['fail2ban-client','reload',NAME]);changed=True
  else:
   sock=client()
   try:
    changed=True
    for command in parsed:
     reply=sock.send(command)
     if reply[0]!=0:raise RuntimeError('WebUI jail could not be applied')
   finally:sock.close()
  if not active():raise RuntimeError('WebUI jail did not become active')
 except Exception:
  if changed and not was_active and active():run(['fail2ban-client','stop',NAME])
  for p,old in previous.items():
   if old is None:p.unlink(missing_ok=True)
   else:atomic(p,*old)
  if changed and was_active:run(['fail2ban-client','reload',NAME])
  raise
 print('WebUI authentication Fail2Ban active: TCP '+str(cfg['port'])+' only, IPv4/IPv6; SSH and VPN ports unchanged.')

def remove():
 for p in (JAIL,FILTER):owned(p)
 if not any(p.exists() for p in (JAIL,FILTER)):return
 if active():run(['fail2ban-client','stop',NAME])
 for p in (JAIL,FILTER):p.unlink(missing_ok=True)

def main():
 if os.geteuid()!=0:raise RuntimeError('Root required')
 action=sys.argv[1] if len(sys.argv)>1 else 'status'
 if action=='setup':setup()
 elif action=='status':
  for p in (JAIL,FILTER):owned(p)
  if not JAIL.exists() or not FILTER.exists() or not active():raise RuntimeError('WebUI protection is not active')
  print(run(['fail2ban-client','status',NAME]).stdout)
 elif action=='remove':remove()
 elif action=='unban' and len(sys.argv)==3:unban(sys.argv[2])
 else:raise RuntimeError('Usage: webui_security.py setup|status|remove|unban IP')
if __name__=='__main__':
 try:main()
 except Exception as exc:print('WebUI protection failed: '+str(exc),file=sys.stderr);sys.exit(1)
