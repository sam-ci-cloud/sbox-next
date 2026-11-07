"""Network-only policy construction and observations. No user/credential edits.
The manager validates generated state with its original checker/transaction.
"""
import copy,ipaddress,json,os,socket,subprocess,sys,time
from pathlib import Path
PRESETS={'preserve':{'inbound':None,'egress':None,'dns':None,'client':None},'ipv4':dict.fromkeys(('inbound','egress','dns','client'),'ipv4'),'dual':{'inbound':'dual','egress':'dual','dns':'prefer_ipv4','client':'dual'},'ipv6':dict.fromkeys(('inbound','egress','dns','client'),'ipv6')}
CLEARABLE=frozenset({'endpoint_override','interface','fallback_delay_ms','udp_egress'})
def effective(server):return dict(server.get('policies') or PRESETS.get(server.get('mode','preserve'),{}))
def patch_state(state,patch):
 if not isinstance(patch,dict) or not patch or not set(patch)<= {'mode','policies','scope','interface','ipv4','ipv6','listen','endpoint_override','fallback_delay_ms','panel_family','udp_egress'}:raise ValueError('Unknown or empty network settings')
 if state.get('zgo_legacy_compat'):raise ValueError('Protected fixed endpoints retain their original network policy')
 result=copy.deepcopy(state);server=result['server']
 if 'mode' in patch and 'policies' not in patch:server.pop('policies',None)
 # Omitted key = unchanged. Explicit "" / null on a clearable field = remove the saved value.
 blank={k for k,v in patch.items() if v is None or v==''}
 if blank-CLEARABLE:raise ValueError('These network settings cannot be blank: '+', '.join(sorted(blank-CLEARABLE)))
 for key in blank:server.pop(key,None)
 server.update({k:v for k,v in patch.items() if k not in blank})
 if server.get('scope','legacy')=='legacy':server['scope']='public'
 if 'policies' in server and not isinstance(server['policies'],dict):raise ValueError('Advanced settings need all four network policies')
 mode=effective(server).get('inbound')
 if 'listen' not in patch:
  if mode=='ipv4':server['listen']='0.0.0.0'
  elif mode=='dual':server['listen']='::'
  elif mode=='ipv6':server['listen']=server.get('ipv6','')
 return result

def endpoint_options(state):
 s=state.get('server',{});mode=effective(s).get('inbound');listen=s.get('listen','0.0.0.0');modes=({4,6} if mode=='dual' else {6} if mode=='ipv6' else {4} if mode=='ipv4' else {4,6} if listen=='::' else {6} if ':' in listen else {4})
 choices=[{'id':'auto','address':state.get('domain','')},{'id':'domain','address':state.get('domain','')}]
 for family in sorted(modes):
  address=s.get('ipv'+str(family))
  if address:choices.append({'id':'ipv'+str(family),'address':address})
 if state.get('zgo_legacy_compat'):choices=choices[:1]
 return {'choices':choices,'policy':effective(s),'reachability':'Not externally verified','tls':'VPN TLS/REALITY SNI stays the configured domain. Subscription HTTPS uses its existing origin; choosing a VPN literal does not change the HTTPS certificate name.'}

def select_endpoint(state,choice):
 if choice not in {'auto','domain','ipv4','ipv6'}:raise ValueError('Choose automatic, domain, IPv4 or IPv6 endpoint')
 if choice not in {c['id'] for c in endpoint_options(state)['choices']}:raise ValueError('This endpoint family is not available on the configured VPN listeners')
 result=copy.deepcopy(state)
 if choice!='auto':result['server']['export_endpoint']=choice
 return result

def listen_for(server,mode):
 if mode=='ipv4':return '0.0.0.0'
 if mode=='dual':return '::'
 if mode=='ipv6':
  address=server.get('ipv6','');ip=ipaddress.ip_address(address)
  if ip.version!=6 or ip.is_unspecified or ip.is_multicast or ip.ipv4_mapped:raise ValueError('IPv6 HTTPS requires an assigned native IPv6 address')
  return address
 if mode=='preserve':return None
 raise ValueError('Invalid HTTPS family')

def observed(state,preflight):
 def cmd(args):
  try:r=subprocess.run(args,capture_output=True,text=True,timeout=4);return json.loads(r.stdout) if r.returncode==0 else []
  except (OSError,ValueError,subprocess.TimeoutExpired):return []
 interfaces=cmd(['ip','-j','address','show']);addresses=[]
 for i in interfaces:
  for a in i.get('addr_info',[]):
   try:p=ipaddress.ip_address(a['local'])
   except (ValueError,KeyError):continue
   addresses.append({'interface':i['ifname'],'address':str(p),'family':p.version,'global_unicast':p.is_global,'scope':a.get('scope'),'usable':not (a.get('tentative') or a.get('dadfailed'))})
 cfg={}
 try:cfg=json.loads(Path('/etc/sbox-webui/settings.json').read_text())
 except (OSError,ValueError):pass
 s=state['server'];return {'server':{k:s.get(k) for k in ('mode','policies','ipv4','ipv6','listen','scope','interface','endpoint_override','fallback_delay_ms','panel_family')},'domain':state.get('domain',''),'effective':effective(s),'addresses':addresses,'routes':{'ipv4':cmd(['ip','-j','-4','route','show','default']),'ipv6':cmd(['ip','-j','-6','route','show','default'])},'endpoint_preflight':preflight,'endpoints':endpoint_options(state),'https':{'listen':cfg.get('listen'),'port':cfg.get('port'),'origin':cfg.get('origin'),'policy':s.get('panel_family','preserve')},'observed_at':time.time(),'reachability':'Interface addresses, routes and DNS are observations; external/provider firewall reachability has not been proven.'}

def _system(*args):subprocess.run(args,check=True,capture_output=True,timeout=45)
def _write_settings(path,cfg):
 import tempfile
 old=path.stat();fd,n=tempfile.mkstemp(prefix='.network-',dir=path.parent)
 try:
  with os.fdopen(fd,'w') as f:json.dump(cfg,f);f.write('\n');f.flush();os.fchmod(f.fileno(),old.st_mode&0o777);os.fchown(f.fileno(),old.st_uid,old.st_gid);os.fsync(f.fileno())
  os.replace(n,path)
  d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:Path(n).unlink(missing_ok=True)
def panel_apply(state,settings=Path('/etc/sbox-webui/settings.json'),forced=None,active=None):
 if not settings.exists():return {'changed':False}
 if settings.is_symlink() or settings.stat().st_uid!=0:raise ValueError('Unsafe HTTPS settings file')
 old=json.loads(settings.read_text());listen=forced if forced is not None else listen_for(state['server'],state['server'].get('panel_family','preserve'))
 current_active=subprocess.run(['systemctl','is-active','--quiet','sbox-webui.service']).returncode==0
 if listen is None or (old['listen']==listen and (active is None or active==current_active)):return {'changed':False}
 ip=ipaddress.ip_address(listen)
 if not ip.is_unspecified:
  assigned=observed(state,{})['addresses']
  if not any(a['address']==str(ip) and a['usable'] for a in assigned):raise ValueError('HTTPS address is not assigned here')
 # Uninstall retains administrator settings but removes service units. During
 # fresh/reinstall this hook runs before WebUI installation. Stage only the
 # explicit family choice; the installer owns subsequent unit creation/start.
 unit=subprocess.run(['systemctl','show','sbox-webui.service','--property=LoadState','--value'],capture_output=True,text=True,timeout=15)
 if unit.stdout.strip()=='not-found' and unit.returncode in (0,1):
  if active is True:raise ValueError('Cannot restore an active HTTPS service without its installed unit')
  _write_settings(settings,{**old,'listen':listen})
  return {'changed':True,'listen':listen,'deferred_activation':True}
 if unit.returncode or unit.stdout.strip() not in ('loaded','masked'):
  raise ValueError('Cannot establish HTTPS unit state; no settings changed')
 was_active=current_active if active is None else active
 def publish(cfg):
  _system('systemctl','stop','sbox-webui.service')
  _write_settings(settings,cfg);_system('systemctl','restart','sbox-webui-firewall.service')
  if was_active:
   _system('systemctl','start','sbox-webui.service')
   for family,host in ([(4,'127.0.0.1'),(6,'::1')] if cfg['listen']=='::' else [(ip.version,{'0.0.0.0':'127.0.0.1'}.get(cfg['listen'],cfg['listen']))]):
    for _ in range(100):
     try:
      with socket.create_connection((host,cfg['port']),timeout=.2):break
     except OSError:time.sleep(.1)
    else:raise ValueError('HTTPS listener health failed after family change')
 try:publish({**old,'listen':listen})
 except Exception:
  publish(old);raise
 return {'changed':True,'listen':listen}

def snapshot_panel(destination):
 root=Path(destination);root.mkdir(parents=True,exist_ok=True,mode=0o700);settings=Path('/etc/sbox-webui/settings.json')
 if settings.is_file() and not settings.is_symlink():
  data={'listen':json.loads(settings.read_text())['listen'],'active':subprocess.run(['systemctl','is-active','--quiet','sbox-webui.service']).returncode==0};p=root/'webui-network.json';p.write_text(json.dumps(data));p.chmod(0o600)
def restore_panel(state,destination):
 p=Path(destination)/'webui-network.json'
 if p.exists():
  record=json.loads(p.read_text());panel_apply(state,forced=record['listen'],active=record['active'])

if __name__=='__main__':
 try:
  action=sys.argv[1];state=json.loads(Path(sys.argv[2]).read_text()) if Path(sys.argv[2]).exists() else {'server':{}}
  if action=='patch':result=patch_state(state,json.loads(Path(sys.argv[3]).read_text()));Path(sys.argv[4]).write_text(json.dumps(result));Path(sys.argv[4]).chmod(0o600)
  elif action=='report':print(json.dumps(observed(state,json.loads(Path(sys.argv[3]).read_text()))))
  elif action=='panel-apply':print(json.dumps(panel_apply(state)))
  elif action=='snapshot':snapshot_panel(sys.argv[3])
  elif action=='restore':restore_panel(state,sys.argv[3])
  else:raise ValueError('Unknown network operation')
 except (ValueError,KeyError,OSError,subprocess.SubprocessError) as e:raise SystemExit('Network configuration: '+str(e))
