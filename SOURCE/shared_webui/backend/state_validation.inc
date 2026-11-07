# Shared additive schema-2 users. Legacy credentials remain untouched.
client_dns=client_policy.get('dns',{})
require(isinstance(client_dns,dict) and set(client_dns)<= {'global','cn','bootstrap','proxy'},'invalid client DNS fields')
for _scope,_resolvers in client_dns.items():
    require(isinstance(_resolvers,list) and 1<=len(_resolvers)<=8,'DNS fields need 1–8 resolvers')
    for _resolver in _resolvers:
        require(isinstance(_resolver,str) and len(_resolver)<=512 and not re.search(r'[\x00-\x20\x7f\\]',_resolver),'invalid DNS resolver')
        try:ipaddress.ip_address(_resolver);_is_ip=True
        except ValueError:_is_ip=False
        if not _is_ip:
            require(_scope!='bootstrap','Bootstrap DNS must use IP literals')
            try:_url=urllib.parse.urlsplit(_resolver);_port=_url.port
            except ValueError:fail('invalid DNS resolver URL')
            try:ipaddress.ip_address(_url.hostname);_dns_host_valid=True
            except (ValueError,TypeError):_dns_host_valid=valid_domain(_url.hostname)
            require(_url.scheme=='https' and _dns_host_valid and not _url.username and not _url.password and not _url.fragment and (_port is None or 1<=_port<=65535),'DNS resolver must be a credential-free HTTPS URL or IP literal')
client_rules=client_policy.get('rules',[])
require(isinstance(client_rules,list) and len(client_rules)<=50,'At most 50 custom routing rules')
for _rule in client_rules:
    require(isinstance(_rule,str) and len(_rule)<=512,'invalid custom routing rule')
    _parts=_rule.split(',')
    require(len(_parts) in (3,4) and _parts[0] in ('DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','IP-CIDR','IP-CIDR6') and _parts[2] in ('DIRECT','REJECT','🚀 VPN'),'invalid routing rule type/action')
    if _parts[0] in ('IP-CIDR','IP-CIDR6'):
        try:_network=ipaddress.ip_network(_parts[1],strict=False)
        except ValueError:fail('invalid routing CIDR')
        require(_network.version==(6 if _parts[0]=='IP-CIDR6' else 4),'routing CIDR family mismatch')
        require(len(_parts)==3 or _parts[3]=='no-resolve','invalid CIDR rule option')
    else:
        require(len(_parts)==3,'invalid domain rule option')
        require(bool(re.fullmatch(r'[A-Za-z0-9._-]{1,253}',_parts[1])) and (_parts[0]=='DOMAIN-KEYWORD' or valid_domain(_parts[1])),'invalid routing domain')
managed_users = state.get('managed_users', [])
require(isinstance(managed_users, list) and len(managed_users) <= 1000, 'managed_users must contain at most 1000 users')
_ids, _names, _credentials = set(), set(), set()
for _user in managed_users:
    require(isinstance(_user, dict) and {'id','name','enabled','tags','protocols'} <= set(_user) <= {'id','name','enabled','tags','protocols','quota','portal'}, 'invalid managed user fields')
    require(isinstance(_user['id'], str) and re.fullmatch(r'[a-f0-9]{32}', _user['id']) and _user['id'] not in _ids, 'invalid/duplicate managed user id')
    _ids.add(_user['id'])
    require(isinstance(_user['name'], str) and re.fullmatch(r'[A-Za-z0-9._-]{1,64}', _user['name']) and _user['name'] not in _names, 'invalid/duplicate managed user name')
    _names.add(_user['name'])
    require(type(_user['enabled']) is bool and isinstance(_user['tags'], list) and len(_user['tags']) <= 10 and all(isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9._-]{1,32}',x) for x in _user['tags']), 'invalid managed user metadata')
    require(isinstance(_user['protocols'],dict) and _user['protocols'] and set(_user['protocols']) <= required_protocols, 'invalid managed user protocols')
    for _proto, _record in _user['protocols'].items():
        require(isinstance(_record,dict) and set(_record)=={'uuid','password'}, 'invalid managed credential fields')
        try: uuid.UUID(_record['uuid'])
        except Exception: fail('invalid managed user UUID')
        require(isinstance(_record['password'],str) and 24 <= len(_record['password']) <= 128, 'invalid managed password')
        for _field in ('uuid','password'):
            _value=_record[_field]
            require((_proto,_field,_value) not in _credentials and _value != protocols[_proto].get(_field), 'duplicate managed/legacy credentials')
            _credentials.add((_proto,_field,_value))

# ADDITIONAL QUOTA MODEL DEFINITIONS
"""Pure quota policy/calendar model, shared by manager validation and collector."""
import calendar
import datetime as _qd
from decimal import Decimal,InvalidOperation
import re as _qr
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError

QUOTA_KEYS={'quota_bytes','period','timezone','reset_day','expires_at','manual_disabled','reset_seq'}

def quota_size(value):
 if type(value) is int:
  if 0<=value<=10**15:return value
  raise ValueError('Quota must be between 0 (unlimited) and 1 PB')
 if not isinstance(value,str):raise ValueError('Use a byte integer or an explicit size such as 5 GiB')
 m=_qr.fullmatch(r'\s*(\d+(?:\.\d{1,6})?)\s*(B|KB|KiB|MB|MiB|GB|GiB|TB|TiB)\s*',value,_qr.I)
 if not m:raise ValueError('Size needs an explicit B/KB/KiB/MB/MiB/GB/GiB/TB/TiB unit')
 scale={'b':1,'kb':1000,'kib':1024,'mb':10**6,'mib':1024**2,'gb':10**9,'gib':1024**3,'tb':10**12,'tib':1024**4}[m[2].lower()];n=Decimal(m[1])*scale
 if n!=n.to_integral_value():raise ValueError('Quota must resolve to an integer number of bytes')
 return quota_size(int(n))

def quota_plan(value=None,base=None):
 if value is None:value={}
 if not isinstance(value,dict) or not set(value)<=QUOTA_KEYS:raise ValueError('Unknown quota field')
 result={'quota_bytes':0,'period':'monthly','timezone':'UTC','reset_day':1,'expires_at':0,'manual_disabled':False,'reset_seq':0}
 if base:result.update(base)
 result.update(value);result['quota_bytes']=quota_size(result['quota_bytes'])
 if result['period'] not in ('none','daily','weekly','monthly'):raise ValueError('Reset period must be none, daily, weekly or monthly')
 if not isinstance(result['timezone'],str) or len(result['timezone'])>64:raise ValueError('Invalid IANA timezone')
 try:ZoneInfo(result['timezone'])
 except (ZoneInfoNotFoundError,ValueError):raise ValueError('Unknown IANA timezone')
 if type(result['reset_day']) is not int or not 1<=result['reset_day']<=31:raise ValueError('Reset day must be 1–31')
 if result['period']=='weekly' and result['reset_day']>7:raise ValueError('Weekly reset day must be 1 (Monday)–7 (Sunday)')
 if type(result['expires_at']) not in (int,float) or not 0<=result['expires_at']<=4102444800:raise ValueError('Expiry must be a UTC Unix timestamp, or 0 for no expiry')
 if type(result['manual_disabled']) is not bool:raise ValueError('manual_disabled must be boolean')
 if type(result['reset_seq']) is not int or not 0<=result['reset_seq']<2**31:raise ValueError('Invalid reset sequence')
 return result

def quota_boundaries(now,plan):
 """Calendar reset boundaries in the configured IANA zone, returned as UTC epochs.
 Monthly anchor day is clamped per month, never progressively changed to Feb28.
 ZoneInfo's timestamp round trip chooses the first representable time after a
 missing local midnight; fold=0 chooses one occurrence for repeated midnights.
 """
 p=quota_plan(plan);zone=ZoneInfo(p['timezone']);dt=_qd.datetime.fromtimestamp(now,zone)
 def midnight(date):return _qd.datetime.combine(date,_qd.time(),zone).timestamp()
 if p['period']=='none':return (None,None)
 if p['period']=='daily':
  today=dt.date();return midnight(today),midnight(today+_qd.timedelta(days=1))
 if p['period']=='weekly':
  date=dt.date()-_qd.timedelta(days=(dt.isoweekday()-p['reset_day'])%7);return midnight(date),midnight(date+_qd.timedelta(days=7))
 def month(y,m):return midnight(_qd.date(y,m,min(p['reset_day'],calendar.monthrange(y,m)[1])))
 current=month(dt.year,dt.month)
 if now<current:
  y,m=(dt.year-1,12) if dt.month==1 else (dt.year,dt.month-1);return month(y,m),current
 y,m=(dt.year+1,1) if dt.month==12 else (dt.year,dt.month+1);return current,month(y,m)

def quota_status(user,used,now):
 p=quota_plan(user.get('quota'));expired=bool(p['expires_at'] and now>=p['expires_at']);exhausted=bool(p['quota_bytes'] and used is not None and used>=p['quota_bytes'])
 if not user.get('enabled',True) or p['manual_disabled']:return 'manually_disabled'
 if expired:return 'expired'
 if exhausted:return 'quota_exceeded'
 return 'active'

for _user in managed_users:
    if 'quota' in _user:
        try: _plan=quota_plan(_user['quota'])
        except ValueError as _err:fail(str(_err))
        require(_plan==_user['quota'],'quota plan must be canonical')
_portal_names=set()
for _user in managed_users:
    if 'portal' not in _user:continue
    _portal=_user['portal']
    require(isinstance(_portal,dict) and set(_portal)=={'username','password_hash','generation','enabled','reset'},'invalid portal account metadata')
    require(isinstance(_portal['username'],str) and re.fullmatch(r'[A-Za-z0-9._-]{1,64}',_portal['username']) and _portal['username'].casefold() not in _portal_names,'invalid/duplicate portal login')
    _portal_names.add(_portal['username'].casefold())
    require(isinstance(_portal['password_hash'],str) and re.fullmatch(r'scrypt\$32768\$8\$3\$[A-Za-z0-9+/=]{20,32}\$[A-Za-z0-9+/=]{40,100}',_portal['password_hash']),'invalid portal password hash')
    require(isinstance(_portal['generation'],str) and re.fullmatch(r'[A-Za-z0-9_-]{32,64}',_portal['generation']),'invalid portal credential generation')
    require(type(_portal['enabled']) is bool and type(_portal['reset']) is bool,'invalid portal flags')
_acct=state.get('accounting',{})
require(isinstance(_acct,dict) and set(_acct)<= {'enabled','port','poll_seconds','core_sha256','coverage','activated_at','failure_policy'},'invalid accounting config')
if _acct:
    require(type(_acct.get('enabled')) is bool and type(_acct.get('port')) is int and 1024<=_acct['port']<=65535,'invalid accounting endpoint')
    require(type(_acct.get('poll_seconds')) is int and 1<=_acct['poll_seconds']<=60,'invalid accounting polling interval')
    require(bool(re.fullmatch(r'[a-f0-9]{64}',str(_acct.get('core_sha256','')))),'accounting core provenance is required')
    require(_acct['port'] not in [v['port'] for v in protocols.values() if v['enabled']],'StatsService port overlaps a VPN listener')
    if _acct['enabled']:require(bool(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?',state['sing_box']['version'])),'Invalid accounting core version; binary provenance is enforced at commit')

if _acct:
    require(_acct.get('failure_policy','open') in ('open','closed'),'failure policy must be open or closed')
    require(isinstance(_acct.get('coverage'),dict) and set(_acct['coverage'])==required_protocols and all(v is True for v in _acct['coverage'].values()),'All five authenticated protocols must be validated')
    require(_acct['port']!=9443,'StatsService cannot use public WebUI port')
