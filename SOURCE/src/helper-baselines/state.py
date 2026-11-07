import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse
import uuid

try:
    import yaml
except Exception as exc:
    raise SystemExit(f"PyYAML is required: {exc}")

action, state_path, extra, cert_dir, manager_version, schema_s, minimum_version = sys.argv[1:8]
expected_schema = int(schema_s)

with open(state_path, 'r', encoding='utf-8') as fh:
    state = json.load(fh)
if not isinstance(state, dict) or type(state.get("schema")) is not int:
    raise SystemExit("invalid state: object with integer schema required")

def fail(message):
    raise SystemExit(f"invalid state: {message}")

def require(condition, message):
    if not condition:
        fail(message)

def valid_domain(value):
    if not isinstance(value, str) or len(value) > 253:
        return False
    labels = value.rstrip('.').split('.')
    if len(labels) < 2:
        return False
    rx = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
    return all(rx.fullmatch(label) for label in labels)

def parse_version(value):
    match = re.match(r'^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$', str(value))
    return tuple(map(int, match.groups())) if match else None

def migrate_v1(s):
    if s.get('schema') != 1:
        return s
    old_security = s.get('security') or {}
    old_firewall = s.get('firewall') or {}
    s['schema'] = expected_schema
    s['manager_version'] = manager_version
    s['firewall'] = {'enabled': old_firewall.get('mode', 'auto') != 'none'}
    s['security'] = {'block_private': not bool(old_security.get('allow_private_destinations', False))}
    s.setdefault('tuning', {'enabled': True})
    s['tuning'] = {'enabled': bool(s['tuning'].get('enabled', True))}
    protocols = s.setdefault('protocols', {})
    protocols.setdefault('hy2', {}).pop('up_mbps', None)
    protocols.setdefault('hy2', {}).pop('down_mbps', None)
    protocols.setdefault('tuic', {}).pop('udp_range', None)
    cert = s.setdefault('certificate', {})
    cert.setdefault('mode', 'existing')
    cert.setdefault('source_mode', 'external')
    cert.setdefault('source_fullchain', '')
    cert.setdefault('source_key', '')
    cert.setdefault('insecure', False)
    return s

MIGRATIONS = {1: migrate_v1}


def migrate(s):
    while s.get('schema') != expected_schema:
        current = s.get('schema')
        step = MIGRATIONS.get(current)
        if step is None:
            if isinstance(current, int) and current > expected_schema:
                raise SystemExit(f'state schema {current} was written by a newer sbox manager (this one speaks schema {expected_schema}).')
            raise SystemExit(f'no migration path from state schema {current} to {expected_schema}.')
        s = step(s)
    return s


if action == 'migrate':
    migrated = migrate(state)
    with open(extra, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(migrated, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
    os.chmod(extra, 0o600)
    raise SystemExit(0)

state = migrate(state)

require(isinstance(state, dict), 'top level must be an object')
require(state.get('schema') == expected_schema, f'schema must be {expected_schema}')
require(state.get('region') in {'global', 'cn'}, 'region must be global or cn')
require(valid_domain(state.get('domain')), 'domain is invalid')
require(re.fullmatch(r'[A-Za-z0-9._-]{1,64}', str(state.get('node_name', ''))) is not None, 'node_name is invalid')

server = state.get('server')
require(isinstance(server, dict), 'server object is missing')
require(server.get('listen') in {'0.0.0.0', '::'}, 'server.listen must be 0.0.0.0 or ::')
for key, family in (('ipv4', 4), ('ipv6', 6)):
    value = server.get(key, '')
    if value:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            fail(f'server.{key} is invalid')
        require(parsed.version == family, f'server.{key} has the wrong address family')

sb = state.get('sing_box')
require(isinstance(sb, dict), 'sing_box object is missing')
version = parse_version(sb.get('version'))
minimum = parse_version(minimum_version)
require(version is not None, 'sing_box.version is invalid')
require(minimum is not None, 'minimum sing-box version setting is invalid')
require(version >= minimum, f'sing_box.version must be >= {minimum_version}')
require(sb.get('channel') in {'stable', 'beta', 'fixed'}, 'sing_box.channel is invalid')

for section in ('firewall', 'tuning', 'security'):
    require(isinstance(state.get(section), dict), f'{section} object is missing')
require(isinstance(state['firewall'].get('enabled'), bool), 'firewall.enabled must be boolean')
require(isinstance(state['tuning'].get('enabled'), bool), 'tuning.enabled must be boolean')
require(isinstance(state['security'].get('block_private'), bool), 'security.block_private must be boolean')

protocols = state.get('protocols')
required_protocols = {'reality', 'vmess', 'hy2', 'tuic', 'anytls'}
require(isinstance(protocols, dict) and set(protocols) == required_protocols, 'protocol set is incomplete')
require(all(isinstance(protocols[name], dict) for name in required_protocols), 'protocols must be objects')
require(any(bool(protocols[name].get('enabled')) for name in required_protocols), 'at least one protocol must be enabled')

# Optional additive schema-2 field. Older states need no credential migration.
client_policy = state.get('client_policy', {'primary': 'tuic'})
require(isinstance(client_policy, dict), 'client_policy must be an object')
primary_protocol = client_policy.get('primary', 'tuic')
require(isinstance(primary_protocol, str) and primary_protocol in required_protocols, 'client_policy.primary is invalid')

health_url = client_policy.get('probe_url', 'https://www.gstatic.com/generate_204')
require(isinstance(health_url, str) and not re.search(r'[\x00-\x20\x7f\\]', health_url),
        'client probe URL must be a string without whitespace/control characters or backslashes')
try:
    parsed_probe = urllib.parse.urlsplit(health_url)
    probe_host = parsed_probe.hostname
    probe_port = parsed_probe.port
except (ValueError, TypeError):
    fail('client probe URL is malformed or has an invalid port')
require(parsed_probe.scheme == 'https' and bool(probe_host) and
        not parsed_probe.username and not parsed_probe.password and not parsed_probe.fragment and
        (probe_port is None or 1 <= probe_port <= 65535),
        'client probe URL must be credential-free HTTPS with a valid host/port and no fragment')
smart_lazy = client_policy.get('smart_lazy', False)
require(isinstance(smart_lazy, bool), 'client_policy.smart_lazy must be boolean')
# The stored fallback priority (client_policy.primary) is only a *preference*:
# the rendered groups always list enabled transports only. If the preferred
# protocol is currently disabled the preference is dormant, not invalid, so it
# is preserved across migrations and reconfigurations. The effective primary
# used for ordering and reported to callers is the preferred protocol when it
# is enabled, otherwise the first enabled protocol in the canonical order.
_effective_order = ['tuic', 'hy2', 'reality', 'anytls', 'vmess']
if isinstance(protocols.get(primary_protocol), dict) and protocols[primary_protocol].get('enabled'):
    effective_primary = primary_protocol
else:
    effective_primary = next((n for n in [primary_protocol] + _effective_order
                              if isinstance(protocols.get(n), dict) and protocols[n].get('enabled')), primary_protocol)


def valid_port(value):
    return type(value) is int and 1 <= value <= 65535 and value != 80

tcp_seen, udp_seen = {}, {}
for name in sorted(required_protocols):
    item = protocols[name]
    require(isinstance(item, dict), f'protocols.{name} must be an object')
    require(isinstance(item.get('enabled'), bool), f'protocols.{name}.enabled must be boolean')
    require(valid_port(item.get('port')), f'protocols.{name}.port is invalid or reserved')
    if item['enabled']:
        family_seen = udp_seen if name in {'hy2', 'tuic'} else tcp_seen
        if item['port'] in family_seen:
            fail(f'{name} shares its port with {family_seen[item["port"]]}')
        family_seen[item['port']] = name

try:
    uuid.UUID(protocols['reality'].get('uuid', ''))
except Exception:
    fail('protocols.reality.uuid is invalid')
require(valid_domain(protocols['reality'].get('sni')), 'protocols.reality.sni is invalid')
require(protocols['reality'].get('fingerprint') in {'chrome','firefox','edge','safari','ios','android','random','randomized'}, 'REALITY fingerprint is invalid')
require(isinstance(protocols['reality'].get('dest_port'), int) and 1 <= protocols['reality']['dest_port'] <= 65535, 'REALITY destination port is invalid')
require(re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', str(protocols['reality'].get('short_id', ''))) is not None, 'REALITY short_id must contain 1-8 bytes of even-length hex')
for field in ('private_key', 'public_key'):
    require(isinstance(protocols['reality'].get(field), str) and len(protocols['reality'][field]) >= 32, f'REALITY {field} is invalid')

try:
    uuid.UUID(protocols['vmess'].get('uuid', ''))
except Exception:
    fail('protocols.vmess.uuid is invalid')
vmess_path = str(protocols['vmess'].get('path', '')).lstrip('/')
require(re.fullmatch(r'[A-Za-z0-9._~-]{1,128}', vmess_path) is not None, 'VMess path is invalid')
require(isinstance(protocols['vmess'].get('tls'), bool), 'VMess tls must be boolean')
require(valid_domain(protocols['vmess'].get('sni')), 'VMess SNI is invalid')

require(isinstance(protocols['hy2'].get('password'), str) and len(protocols['hy2']['password']) >= 16, 'Hysteria2 password is too short')
raw_range = protocols['hy2'].get('udp_range', '')
require(isinstance(raw_range, str), 'Hysteria2 udp_range must be a string')
if raw_range:
    match = re.fullmatch(r'(\d{1,5}):(\d{1,5})', raw_range)
    require(match is not None, 'Hysteria2 udp_range must use start:end')
    start, end = map(int, match.groups())
    require(1 <= start < end <= 65535 and 10 <= end-start+1 <= 10000, 'Hysteria2 udp_range is invalid')
    require(not start <= protocols['hy2']['port'] <= end, 'Hysteria2 range includes its main port')
    require((not protocols['tuic']['enabled']) or not start <= protocols['tuic']['port'] <= end, 'Hysteria2 range includes the enabled TUIC main port')

try:
    uuid.UUID(protocols['tuic'].get('uuid', ''))
except Exception:
    fail('protocols.tuic.uuid is invalid')
require(isinstance(protocols['tuic'].get('password'), str) and len(protocols['tuic']['password']) >= 16, 'TUIC password is too short')
require(isinstance(protocols['anytls'].get('password'), str) and len(protocols['anytls']['password']) >= 16, 'AnyTLS password is too short')

certificate_needed = (
    (protocols['vmess']['enabled'] and protocols['vmess']['tls']) or
    protocols['hy2']['enabled'] or protocols['tuic']['enabled'] or protocols['anytls']['enabled']
)
cert = state.get('certificate')
require(isinstance(cert, dict), 'certificate object is missing')
require(cert.get('mode') in {'none','certbot-dns-cloudflare','certbot-http01','existing','self-signed'}, 'certificate.mode is invalid')
require(isinstance(cert.get('insecure'), bool), 'certificate.insecure must be boolean')
if certificate_needed:
    require(cert.get('mode') != 'none', 'enabled TLS protocols require a certificate')
    require(isinstance(cert.get('source_fullchain'), str) and cert['source_fullchain'].startswith('/'), 'certificate source_fullchain must be absolute')
    require(isinstance(cert.get('source_key'), str) and cert['source_key'].startswith('/'), 'certificate source_key must be absolute')

# BEGIN WEBUI USER VALIDATION
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
    if _acct['enabled']:require(state['sing_box']['version']=='1.13.14','This accounting adapter is validated for pinned 1.13.14 only')

if _acct:
    require(_acct.get('failure_policy','open') in ('open','closed'),'failure policy must be open or closed')
    require(isinstance(_acct.get('coverage'),dict) and set(_acct['coverage'])==required_protocols and all(v is True for v in _acct['coverage'].values()),'All five authenticated protocols must be validated')
    require(_acct['port']!=9443,'StatsService cannot use public WebUI port')

# END WEBUI USER VALIDATION

if action == 'validate':
    raise SystemExit(0)
if action == 'cert-needed':
    print('true' if certificate_needed else 'false')
    raise SystemExit(0)
if action == 'effective-primary':
    print(effective_primary)
    raise SystemExit(0)
if action != 'render':
    raise SystemExit(f'unknown state_tool action: {action}')

out = Path(extra)
out.mkdir(parents=True, exist_ok=True)

def dump_json(name, obj):
    target = out / name
    target.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.chmod(target, 0o600)

class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True

def dump_yaml(name, obj):
    target = out / name
    header = (
        f'# sbox {manager_version} - adaptive client policy\n'
        '# Fresh default: Anti-Block Auto uses ordered fallback across enabled transports.\n'
        '# Smart Auto is optional URL-test; LOCK pins one transport for long-lived applications.\n'
        '# Fallback affects new connections; it cannot migrate established flows or guarantee live calls.\n'
        '# One VPS/IP remains a shared failure point; health tests cannot detect every filtering rule.\n'
        '# Reimport/reload this YAML and select Anti-Block Auto; cached client choices may persist.\n'
        '# Smart Auto uses Mihomo reachability + HTTP delay tests; it is deterministic, not AI learning.\n'
        '# It cannot directly measure WhatsApp MOS, media packet loss or jitter from YAML alone.\n'
        '# Existing DNS, routing, credentials and protocol settings are preserved.\n'
    )
    target.write_text(header + yaml.dump(obj, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False, default_flow_style=False), encoding='utf-8')
    os.chmod(target, 0o600)

def quote(value):
    return urllib.parse.quote(str(value), safe='')

domain = state['domain']
node = state['node_name']
listen = state['server']['listen']
insecure = bool(cert.get('insecure', False))
p = protocols
# Preserve the effective R2/R3 layout for policy-only rendering. The optional
# eighth argument is the actual live config; only certificate paths are read
# from it. All other server fields are independently rendered and drift-checked.
service_cert = f'{cert_dir}/live/fullchain.pem'
service_key = f'{cert_dir}/live/privkey.pem'
if os.environ.get('SBOX_CERT_LAYOUT') != 'live':
    effective = sys.argv[8] if len(sys.argv) > 8 else ''
    pairs = set()
    if effective and Path(effective).is_file():
        live = json.loads(Path(effective).read_text())
        for inbound in live.get('inbounds', []):
            tls = inbound.get('tls', {})
            if 'certificate_path' in tls or 'key_path' in tls:
                pairs.add((tls.get('certificate_path'), tls.get('key_path')))
        allowed = {(f'{cert_dir}/fullchain.pem', f'{cert_dir}/privkey.pem'),
                   (service_cert, service_key)}
        require(len(pairs) <= 1 and pairs <= allowed, 'live TLS paths are inconsistent or outside managed certificate layouts')
        if pairs:
            service_cert, service_key = next(iter(pairs))
    elif (Path(cert_dir)/'fullchain.pem').is_file() and (Path(cert_dir)/'privkey.pem').is_file() and not (Path(cert_dir)/'live').exists():
        service_cert, service_key = f'{cert_dir}/fullchain.pem', f'{cert_dir}/privkey.pem'

# Server config: conservative protocol options and low-volume logging.
inbounds = []
if p['reality']['enabled']:
    r = p['reality']
    inbounds.append({
        'type': 'vless', 'tag': 'reality-in', 'listen': listen, 'listen_port': r['port'],
        'users': [{'name': 'reality', 'uuid': r['uuid'], 'flow': 'xtls-rprx-vision'}],
        'tls': {
            'enabled': True,
            'server_name': r['sni'],
            'reality': {
                'enabled': True,
                'handshake': {'server': r['sni'], 'server_port': r['dest_port']},
                'private_key': r['private_key'],
                'short_id': [r['short_id']],
            },
        },
    })
if p['vmess']['enabled']:
    v = p['vmess']; path = '/' + str(v['path']).lstrip('/')
    inbound = {
        'type': 'vmess', 'tag': 'vmess-ws-in', 'listen': listen, 'listen_port': v['port'],
        'users': [{'name': 'vmess', 'uuid': v['uuid'], 'alterId': 0}],
        'transport': {'type': 'ws', 'path': path},
    }
    if v['tls']:
        inbound['tls'] = {'enabled': True, 'certificate_path': service_cert, 'key_path': service_key}
    inbounds.append(inbound)
if p['hy2']['enabled']:
    h = p['hy2']
    inbounds.append({
        'type': 'hysteria2', 'tag': 'hy2-in', 'listen': listen, 'listen_port': h['port'],
        'users': [{'name': 'hy2', 'password': h['password']}],
        'ignore_client_bandwidth': True,
        'tls': {'enabled': True, 'alpn': ['h3'], 'certificate_path': service_cert, 'key_path': service_key},
    })
if p['tuic']['enabled']:
    t = p['tuic']
    inbounds.append({
        'type': 'tuic', 'tag': 'tuic-in', 'listen': listen, 'listen_port': t['port'],
        'users': [{'name': 'tuic', 'uuid': t['uuid'], 'password': t['password']}],
        'congestion_control': 'bbr',
        'zero_rtt_handshake': False,
        'tls': {'enabled': True, 'alpn': ['h3'], 'certificate_path': service_cert, 'key_path': service_key},
    })
if p['anytls']['enabled']:
    a = p['anytls']
    inbounds.append({
        'type': 'anytls', 'tag': 'anytls-in', 'listen': listen, 'listen_port': a['port'],
        'users': [{'name': 'anytls', 'password': a['password']}],
        'tls': {'enabled': True, 'certificate_path': service_cert, 'key_path': service_key},
    })

# BEGIN WEBUI USER RENDER
# Add independently authenticated clients to existing inbounds only.
_tags = {'reality-in':'reality','vmess-ws-in':'vmess','hy2-in':'hy2','tuic-in':'tuic','anytls-in':'anytls'}
for _inbound in inbounds:
    _proto = _tags[_inbound['tag']]
    for _user in managed_users:
        if not _user['enabled'] or _proto not in _user['protocols']: continue
        _record = _user['protocols'][_proto]
        _entry = {'name': 'user-' + _user['id'] + ('@'+_proto if state.get('accounting',{}).get('enabled') else '')}
        if _proto in ('reality','vmess','tuic'): _entry['uuid'] = _record['uuid']
        if _proto in ('hy2','tuic','anytls'): _entry['password'] = _record['password']
        if _proto == 'reality': _entry['flow'] = 'xtls-rprx-vision'
        if _proto == 'vmess': _entry['alterId'] = 0
        _inbound['users'].append(_entry)

# END WEBUI USER RENDER

route_rules = []
if state['security']['block_private']:
    route_rules.append({'ip_is_private': True, 'action': 'reject'})
server_config = {
    'log': {'level': 'warn', 'timestamp': True},
    'inbounds': inbounds,
    'outbounds': [{'type': 'direct', 'tag': 'direct'}],
    'route': {'rules': route_rules, 'final': 'direct'},
}
if state.get('accounting',{}).get('enabled'):
    server_config['experimental']={'v2ray_api':{'listen':'127.0.0.1:'+str(state['accounting']['port']),'stats':{'enabled':True,'users':sorted(set(u['name'] for inbound in inbounds for u in inbound.get('users',[])))}}}
dump_json('server.json', server_config)

mihomo_proxies = []
links = []
endpoint = domain

if p['reality']['enabled']:
    r = p['reality']; name = f'vless-reality-vision-{node}'
    params = urllib.parse.urlencode({
        'encryption': 'none', 'flow': 'xtls-rprx-vision', 'security': 'reality',
        'sni': r['sni'], 'fp': r['fingerprint'], 'pbk': r['public_key'],
        'sid': r['short_id'], 'type': 'tcp', 'headerType': 'none',
    })
    links.append(('VLESS REALITY', f"vless://{r['uuid']}@{endpoint}:{r['port']}?{params}#{quote(name)}"))
    mihomo_proxies.append({
        'name': name, 'type': 'vless', 'server': endpoint, 'port': r['port'], 'uuid': r['uuid'],
        'network': 'tcp', 'tls': True, 'udp': True, 'flow': 'xtls-rprx-vision',
        'servername': r['sni'], 'client-fingerprint': r['fingerprint'],
        'reality-opts': {'public-key': r['public_key'], 'short-id': r['short_id']},
    })

if p['vmess']['enabled']:
    v = p['vmess']; name = f'vmess-ws-{node}'; path = '/' + str(v['path']).lstrip('/')
    vmess_obj = {
        'v': '2', 'ps': name, 'add': endpoint, 'port': str(v['port']), 'id': v['uuid'],
        'aid': '0', 'scy': 'auto', 'net': 'ws', 'type': 'none', 'host': v['sni'],
        'path': path, 'tls': 'tls' if v['tls'] else '',
        'sni': v['sni'] if v['tls'] else '', 'fp': 'chrome' if v['tls'] else '',
    }
    encoded = base64.b64encode(json.dumps(vmess_obj, separators=(',', ':')).encode()).decode()
    links.append(('VMess WS TLS' if v['tls'] else 'VMess WS', 'vmess://' + encoded))
    proxy = {
        'name': name, 'type': 'vmess', 'server': endpoint, 'port': v['port'], 'uuid': v['uuid'],
        'alterId': 0, 'cipher': 'auto', 'udp': True, 'tls': bool(v['tls']), 'network': 'ws',
        'ws-opts': {'path': path, 'headers': {'Host': v['sni']}},
    }
    if v['tls']:
        proxy['servername'] = v['sni']
        proxy['client-fingerprint'] = 'chrome'
        proxy['skip-cert-verify'] = insecure
    mihomo_proxies.append(proxy)

if p['hy2']['enabled']:
    h = p['hy2']; name = f'hysteria2-{node}'
    params = {'security': 'tls', 'sni': domain, 'alpn': 'h3', 'insecure': '1' if insecure else '0'}
    if h.get('udp_range'):
        params['mport'] = h['udp_range'].replace(':', '-')
    links.append(('Hysteria2', f"hysteria2://{quote(h['password'])}@{endpoint}:{h['port']}/?{urllib.parse.urlencode(params)}#{quote(name)}"))
    proxy = {
        'name': name, 'type': 'hysteria2', 'server': endpoint, 'port': h['port'],
        'password': h['password'], 'sni': domain, 'alpn': ['h3'], 'skip-cert-verify': insecure,
    }
    if h.get('udp_range'):
        proxy['ports'] = h['udp_range'].replace(':', '-')
    mihomo_proxies.append(proxy)

if p['tuic']['enabled']:
    t = p['tuic']; name = f'tuic5-{node}'
    params = urllib.parse.urlencode({
        'congestion_control': 'bbr', 'udp_relay_mode': 'native', 'alpn': 'h3',
        'sni': domain, 'allow_insecure': '1' if insecure else '0',
    })
    links.append(('TUIC v5', f"tuic://{quote(t['uuid'])}:{quote(t['password'])}@{endpoint}:{t['port']}?{params}#{quote(name)}"))
    mihomo_proxies.append({
        'name': name, 'type': 'tuic', 'server': endpoint, 'port': t['port'], 'uuid': t['uuid'],
        'password': t['password'], 'alpn': ['h3'], 'udp-relay-mode': 'native',
        'congestion-controller': 'bbr', 'sni': domain, 'skip-cert-verify': insecure,
    })

if p['anytls']['enabled']:
    a = p['anytls']; name = f'anytls-{node}'
    params = urllib.parse.urlencode({'sni': domain, 'insecure': '1' if insecure else '0', 'fp': 'chrome'})
    links.append(('AnyTLS', f"anytls://{quote(a['password'])}@{endpoint}:{a['port']}?{params}#{quote(name)}"))
    mihomo_proxies.append({
        'name': name, 'type': 'anytls', 'server': endpoint, 'port': a['port'],
        'password': a['password'], 'client-fingerprint': 'chrome', 'udp': True,
        'sni': domain, 'skip-cert-verify': insecure,
    })

proxy_names = [proxy['name'] for proxy in mihomo_proxies]
if not proxy_names:
    raise SystemExit('no enabled protocols')

# Generate three explicit Clash Mi / Mihomo profiles plus one active alias.
# GLOBAL: only LAN/local traffic is DIRECT; everything else uses VPN.
# CN: LAN/local + CN GEOSITE/GEOIP are DIRECT; everything else uses VPN.
# INTERNAL: no bypass rules; every destination uses VPN.
default_nameservers = ['223.5.5.5', '119.29.29.29']
global_nameservers = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
cn_nameservers = ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
proxy_nameservers = ['https://223.5.5.5/dns-query', 'https://doh.pub/dns-query']
# health_url and smart_lazy were validated before every state action.

# Priority remains useful for failover/manual modes, but Smart Auto chooses by
# measured reachability and delay. Disabled protocols are omitted.
protocol_order = ['tuic', 'hy2', 'reality', 'anytls', 'vmess']
# Order by the *effective* primary (an enabled transport) so a dormant
# preference pointing at a disabled protocol never silently decides ordering.
protocol_order = [effective_primary] + [key for key in protocol_order if key != effective_primary]
protocol_type = {'tuic': 'tuic', 'hy2': 'hysteria2', 'reality': 'vless', 'anytls': 'anytls', 'vmess': 'vmess'}
ordered_names = [proxy['name'] for key in protocol_order for proxy in mihomo_proxies
                 if proxy['type'] == protocol_type[key]]

# Exactly three policies under the familiar VPN selector. Client-local cached
# choices may persist; reimport/reload and manual selection remain client actions.
smart_name = '🧠 Smart Auto'
stable_name = '🛡 Anti-Block Auto'
fixed_name = '🔒 LOCK'
vpn_group_name = '🚀 VPN'

proxy_groups = [
    {
        'name': stable_name,
        'type': 'fallback',
        'url': health_url,
        'interval': 60,
        'timeout': 5000,
        'expected-status': '204',
        'max-failed-times': 2,
        'lazy': False,
        'proxies': list(ordered_names),
    },
    {
        'name': smart_name,
        'type': 'url-test',
        'url': health_url,
        # Continuously sample every enabled transport. A 120 ms tolerance
        # deliberately favors stability over tiny benchmark wins.
        'interval': 60,
        'timeout': 5000,
        'expected-status': '204',
        'max-failed-times': 2,
        'tolerance': 120,
        'lazy': smart_lazy,
        'proxies': list(ordered_names),
    },
    {
        'name': fixed_name,
        'type': 'select',
        'default-selected': ordered_names[0],
        'proxies': list(ordered_names),
    },
    {
        'name': vpn_group_name,
        'type': 'select',
        # Raw transports are selected through LOCK.
        'default-selected': stable_name,
        'proxies': [stable_name, smart_name, fixed_name],
    },
]

lan_rules = [
    'DOMAIN-SUFFIX,lan,DIRECT',
    'DOMAIN-SUFFIX,local,DIRECT',
    'GEOIP,LAN,DIRECT,no-resolve',
]

def build_dns(profile):
    dns = {
        'enable': True,
        'listen': '127.0.0.1:1053',
        'ipv6': True,
        'prefer-h3': False,
        'respect-rules': True,
        'use-hosts': True,
        'use-system-hosts': True,
        'cache-algorithm': 'arc',
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        'fake-ip-filter-mode': 'blacklist',
        'fake-ip-filter': [
            '*.lan', '*.local',
            '+.msftconnecttest.com', '+.msftncsi.com',
            'localhost.ptlogin2.qq.com', 'localhost.sec.qq.com',
            '+.in-addr.arpa', '+.ip6.arpa',
            'time.*.com', 'time.*.gov', 'pool.ntp.org',
            'localhost.work.weixin.qq.com',
        ],
        'default-nameserver': list(default_nameservers),
        'nameserver': list(global_nameservers),
        # This resolves the VPN server hostname without creating a DNS loop.
        'proxy-server-nameserver': list(proxy_nameservers),
    }
    if profile == 'cn':
        dns['nameserver-policy'] = {'geosite:cn': list(cn_nameservers)}
        dns['direct-nameserver'] = list(cn_nameservers)
        dns['direct-nameserver-follow-policy'] = True
    # BEGIN WEBUI CLIENT DNS
    if 'global' in client_dns:dns['nameserver']=list(client_dns['global'])
    if 'bootstrap' in client_dns:dns['default-nameserver']=list(client_dns['bootstrap'])
    if 'proxy' in client_dns:dns['proxy-server-nameserver']=list(client_dns['proxy'])
    if profile=='cn' and 'cn' in client_dns:
        dns['nameserver-policy']={'geosite:cn':list(client_dns['cn'])}
        dns['direct-nameserver']=list(client_dns['cn'])

    # END WEBUI CLIENT DNS
    return dns

def build_mihomo(profile):
    # INTERNAL deliberately has no DIRECT rule. GLOBAL/CN retain their
    # original bypass policies and remain unchanged.
    rules = [] if profile == 'internal' else list(lan_rules)
    if profile == 'cn':
        rules.extend([
            'GEOSITE,CN,DIRECT',
            'GEOIP,CN,DIRECT,no-resolve',
        ])
    if profile != 'internal':rules=list(client_rules)+rules
    rules.append(f'MATCH,{vpn_group_name}')

    return {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'warning',
        'unified-delay': True,
        'tcp-concurrent': True,
        'profile': {
            'store-selected': True,
            'store-fake-ip': True,
        },
        'geodata-mode': True,
        'geo-auto-update': True,
        'geo-update-interval': 24,
        'dns': build_dns(profile),
        'proxies': mihomo_proxies,
        'proxy-groups': proxy_groups,
        'rules': rules,
    }

mihomo_global = build_mihomo('global')
mihomo_cn = build_mihomo('cn')
mihomo_internal = build_mihomo('internal')
active_mihomo = mihomo_cn if state['region'] == 'cn' else mihomo_global

# The clmi-* and internal names are compatibility aliases of the canonical
# mihomo-* profiles. Emitting them from one table keeps the name list in a
# single place and makes silent content drift between the names impossible.
for name, profile_data in (
    ('mihomo-global.yaml', mihomo_global),
    ('mihomo-cn.yaml', mihomo_cn),
    ('mihomo-internal.yaml', mihomo_internal),
    ('clmi-global.yaml', mihomo_global),
    ('clmi-cn.yaml', mihomo_cn),
    ('clmi-internal.yaml', mihomo_internal),
    ('internal.yaml', mihomo_internal),
    ('mihomo.yaml', active_mihomo),
    ('clmi.yaml', active_mihomo),
):
    dump_yaml(name, profile_data)

lines = [f'# sbox {manager_version}', f'# profile={state["region"].upper()} node={node} domain={domain}', '']
for label, link in links:
    lines.extend([f'[{label}]', link, ''])
(out / 'links.txt').write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
os.chmod(out / 'links.txt', 0o600)

dump_json('summary.json', {
    'manager_version': manager_version,
    'profile': state['region'].upper(),
    'node_name': node,
    'domain': domain,
    'sing_box_version': state['sing_box']['version'],
    'enabled_protocols': [name for name, cfg in p.items() if cfg['enabled']],
    'certificate_mode': cert.get('mode'),
    'certificate_insecure': insecure,
    'client_policy': {'primary': primary_protocol, 'effective_primary': effective_primary, 'primary_enabled': bool(protocols.get(primary_protocol, {}).get('enabled')), 'effective_order': ordered_names, 'default_group': stable_name, 'smart_auto': {'lazy': smart_lazy, 'interval': 60, 'timeout_ms': 5000, 'tolerance_ms': 120, 'max_failed_times': 2}, 'anti_block_auto': {'interval': 60, 'timeout_ms': 5000, 'max_failed_times': 2}},
})
