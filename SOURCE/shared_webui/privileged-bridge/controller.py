"""Called only by the existing manager while holding its original lock.

Candidate construction never writes the live state/config. The shell manager
validates/renders/checks and commits using its existing transaction journal.
"""
import copy
import difflib
import json
from pathlib import Path
import re
import secrets
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from common import Problem, PROTOCOLS, clean_name, redact, require, password_hash, token
from network_policy import patch_state, select_endpoint, effective
from quota_models import quota_plan, quota_size, QUOTA_KEYS


def quota_change(user,data):
    require(isinstance(data,dict) and set(data)<= (QUOTA_KEYS-{'reset_seq'})|{'action','topup_bytes'},'Invalid quota change')
    action=data.get('action','set');require(action in ('set','reset','pause','resume','topup'),'Invalid quota action')
    plan=quota_plan(user.get('quota'))
    if action=='reset':
        require(set(data)=={'action'},'Reset accepts no extra fields');
        import sqlite3
        path=Path('/var/lib/sbox-accounting/usage.db')
        if path.exists():
            db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)
            try:
                row=db.execute('SELECT reset_seq FROM totals WHERE user_id=?',(user['id'],)).fetchone()
                if row:plan['reset_seq']=max(plan['reset_seq'],row[0])
            finally:db.close()
        plan['reset_seq']+=1
    elif action in ('pause','resume'):
        require(set(data)=={'action'},'Pause/resume accepts no extra fields');plan['manual_disabled']=action=='pause'
    elif action=='topup':
        require(set(data)=={'action','topup_bytes'} and plan['quota_bytes']>0,'Top up an existing limited plan');extra=quota_size(data['topup_bytes']);require(extra>0,'Top up must be positive');plan['quota_bytes']=quota_size(plan['quota_bytes']+extra)
    else:plan=quota_plan({k:v for k,v in data.items() if k!='action'},plan)
    user['quota']=quota_plan(plan)

def portal_change(user,data,users):
    require(isinstance(data,dict) and set(data)<= {'username','password','enabled','reset'},'Unknown portal account field')
    portal=dict(user.get('portal',{}))
    if 'username' in data:
        name=clean_name(data['username']);require(name.casefold() not in ('admin','root','reader'),'Choose a distinct portal login name');require(not any(u['id']!=user['id'] and u.get('portal',{}).get('username','').casefold()==name.casefold() for u in users),'Portal login already exists',409);portal['username']=name
    require(portal.get('username'),'Portal username is required')
    if 'password' in data:
        password=data['password'];require(all(password not in (v.get('uuid'),v.get('password')) for v in user['protocols'].values()),'Portal password must differ from VPN credentials');portal['password_hash']=password_hash(password);portal['generation']=token();portal['reset']=True
    require(portal.get('password_hash') and portal.get('generation'),'Initial portal password is required')
    if 'enabled' in data:
        require(type(data['enabled']) is bool,'Portal enabled must be boolean')
        if portal.get('enabled')!=data['enabled']:portal['generation']=token()
        portal['enabled']=data['enabled']
    portal.setdefault('enabled',True)
    if 'reset' in data:require(type(data['reset']) is bool,'Portal reset must be boolean');portal['reset']=data['reset']
    user['portal']=portal

def candidate(state, request, variant):
    require(isinstance(request, dict) and set(request) <= {'kind', 'data', 'id'}, 'Invalid change request')
    result = copy.deepcopy(state)
    kind, data, ident = request.get('kind'), request.get('data', {}), request.get('id')
    require(isinstance(data, dict), 'Change data must be an object')
    if kind == 'inbounds':
        require(variant == 'universal', 'Legacy listener identity is protected', 403)
        require(set(data) <= set(PROTOCOLS), 'Unknown protocol')
        for proto, fields in data.items():
            allowed = {'enabled', 'port'} | ({'multiplex'} if proto == 'vmess' else set())
            require(isinstance(fields, dict) and set(fields) <= allowed, 'Only enabled, port and VMess connection reuse can be edited here')
            for key, value in fields.items():
                require(type(value) is (int if key == 'port' else bool), 'Invalid listener field type')
                result['protocols'][proto][key] = value
    elif kind == 'network':
        require(variant=='universal','Protected network identity is locked',403)
        try:result=patch_state(state,data)
        except ValueError as e:raise Problem(422,str(e))
    elif kind == 'policy':
        require(set(data) <= {'primary', 'smart_lazy', 'probe_url', 'expected_status', 'smart_tolerance_ms', 'default_group', 'health_interval_s', 'health_timeout_ms', 'health_max_failed', 'dns', 'rules', 'rule_precedence'}, 'Unknown policy setting')
        require('health_interval_s' not in data or type(data['health_interval_s']) is int and 30<=data['health_interval_s']<=600, 'Health-check interval must be30–600s')
        require('health_timeout_ms' not in data or type(data['health_timeout_ms']) is int and 1000<=data['health_timeout_ms']<=10000, 'Probe timeout must be1000–10000ms')
        require('health_max_failed' not in data or type(data['health_max_failed']) is int and 1<=data['health_max_failed']<=5, 'Failed connections before re-check must be1–5')
        require('default_group' not in data or type(data['default_group']) is str and data['default_group'] in ('anti_block', 'smart'), 'Default group must be anti_block or smart')
        require('primary' not in data or data['primary'] in PROTOCOLS, 'Invalid primary')
        require('smart_lazy' not in data or type(data['smart_lazy']) is bool, 'Invalid probe mode')
        require('rule_precedence' not in data or data['rule_precedence'] in ('lan_first', 'custom_first'), 'Local network rule order must be lan_first or custom_first')
        require('expected_status' not in data or type(data['expected_status']) is str and data['expected_status'] in ('200','204','200/204'),'Expected HTTP must be200,204 or200/204')
        require('smart_tolerance_ms' not in data or type(data['smart_tolerance_ms']) is int and 10<=data['smart_tolerance_ms']<=300,'Tolerance must be10–300ms')
        result.setdefault('client_policy', {}).update(data)
    elif kind == 'users-import':
        require(set(data)<= {'names','tags'} and isinstance(data.get('names'),list) and 1<=len(data['names'])<=100,'Batch creation accepts 1–100 names')
        for name in data['names']:
            result=candidate(result,{'kind':'user-create','data':{'name':name,'tags':data.get('tags',[])}},variant)
    elif kind == 'users-bulk':
        # One validated transaction (one core restart) for many explicit IDs.
        require(set(data) == {'action', 'ids'} and data.get('action') in ('disable', 'enable', 'revoke'), 'Bulk action must be disable, enable or revoke')
        ids = data['ids']
        require(isinstance(ids, list) and 1 <= len(ids) <= 1000 and all(isinstance(i, str) for i in ids), 'Select 1–1000 users')
        require('legacy' not in ids, 'The protected original identity cannot be changed in bulk', 403)
        require(len(set(ids)) == len(ids), 'Duplicate user IDs in selection')
        users = result.setdefault('managed_users', [])
        known = {u['id'] for u in users}
        unknown = [i for i in ids if i not in known]
        require(not unknown, 'Unknown user ID(s): ' + ', '.join(i[:8] for i in unknown[:5]), 404)
        selected = set(ids)
        if data['action'] == 'revoke':
            result['managed_users'] = [u for u in users if u['id'] not in selected]
        else:
            for u in users:
                if u['id'] in selected:
                    u['enabled'] = data['action'] == 'enable'
    elif kind=='quota-bulk':
        require(state.get('accounting',{}).get('enabled'),'Enable verified accounting first',409)
        require(set(data)=={'ids','plan'} and isinstance(data['ids'],list) and 1<=len(data['ids'])<=1000 and all(isinstance(i,str) for i in data['ids']) and len(set(data['ids']))==len(data['ids']),'Select 1–1000 unique managed IDs')
        selected=set(data['ids']);require('legacy' not in selected,'Protected shared identity cannot receive quotas',403)
        users=result.get('managed_users',[]);require(selected<={u['id'] for u in users},'Unknown user',404)
        for user in users:
            if user['id'] in selected:quota_change(user,data['plan'])
    elif kind=='accounting-policy':
        require(result.get('accounting',{}).get('enabled'),'Accounting is not enabled',409)
        require(set(data)<= {'failure_policy','poll_seconds'},'Unknown accounting policy')
        if 'failure_policy' in data:require(data['failure_policy'] in ('open','closed'),'Failure policy must be open or closed')
        if 'poll_seconds' in data:require(type(data['poll_seconds']) is int and 1<=data['poll_seconds']<=60,'Polling must be 1–60 seconds')
        result['accounting'].update(data)
    elif kind in ('quota','portal-account'):
        require(isinstance(ident,str) and ident!='legacy','Legacy identity is protected',403)
        user=next((u for u in result.get('managed_users',[]) if u['id']==ident),None);require(user is not None,'Unknown user',404)
        if kind=='quota':
            require(state.get('accounting',{}).get('enabled'),'Enable the verified accounting core before setting quotas',409);quota_change(user,data)
        else:portal_change(user,data,result.get('managed_users',[]))
    elif kind in ('user-create', 'user-edit', 'user-disable', 'user-revoke'):
        users = result.setdefault('managed_users', [])
        require(set(data) <= {'name','tags','enabled','protocols','quota','portal','subscription'}, 'Unknown user field')
        if 'subscription' in data:require(kind=='user-create' and type(data['subscription']) is bool,'Subscription onboarding is a boolean for a new user')
        if kind == 'user-create':
            require(len(users) < 1000, 'Maximum 1000 users')
            user = {'id': uuid.uuid4().hex, 'name': clean_name(data.get('name')), 'enabled': True, 'tags': [], 'protocols': {}}
            require(not any(u['name'] == user['name'] for u in users), 'User name already exists', 409)
            selected = data.get('protocols', [p for p in PROTOCOLS if state['protocols'].get(p,{}).get('enabled')])
            require(isinstance(selected, list) and selected and set(selected) <= set(PROTOCOLS), 'Invalid protocols')
            for p in selected:
                require(state['protocols'][p]['enabled'], 'Protocol is disabled')
                user['protocols'][p] = dict(uuid=str(uuid.uuid4()), password=secrets.token_urlsafe(32))
            users.append(user)
        else:
            require(isinstance(ident, str) and ident != 'legacy', 'Legacy identity is protected', 403)
            user = next((u for u in users if u['id'] == ident), None)
            require(user is not None, 'Unknown user', 404)
            require('protocols' not in data, 'Create a new user to change protocol credentials')
        if kind == 'user-revoke':
            users.remove(user)
        else:
            if 'name' in data: user['name'] = clean_name(data['name'])
            if 'tags' in data:
                require(isinstance(data['tags'], list) and len(data['tags']) <= 10 and all(isinstance(t, str) and re.fullmatch(r'[A-Za-z0-9._-]{1,32}', t) for t in data['tags']), 'Invalid tags')
                user['tags'] = data['tags']
            if 'enabled' in data:
                require(type(data['enabled']) is bool, 'enabled must be boolean')
                user['enabled'] = data['enabled']
            if kind == 'user-disable': user['enabled'] = False
            if 'quota' in data:
                require(state.get('accounting',{}).get('enabled'),'Enable verified accounting before adding quotas',409);quota_change(user,data['quota'])
            elif kind=='user-create' and state.get('accounting',{}).get('enabled'):user['quota']=quota_plan()
            if 'portal' in data:portal_change(user,data['portal'],users)
    else:
        raise Problem(400, 'Unknown change kind')
    return result

LEGACY_FIELDS = ('uuid', 'password', 'private_key', 'public_key', 'short_id', 'port', 'enabled', 'udp_range', 'server_name', 'path')


def _fingerprint(value):
    import hashlib
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def preview(before, after, request, variant):
    """Human-readable, redacted summary of exactly what a change affects."""
    kind = request.get('kind')
    old_users = {u['id']: u for u in before.get('managed_users', [])}
    new_users = {u['id']: u for u in after.get('managed_users', [])}
    created = [new_users[i]['name'] for i in new_users if i not in old_users]
    removed = [old_users[i]['name'] for i in old_users if i not in new_users]
    disabled = [new_users[i]['name'] for i in new_users if i in old_users and old_users[i]['enabled'] and not new_users[i]['enabled']]
    enabled = [new_users[i]['name'] for i in new_users if i in old_users and not old_users[i]['enabled'] and new_users[i]['enabled']]
    renamed = [old_users[i]['name'] + ' → ' + new_users[i]['name'] for i in new_users if i in old_users and old_users[i]['name'] != new_users[i]['name']]
    retagged = [new_users[i]['name'] for i in new_users if i in old_users and old_users[i]['tags'] != new_users[i]['tags']]
    listeners = []
    for proto, fields in after.get('protocols', {}).items():
        old = before.get('protocols', {}).get(proto, {})
        for key in ('enabled', 'port'):
            if old.get(key) != fields.get(key):
                listeners.append({'protocol': proto, 'field': key, 'before': old.get(key), 'after': fields.get(key)})
    legacy_before = {p: {k: v.get(k) for k in LEGACY_FIELDS if k in v} for p, v in before.get('protocols', {}).items()}
    legacy_after = {p: {k: v.get(k) for k in LEGACY_FIELDS if k in v} for p, v in after.get('protocols', {}).items()}
    legacy_changed = sorted(p for p in legacy_before if legacy_before[p] != legacy_after.get(p))
    policy_changed = sorted(k for k in set(before.get('client_policy', {})) | set(after.get('client_policy', {})) if before.get('client_policy', {}).get(k) != after.get('client_policy', {}).get(k))
    restart = kind not in ('policy','quota','quota-bulk','portal-account','accounting-policy')
    quota_changed=[new_users[i]['name'] for i in new_users if i in old_users and new_users[i].get('quota')!=old_users[i].get('quota')]
    portal_changed=[new_users[i]['name'] for i in new_users if i in old_users and new_users[i].get('portal')!=old_users[i].get('portal')]
    affected = list(dict.fromkeys(created + removed + disabled + enabled + renamed + retagged+quota_changed+portal_changed))
    titles = {'user-create': 'Create user', 'users-import': 'Create users', 'user-edit': 'Edit user', 'user-disable': 'Disable user', 'user-revoke': 'Revoke user',
              'users-bulk': 'Bulk %s' % (request.get('data', {}).get('action') or 'change'), 'inbounds': 'Change listeners', 'policy': 'Change client policy','quota':'Change quota / reset / pause','portal-account':'Manage usage-only portal account'}
    services = ['sing-box.service (restart: active VPN connections drop and reconnect)'] if restart else []
    if listeners:
        services.append('owned firewall/NAT rules (reconciled for the new ports)')
    summary = {
        'title': titles.get(kind, kind), 'kind': kind,
        'counts': {'created': len(created), 'removed': len(removed), 'disabled': len(disabled), 'enabled': len(enabled), 'renamed': len(renamed), 'retagged': len(retagged)},
        'users': {'created': created[:200], 'removed': removed[:200], 'disabled': disabled[:200], 'enabled': enabled[:200], 'renamed': renamed[:200], 'retagged': retagged[:200]},
        'quota_users':quota_changed[:200],'portal_users':portal_changed[:200],'changed_ids':sorted(i for i in set(old_users)|set(new_users) if old_users.get(i)!=new_users.get(i)),'affected_total': len(affected), 'listeners': listeners, 'policy_fields': policy_changed,
        'network':({'before':effective(before['server']),'after':effective(after['server']),'old_listen':before['server']['listen'],'new_listen':after['server']['listen'],'panel_before':before['server'].get('panel_family','preserve'),'panel_after':after['server'].get('panel_family','preserve'),'old_endpoints':{k:before['server'].get(k) for k in ('ipv4','ipv6')},'new_endpoints':{k:after['server'].get(k) for k in ('ipv4','ipv6')},'identities':'preserved','exports':'Subscriptions retain identity; refreshed YAML/JSON/links use the new endpoint policy; QR payloads must be refreshed','restart':'VPN restarts; HTTPS listener may also restart. SSH settings are unchanged.'} if kind=='network' else None),
        'services': services,
        'protected_identity': 'changed: ' + ', '.join(legacy_changed) if legacy_changed else 'unchanged',
        'protected_identity_note': ('The original shared identity (all its protocols, keys, ports and ranges) is byte-for-byte unchanged by this change.'
                                    if not legacy_changed else 'Listener settings of the original installer identity change; existing client files must be updated.'),
        'before_fingerprint': _fingerprint(before), 'after_fingerprint': _fingerprint(after),
        'unaffected_users': len([i for i in new_users if new_users[i]['name'] not in affected]),
    }
    if variant == 'zgocloud' and legacy_changed:
        raise Problem(403, 'Protected ZgoCloud identity would change: ' + ', '.join(legacy_changed))
    safe = []
    for value in (before, after):
        item = redact(value); item['client_policy'] = value.get('client_policy', {}); safe.append(item)
    before_lines, after_lines = (json.dumps(x, sort_keys=True, indent=2).splitlines() for x in safe)
    return {
        'diff': '\n'.join(difflib.unified_diff(before_lines, after_lines, fromfile='current', tofile='candidate', lineterm=''))[:120000],
        'restart': restart, 'summary': summary,
        'warning': 'Core changes restart sing-box and interrupt active connections.' if restart else 'Manager metadata/client policy only. No core restart. Quota guard updates within the documented polling interval.',
    }


def main():
    action, source, target, variant = sys.argv[1:5]
    state = json.loads(Path(source).read_text())
    request = json.load(sys.stdin)
    if action == 'candidate':
        result = candidate(state, request, variant)
        Path(target).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        Path(target).chmod(0o600)
        print(json.dumps(preview(state, result, request, variant)))
    elif action == 'export':
        require(set(request)<= {'id','profile','format','endpoint'},'Unknown export setting')
        try:state=select_endpoint(state,request.get('endpoint','auto'))
        except ValueError as e:raise Problem(422,str(e))
        ident = request.get('id')
        if ident != 'legacy':
            user = next((u for u in state.get('managed_users', []) if u['id'] == ident and u['enabled']), None)
            require(user is not None, 'User unavailable', 404)
            for proto in PROTOCOLS:
                record = user['protocols'].get(proto)
                state['protocols'][proto]['enabled'] = bool(record) and state['protocols'][proto]['enabled']
                if record:
                    if proto in ('reality', 'vmess', 'tuic'): state['protocols'][proto]['uuid'] = record['uuid']
                    if proto in ('hy2', 'tuic', 'anytls'): state['protocols'][proto]['password'] = record['password']
        state.pop('managed_users', None)
        Path(target).write_text(json.dumps(state))
        Path(target).chmod(0o600)
    else:
        raise Problem(400, 'Unknown controller action')

if __name__ == '__main__':
    try: main()
    except (Problem, ValueError, KeyError, TypeError) as e:
        print('Invalid WebUI change: ' + str(e), file=sys.stderr)
        sys.exit(1)
