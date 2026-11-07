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
