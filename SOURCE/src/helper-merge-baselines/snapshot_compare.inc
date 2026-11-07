    other=Path(sys.argv[3]); expected=inventory(root); actual=inventory(other)
    mode=sys.argv[4] if len(sys.argv)>4 else 'strict'
    if mode not in ('strict','live-quota'):raise SystemExit('invalid snapshot comparison mode')
    if mode=='live-quota' and 'quota-runtime.json' in expected and 'quota-runtime.json' in actual:
        # Only staging recovery may retain the collector's newer policy. The
        # snapshot itself stays byte-exact; all other files and this file's
        # owner/group/mode/type must still match the trusted snapshot.
        import math
        state=json.loads((other/'state.json').read_text())
        known={'user-'+u['id']+'@'+p for u in state.get('managed_users',[]) for p in u.get('protocols',{})}
        source='sing-box V2Ray StatsService: authenticated routed payload; excludes host/provider overhead'
        for directory,rows in ((root,expected),(other,actual)):
            row=rows['quota-runtime.json']; path=directory/'quota-runtime.json'
            if row['type']!='file' or row['mode']!=0o640 or row['uid']!=(directory/'state.json').stat().st_uid:raise SystemExit('unsafe live quota policy metadata')
            value=json.loads(path.read_text())
            if not isinstance(value,dict) or not {'blocked','sampled_at','source'}<=set(value) or set(value)-{'blocked','sampled_at','source','proven_blocked','degraded','reason'}:raise SystemExit('invalid live quota policy fields')
            if value['source']!=source or type(value['sampled_at']) not in (int,float) or not math.isfinite(value['sampled_at']) or value['sampled_at']<=0:raise SystemExit('invalid live quota policy provenance/time')
            blocked=value['blocked']
            if not isinstance(blocked,list) or any(not isinstance(tag,str) or tag not in known for tag in blocked) or len(blocked)!=len(set(blocked)):raise SystemExit('invalid live quota policy identities')
            if 'proven_blocked' in value:
                proven=value['proven_blocked']
                if not isinstance(proven,list) or any(not isinstance(tag,str) or tag not in blocked for tag in proven):raise SystemExit('invalid proven quota identities')
            if 'degraded' in value and type(value['degraded']) is not bool:raise SystemExit('invalid quota degradation flag')
            if 'reason' in value and (not isinstance(value['reason'],str) or len(value['reason'])>512):raise SystemExit('invalid quota reason')
            del row['sha256']
    if expected!=actual:raise SystemExit('restored tree differs from snapshot: '+str(other))
