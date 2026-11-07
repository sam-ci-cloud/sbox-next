#!/usr/bin/env python3
"""List the panel's HTTP routes from backend/server.py and compare with api-spec/openapi.json.

  api_inventory.py            print JSON {routes, missing_from_spec, stale_in_spec}; exit 1 on drift
  api_inventory.py --update   add missing routes to the spec (existing entries are kept)

Routes are read from the dispatcher source (no hand-maintained list), so a new
route without a spec entry fails the check in test_panel_v2.ApiSpec.
"""
import ast,json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / 'backend/server.py'
SPEC = ROOT / 'api-spec/openapi.json'

SUMMARIES = {
    'dashboard': 'Overview tiles, resources, alerts and last change from the real bridge (external reachability is always "unknown")',
    'system/version': 'Panel, manager and core versions plus installed panel file integrity against the build manifest',
    'diagnostics/report': 'Copyable redacted health report (text/plain); contains no credentials or tokens',
    'protocols/health': 'Per-protocol listener, certificate and last local probe; external path never claimed',
    'protocols/probe': 'Run loopback-only TCP/TLS probes now (6 per minute); UDP inbounds are reported "not-probed"',
    'certificates/readiness': 'Public ACME prerequisites (DNS A/AAAA, port 80, renewal timer) observed on this host',
    'alerts': 'Open and recent alerts plus the change/event timeline',
    'alerts/silence': 'Silence alert notifications panel-wide for {minutes} (0-1440; 0 clears)',
    'alerts/evaluate': 'Evaluate alert rules now from real state (normally every 30 s)',
    'subscriptions/settings': 'Opt-in personal landing page for subscription links',
    'auth/totp/disable': 'Disable TOTP; needs a fresh session and a current code',
    'auth/sessions': 'List own browser sessions (admins may list all)',
    'auth/sessions/revoke': 'Revoke {id}, {others:true} or (admin) {all_accounts:true}; the current session is kept',
}


def routes():
    tree=ast.parse(SERVER.read_text());out={}
    def strings(test,name):
        values=[]
        for expr in ast.walk(test):
            if isinstance(expr,ast.Compare) and isinstance(expr.left,ast.Name) and expr.left.id==name:
                for op,right in zip(expr.ops,expr.comparators):
                    if isinstance(op,ast.Eq) and isinstance(right,ast.Constant) and isinstance(right.value,str):values.append(right.value)
                    elif isinstance(op,ast.In) and isinstance(right,(ast.Tuple,ast.List)):
                        values.extend(x.value for x in right.elts if isinstance(x,ast.Constant) and isinstance(x.value,str))
        return values
    def possible(test,http):
        if isinstance(test,ast.Name) and test.id=='write':return {http=='post'}
        if isinstance(test,ast.UnaryOp) and isinstance(test.op,ast.Not):return {not x for x in possible(test.operand,http)}
        if isinstance(test,ast.BoolOp):
            result={isinstance(test.op,ast.And)}
            for child in test.values:
                result={a and b if isinstance(test.op,ast.And) else a or b for a in result for b in possible(child,http)}
            return result
        if isinstance(test,ast.Compare) and isinstance(test.left,ast.Attribute) and test.left.attr=='command' and len(test.ops)==1:
            right=test.comparators[0]
            if isinstance(test.ops[0],ast.Eq) and isinstance(right,ast.Constant):return {http.upper()==right.value}
            if isinstance(test.ops[0],ast.In) and isinstance(right,(ast.Tuple,ast.List)):
                return {http.upper() in [x.value for x in right.elts if isinstance(x,ast.Constant)]}
        return {True,False}
    def walk(node,base,allowed):
        if isinstance(node,ast.If):
            yes={http for http in allowed if True in possible(node.test,http)}
            no={http for http in allowed if False in possible(node.test,http)}
            for suffix in strings(node.test,'suffix'):out.setdefault(base+suffix,set()).update(yes)
            for path in strings(node.test,'path'):
                if path.startswith('/api/v1/'):out.setdefault(path,set()).update(yes)
            for child in node.body:walk(child,base,yes)
            for child in node.orelse:walk(child,base,no)
            return
        if isinstance(node,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='reads' for x in node.targets) and isinstance(node.value,ast.Dict):
            for key in node.value.keys:
                if isinstance(key,ast.Constant):out.setdefault(base+key.value,set()).add('get')
        for child in ast.iter_child_nodes(node):walk(child,base,allowed)
    for method in ast.walk(tree):
        if not isinstance(method,ast.FunctionDef) or method.name not in ('handle_request','auth_routes','portal_routes'):continue
        base='/api/v1/portal/' if method.name=='portal_routes' else '/api/v1/'
        walk(method,base,{'get','post'})
    for path in ('/api/v1/changes/{token}','/sub/{token}/{profile}.{format}','/sub/{token}/'):out.setdefault(path,set()).add('get')
    return {k:sorted(v) for k,v in sorted(out.items())}


def main():
    spec = json.loads(SPEC.read_text()); live = routes()
    missing = {p: [m for m in ms if m not in spec['paths'].get(p, {})] for p, ms in live.items()}
    missing = {p: ms for p, ms in missing.items() if ms}
    stale = sorted(p for p in spec['paths'] if p not in live)
    if '--update' in sys.argv:
        template = next(iter(spec['paths']['/api/v1/users'].values()))
        for p, ms in missing.items():
            for m in ms:
                entry = json.loads(json.dumps(template)); key = p.replace('/api/v1/', '')
                entry['summary'] = SUMMARIES.get(key, key)
                if p == '/sub/{token}/':
                    entry = {'summary': 'Opt-in personal subscription landing page (CSP default-src none; no admin data)', 'parameters': [{'in': 'path', 'name': 'token', 'required': True, 'schema': {'type': 'string'}}],
                             'responses': {'200': {'description': 'HTML page'}, '404': {'description': 'Unknown, revoked or disabled'}, '429': {'description': 'Rate limited'}}}
                spec['paths'].setdefault(p, {})[m] = entry
        spec['paths'] = dict(sorted(spec['paths'].items()))
        SPEC.write_text(json.dumps(spec, indent=2, sort_keys=True) + '\n')
        missing = {}
    print(json.dumps({'routes': live, 'missing_from_spec': missing, 'stale_in_spec': stale}, indent=1))
    return 1 if missing or stale else 0


if __name__ == '__main__':
    sys.exit(main())
