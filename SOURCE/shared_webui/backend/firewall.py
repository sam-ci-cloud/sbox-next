"""Only the panel TCP accept rule; never flush tables or alter VPN/SSH policy."""
import json
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import sys
# The root-owned firewall helper survives rollback to pre-firewall panel releases.
sys.path.insert(0, '/usr/local/lib/sbox-webui/current/backend')
from common import Problem, atomic_json, require

TAG = 'sbox-webui'

def execute(argv):
    return subprocess.run(argv, text=True, capture_output=True, timeout=30,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}, stdin=subprocess.DEVNULL)

def checked(argv):
    result = execute(argv)
    require(result.returncode == 0, 'Panel firewall command failed; inspect host firewall and run sbox webui doctor', 503)
    return result.stdout

def public(cfg):
    return not ipaddress.ip_address(cfg['listen']).is_loopback

def tools(cfg):
    return ('iptables','ip6tables') if cfg['listen']=='::' else ('ip6tables',) if ipaddress.ip_address(cfg['listen']).version==6 else ('iptables',)

def rule(cfg):
    port = int(cfg['port'])
    require(1024 <= port <= 65535, 'Invalid panel firewall port')
    return ['INPUT']+(['-d',cfg['listen']] if cfg['listen'] not in ('0.0.0.0','::') else [])+['-p','tcp','--dport',str(port),'-m','comment','--comment',TAG,'-j','ACCEPT']

def apply(cfg, state):
    if not public(cfg) or not state.get('firewall', {}).get('enabled', False): return
    # UFW must also allow the port: its later DROP can otherwise defeat an
    # independent nftables base-chain ACCEPT. Retain every foreign UFW rule.
    ufw = shutil.which('ufw')
    if ufw:
        checked([ufw,'allow','proto','tcp','from','any','to',('any' if cfg['listen']=='::' else '0.0.0.0/0' if cfg['listen']=='0.0.0.0' else cfg['listen']),'port',str(int(cfg['port'])),'comment',TAG])
    for tool in tools(cfg):
        binary = shutil.which(tool)
        require(binary, 'Install '+tool+' to configure the panel host firewall', 503)
        args = rule(cfg)
        exists=execute([binary,'-w','5','-C',*args]).returncode==0
        if exists:
            lines=checked([binary,'-w','5','-S','INPUT']).splitlines()
            entries=[line for line in lines if line.startswith('-A INPUT ')]
            if '-A INPUT -j SBOX_INPUT' in entries and entries.index('-A INPUT -j SBOX_INPUT')>0:
                checked([binary,'-w','5','-D',*args]);exists=False
        if not exists:
            # The dedicated manager verifies that its owned hook remains first.
            # Keep all VPN/SSH guards ahead of the panel's narrow TCP accept.
            lines=checked([binary,'-w','5','-S','INPUT']).splitlines()
            entries=[line for line in lines if line.startswith('-A INPUT ')]
            position=entries.index('-A INPUT -j SBOX_INPUT')+2 if '-A INPUT -j SBOX_INPUT' in entries else 1
            checked([binary,'-w','5','-I',args[0],str(position),*args[1:]])

def check(cfg, state):
    """Read-only drift check of the panel's owned rules. Returns a list of problems (empty = healthy).
    A foreign UFW reload or firewall tool can drop the narrow INPUT accept while the panel keeps
    listening; with default-drop hardening that silently locks the panel out."""
    if not public(cfg) or not state.get('firewall', {}).get('enabled', False): return []
    problems = []
    for tool in tools(cfg):
        binary = shutil.which(tool)
        if not binary:
            problems.append(tool + ' unavailable'); continue
        if execute([binary,'-w','5','-C',*rule(cfg)]).returncode != 0:
            problems.append(tool + ' panel INPUT rule missing'); continue
        entries=[line for line in checked([binary,'-w','5','-S','INPUT']).splitlines() if line.startswith('-A INPUT ')]
        if '-A INPUT -j SBOX_INPUT' in entries and entries.index('-A INPUT -j SBOX_INPUT')>0:
            problems.append(tool + ' manager hook no longer first')
    ufw = shutil.which('ufw')
    if ufw:
        status = execute([ufw,'status'])
        if status.returncode == 0 and 'Status: active' in status.stdout:
            port = str(int(cfg['port']))
            if not any(re.search(r'#\s*'+TAG+r'\s*$', line) and re.search(r'\b'+port+r'(?:/tcp)?\b', line) for line in status.stdout.splitlines()):
                problems.append('ufw panel allow missing')
    return problems

def remove(cfg):
    if not public(cfg): return
    for tool in tools(cfg):
        binary = shutil.which(tool)
        if binary:
            args = rule(cfg)
            while execute([binary,'-w','5','-C',*args]).returncode == 0:
                checked([binary,'-w','5','-D',*args])
    ufw = shutil.which('ufw')
    if ufw:
        # Delete only numbered rules carrying our exact comment and port. A
        # pre-existing identical foreign allow stays foreign and is retained.
        rows = checked([ufw,'status','numbered']).splitlines()
        for line in reversed(rows):
            match = re.match(r'\[\s*(\d+)\]\s+(.*)', line)
            if match and re.search(r'#\s*'+TAG+r'\s*$',match[2]) and re.search(r'\b'+str(int(cfg['port']))+r'(?:/tcp)?\b',match[2]):
                checked([ufw,'--force','delete',match[1]])

def guidance(cfg):
    if not public(cfg):
        return 'Explicit loopback WebUI listener. Public access is disabled by this operator setting.'
    families='; '.join('IPv6 source ::/0' if tool=='ip6tables' else 'IPv4 source 0.0.0.0/0' for tool in tools(cfg))
    return ('WebUI is accessible from any source IP, after HTTPS authentication. '
            'Provider security group: allow inbound TCP '+str(cfg['port'])+' from '+families+'. '
            'Provider firewall and Internet reachability are unverified; use the configured HTTPS hostname from outside networks. '
            'A listener or host rule does not prove public routing. VPN TCP/UDP 443 is unchanged.')

def main():
    import os
    require(os.geteuid()==0,'Root required',403)
    etc=Path('/etc/sbox-webui');cfg=json.loads((etc/'settings.json').read_text())
    record=etc/'firewall.json'
    require(not record.is_symlink(),'Unsafe panel firewall record')
    old=json.loads(record.read_text()) if record.exists() else None
    if sys.argv[1]=='remove':
        if old:remove(old)
        record.unlink(missing_ok=True)
    elif sys.argv[1] in ('check','repair'):
        state=json.loads(Path('/etc/sbox-manager/state.json').read_text())
        problems=check(cfg,state)
        if problems and sys.argv[1]=='repair':
            # Self-healing after drift (timer): re-apply only the owned rule, then verify again.
            apply(cfg,state);atomic_json(record,cfg,0o600)
            remaining=check(cfg,state)
            print(json.dumps({'panel_firewall':'restored' if not remaining else 'failed','drift':problems,'remaining':remaining}))
            sys.exit(1 if remaining else 0)
        print(json.dumps({'panel_firewall':'healthy' if not problems else 'drift','problems':problems}))
        sys.exit(1 if problems else 0)
    else:
        if old and (old['listen'],old['port'])!=(cfg['listen'],cfg['port']): remove(old)
        apply(cfg,json.loads(Path('/etc/sbox-manager/state.json').read_text()))
        atomic_json(record,cfg,0o600)
        print(guidance(cfg))

if __name__=='__main__':main()
