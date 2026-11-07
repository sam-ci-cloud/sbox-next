import hashlib
import json
import os
import re
import shlex
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


def fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_tree(path):
    for item in sorted(Path(path).rglob('*')):
        if item.is_file():
            with item.open('rb') as stream:
                os.fsync(stream.fileno())
    for item in sorted(Path(path).rglob('*'), reverse=True):
        if item.is_dir():
            fsync_dir(item)
    fsync_dir(path)
    fsync_dir(Path(path).parent)


def verify_server_identity(meta, server_config, core):
    for path in (server_config, core):
        regular(path)
    if (meta.get('format') != 1 or
        meta.get('server_config_sha256') != digest(server_config) or
        meta.get('core_sha256') != digest(core)):
        raise RuntimeError('server config/core changed since snapshot; recovery refused, journal preserved')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f'expected a regular non-symlink file: {path}')


def regular_tree(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f'expected a regular directory: {path}')
    for item in path.rglob('*'):
        if item.is_symlink() or not (item.is_file() or item.is_dir()):
            raise RuntimeError(f'unsupported item in policy directory: {item}')


def tree_hashes(path):
    regular_tree(path)
    return {str(p.relative_to(path)): digest(p) for p in sorted(Path(path).rglob('*')) if p.is_file()}


def private_tree(path):
    for p in [Path(path)] + list(Path(path).rglob('*')):
        os.chmod(p, 0o700 if p.is_dir() else 0o600)


def atomic_file(source, destination, mode):
    destination = Path(destination)
    fd, name = tempfile.mkstemp(prefix='.policy-', dir=str(destination.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(Path(source).read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
            # Policy operations run as root. Normalize ownership explicitly so
            # setgid/ACL parent directories cannot produce helpers owned by an
            # unexpected group and make doctor fail after a successful upgrade.
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), mode)
        os.replace(name, destination)
        fsync_dir(destination.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def server_state(path):
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    if value.get('schema') == 1:
        # The recognized v1 -> v2 semantic migration, also regression-compared
        # against the state helper. No identities/ports/certificate paths rotate.
        value['schema'] = 2
        value['firewall'] = {'enabled': (value.get('firewall') or {}).get('mode', 'auto') != 'none'}
        value['security'] = {'block_private': not bool((value.get('security') or {}).get('allow_private_destinations', False))}
        value['tuning'] = {'enabled': bool((value.get('tuning') or {}).get('enabled', True))}
        value['protocols'].get('hy2', {}).pop('up_mbps', None)
        value['protocols'].get('hy2', {}).pop('down_mbps', None)
        value['protocols'].get('tuic', {}).pop('udp_range', None)
        cert=value.setdefault('certificate', {})
        for key, default in {'mode':'existing','source_mode':'external','source_fullchain':'','source_key':'','insecure':False}.items():
            cert.setdefault(key,default)
    for user in value.get('managed_users',[]):
        user.pop('quota',None);user.pop('portal',None)
    for key in ('poll_seconds','failure_policy'):
        value.get('accounting',{}).pop(key,None)
    for key in ('client_policy', 'manager_version', 'updated_at'):
        value.pop(key, None)
    return value


def owned_firewall_rows(text):
    """Ordered owned chains and hooks; foreign rules and counters are telemetry.

    Include every reference to a reserved chain, even from an unexpected parent:
    duplicates, altered conditions, extra hooks and owned rule changes are drift.
    Parent absolute positions may change when Docker/UFW/other jails add rules.
    """
    rows=[]; table=None
    for line in text.splitlines():
        if line.startswith('*'):table=line[1:];continue
        if line=='COMMIT':table=None;continue
        chain={'filter':'SBOX_INPUT','nat':'SBOX_NAT'}.get(table)
        if not chain:continue
        tokens=shlex.split(line,comments=True)
        if not tokens:continue
        if tokens[0]==':'+chain:
            rows.append([table,tokens[0],tokens[1]])
        elif tokens[0]=='-A' and len(tokens)>1:
            owned=tokens[1]==chain
            for index,token in enumerate(tokens[:-1]):
                if token in ('-j','--jump','-g','--goto') and tokens[index+1]==chain:owned=True
            if owned:rows.append([table,*tokens])
    return rows


def runtime_invariants(server_config, legacy_firewall=False):
    def output(args, required=True):
        p=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if required and p.returncode:
            raise RuntimeError('cannot read policy runtime invariant: '+args[0])
        text='\n'.join(line for line in p.stdout.splitlines() if not line.startswith('#'))
        if args[0] in ('iptables-save','ip6tables-save'):
            text=re.sub(r'\[\d+:\d+\]', '[0:0]', text) # packet counters are live telemetry, not rule drift
            if not legacy_firewall:text=json.dumps(owned_firewall_rows(text),separators=(',',':'))
        return hashlib.sha256(text.encode()).hexdigest()
    value={}
    value['service']=output(['systemctl','show','-p','MainPID','-p','NRestarts','-p','ActiveState','-p','UnitFileState','sing-box.service'])
    for family in ('iptables-save','ip6tables-save'):
        value[family if legacy_firewall else family+"-owned-v2"]=output([family])
    keys=['net.core.default_qdisc','net.ipv4.tcp_congestion_control','net.core.rmem_max','net.core.wmem_max','net.core.somaxconn','net.core.netdev_max_backlog','net.ipv4.tcp_fastopen','net.ipv4.tcp_mtu_probing','net.ipv4.udp_rmem_min','net.ipv4.udp_wmem_min']
    # -e: keys absent in a container network namespace (LXC/OpenVZ VPS) are
    # skipped instead of aborting; the digest stays comparable within one host.
    value['sysctl']=output(['sysctl','-e','-n',*keys])
    for path in ('/etc/systemd/system/sing-box.service','/etc/systemd/system/sbox-manager-firewall.service','/etc/sysctl.d/99-sbox-manager.conf','/etc/fail2ban/jail.d/sbox-manager.local','/etc/fail2ban/action.d/sbox-manager.conf','/usr/local/lib/sbox-manager-security/action'):
        if Path(path).exists():value[path]=digest(path)
    if Path('/usr/local/lib/sbox-manager-security/action').exists():
        # Set members change legitimately during bans. Protect structure/order,
        # not counters, handles or the current dynamic ban membership.
        p=subprocess.run(['nft','-j','list','table','inet','sbox_guard'],capture_output=True,text=True,timeout=15,check=True)
        rows=[]
        for entry in json.loads(p.stdout)['nftables']:
            if 'metainfo' in entry:continue
            row=json.loads(json.dumps(entry))
            for kind in ('table','chain','set','rule'):
                if kind in row:
                    for key in ('handle','elem','index'):row[kind].pop(key,None)
            rows.append(row)
        value['native_guard_structure']=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()
    for inbound in json.loads(Path(server_config).read_text()).get('inbounds',[]):
        for field in ('certificate_path','key_path'):
            path=inbound.get('tls',{}).get(field)
            if path:value[path]=digest(path)
    return value


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def service_facts():
    p=subprocess.run(['systemctl','show','sing-box.service','-p','MainPID','-p','ActiveState','-p','UnitFileState'],capture_output=True,text=True,timeout=15,check=True)
    return dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)


def verify_runtime_invariants(meta, server_config):
    expected=meta.get('runtime_invariants')
    if expected is not None:
        legacy_firewall=any(key in expected for key in ('iptables-save','ip6tables-save'))
        observed=runtime_invariants(server_config,legacy_firewall=legacy_firewall)
        rebooted=bool(meta.get('boot_id') and meta['boot_id']!=boot_id())
        ignored={'service'} if rebooted else set()
        if any(observed.get(key)!=value for key,value in expected.items() if key not in ignored):
            detail=' (legacy whole-firewall journal requires assisted verification if foreign rules changed)' if legacy_firewall else ''
            raise RuntimeError('service/certificate/SBOX firewall/sysctl drift; journal preserved'+detail)
        if rebooted:
            facts=service_facts(); before=meta.get('service_facts_before',{})
            if before.get('ActiveState','active')=='active' and (facts.get('ActiveState')!='active' or not facts.get('MainPID','0').isdigit() or int(facts['MainPID'])<=0):
                raise RuntimeError('core is not healthy after reboot; journal preserved, repair service before policy recovery')
            if before.get('UnitFileState') and before['UnitFileState']!=facts.get('UnitFileState'):
                raise RuntimeError('persistent service enablement changed; journal preserved')
    if expected is None and os.environ.get('SBOX_POLICY_RUNTIME') == '1':
        raise RuntimeError('legacy policy recovery lacks runtime fingerprints; assisted recovery required, journal preserved')


def interrupt(signum, frame):
    raise RuntimeError(f'policy transaction interrupted by signal {signum}')


def journal_path(backup_root):
    return Path(backup_root) / '.policy-journal.json'


def write_policy_journal(backup_root, payload):
    """Durably record an in-flight policy transaction, fail-closed and exclusive.

    The pointer is created with O_CREAT|O_EXCL so a second concurrent/retry
    transaction cannot clobber the recovery pointer of an interrupted one
    (AUD-04 analogue for the policy layer)."""
    path = journal_path(backup_root)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as fh:
            json.dump(payload, fh, indent=2)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def clear_policy_journal(backup_root):
    try:
        os.unlink(journal_path(backup_root))
        fsync_dir(backup_root)
    except FileNotFoundError:
        pass


def restore_exports_from_snapshot(snapshot, exports):
    """Replace the live exports with the snapshot copy, tolerating a missing or
    partial live directory (the crash window leaves exports absent)."""
    exports = Path(exports)
    staging = exports.parent / ('.exports-recover-' + os.urandom(4).hex())
    shutil.copytree(snapshot / 'exports', staging)
    private_tree(staging)
    durable_tree(staging)
    if exports.is_symlink() or (exports.exists() and not exports.is_dir()):
        exports.unlink()
    elif exports.is_dir():
        shutil.rmtree(exports)
    os.replace(staging, exports)
    fsync_dir(exports.parent)


def recover(backup_root, state_file, exports, manager_file, server_config, core, *_ignored):
    """Recover an interrupted policy-only transaction from its durable journal.

    Works even when the live exports directory is missing or incomplete. Fails
    closed: if the journal or its snapshot is missing/corrupt, nothing is
    cleared and a nonzero exit is raised with the evidence preserved. No
    sing-box/core/service restart is performed."""
    backup_root = Path(backup_root)
    jpath = journal_path(backup_root)
    if not jpath.exists():
        print('No interrupted policy transaction to recover.')
        return
    journal = json.loads(jpath.read_text(encoding='utf-8'))
    regular(jpath)
    if journal.get('format') != 1:
        raise RuntimeError('unknown policy journal format; preserved')
    for key, expected in [('state_file', state_file), ('exports', exports), ('manager_file', manager_file)]:
        if journal.get(key) != str(expected):
            raise RuntimeError('policy journal target mismatch; preserved')
    snapshot = Path(journal.get('snapshot', ''))
    if snapshot.is_symlink() or snapshot.resolve().parent != backup_root.resolve() or not snapshot.name.startswith('policy-'):
        raise RuntimeError('policy snapshot is outside backup root; journal preserved')
    if not snapshot.is_dir():
        raise RuntimeError(f'policy journal references a missing snapshot: {snapshot}; journal preserved for assisted recovery')
    # integrity of the snapshot
    hashes = json.loads((snapshot / 'hashes.json').read_text(encoding='utf-8'))
    observed = tree_hashes(snapshot)
    observed.pop('hashes.json', None)
    if hashes != observed:
        raise RuntimeError(f'policy snapshot integrity check failed: {snapshot}; journal preserved for assisted recovery')
    meta = json.loads((snapshot / 'snapshot.json').read_text(encoding='utf-8'))
    verify_server_identity(meta, server_config, core)
    verify_runtime_invariants(meta, server_config)
    recovery_runtime=runtime_invariants(server_config) if meta.get('runtime_invariants') is not None else None
    state_file, manager_file = Path(state_file), Path(manager_file)
    allowed = {str(manager_file.parent / 'sbox-state'), str(manager_file.parent / 'sbox-policy')}
    helpers = validate_helper_meta(meta.get('helpers', []))
    if any(entry['target'] not in allowed for entry in helpers):
        raise RuntimeError('unexpected recovery helper target; journal preserved')
    if json.loads((snapshot / 'exports/server.json').read_text()) != json.loads(Path(server_config).read_text()):
        raise RuntimeError('snapshot exports disagree with live server; journal preserved')
    restore_exports_from_snapshot(snapshot, exports)
    atomic_file(snapshot / 'state.json', state_file, 0o600)
    atomic_file(snapshot / 'manager', manager_file, 0o755)
    restore_helper_files(snapshot, validate_helper_meta(meta.get('helpers', [])))
    # verify before declaring success
    if digest(state_file) != digest(snapshot / 'state.json'):
        raise RuntimeError('post-recovery state verification failed; journal preserved')
    if tree_hashes(Path(exports)) != tree_hashes(snapshot / 'exports'):
        raise RuntimeError('post-recovery exports verification failed; journal preserved')
    if not helper_files_match(snapshot, validate_helper_meta(meta.get('helpers', []))):
        raise RuntimeError('post-recovery helper verification failed; journal preserved')
    if digest(manager_file) != digest(snapshot / 'manager'):
        raise RuntimeError('post-recovery manager verification failed; journal preserved')
    verify_server_identity(meta, server_config, core)
    verify_runtime_invariants(meta, server_config)
    if recovery_runtime is not None and runtime_invariants(server_config)!=recovery_runtime:
        raise RuntimeError('runtime changed during policy recovery; journal preserved')
    clear_policy_journal(backup_root)
    print('Policy recovery complete: manager/state/helpers/exports restored from the durable snapshot.')
    print('No service restart, core update, firewall or certificate change was performed.')


def parse_helpers(raw):
    """Return [(source, target), ...] for helper files an apply operation owns."""
    if not raw:
        return []
    items = json.loads(raw)
    if not isinstance(items, list):
        raise RuntimeError('helper list must be an array')
    helpers = []
    seen = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {'source', 'target'}:
            raise RuntimeError('each helper entry needs exactly source and target')
        helper_source, helper_target = Path(item['source']), Path(item['target'])
        regular(helper_source)
        if not helper_target.parent.is_dir():
            raise RuntimeError(f'helper target directory is missing: {helper_target.parent}')
        key = str(helper_target)
        if key in seen:
            raise RuntimeError(f'duplicate helper target: {helper_target}')
        seen.add(key)
        if os.path.lexists(helper_target) and (helper_target.is_symlink() or not helper_target.is_file()):
            raise RuntimeError(f'unexpected helper path: {helper_target}')
        helpers.append((helper_source, helper_target))
    return helpers


def snapshot_helper_files(snapshot, targets):
    """Snapshot the current helper targets before any policy-layer mutation."""
    helper_dir = snapshot / 'helpers'
    helper_dir.mkdir(mode=0o700)
    meta = []
    seen = set()
    for index, target in enumerate(map(Path, targets)):
        key = str(target)
        if key in seen:
            continue
        seen.add(key)
        name = f'{index}-{target.name}'
        present = os.path.lexists(target)
        if present:
            if target.is_symlink() or not target.is_file():
                raise RuntimeError(f'unexpected helper path: {target}')
            shutil.copyfile(target, helper_dir / name)
        meta.append({'target': str(target), 'name': name, 'present': present})
    return meta


def validate_helper_meta(meta):
    if not isinstance(meta, list):
        raise RuntimeError('snapshot helper metadata must be an array')
    seen = set()
    for entry in meta:
        if not isinstance(entry, dict) or set(entry) != {'target', 'name', 'present'}:
            raise RuntimeError('invalid helper metadata in policy snapshot')
        target = str(entry['target'])
        if target in seen:
            raise RuntimeError(f'duplicate helper target in snapshot: {target}')
        seen.add(target)
        if not isinstance(entry['name'], str) or '/' in entry['name'] or entry['name'] in {'', '.', '..'}:
            raise RuntimeError('invalid helper snapshot filename')
        if not isinstance(entry['present'], bool):
            raise RuntimeError('invalid helper snapshot presence flag')
    return meta


def restore_helper_files(snapshot, meta):
    """Put helper files back exactly as the supplied snapshot recorded them."""
    validate_helper_meta(meta)
    for entry in meta:
        target = Path(entry['target'])
        saved = snapshot / 'helpers' / entry['name']
        if entry['present']:
            regular(saved)
            atomic_file(saved, target, 0o755)
        else:
            if target.is_symlink() or target.exists():
                if target.is_dir():
                    raise RuntimeError(f'cannot remove unexpected helper directory during rollback: {target}')
                target.unlink()


def helper_files_match(snapshot, meta):
    validate_helper_meta(meta)
    for entry in meta:
        target = Path(entry['target'])
        saved = snapshot / 'helpers' / entry['name']
        if entry['present']:
            if target.is_symlink() or not target.is_file() or not saved.is_file() or digest(target) != digest(saved):
                return False
        elif target.is_symlink() or target.exists():
            return False
    return True


def transaction(action, source, rendered, manager_source, state_file, exports,
                manager_file, server_config, core, backup_root, helpers_json=''):
    state_file, exports, manager_file, server_config, core, backup_root = map(
        Path, (state_file, exports, manager_file, server_config, core, backup_root))
    for p in (state_file, manager_file, server_config, core):
        regular(p)
    regular_tree(exports)
    before_state = server_state(state_file)
    config_sha, core_sha = digest(server_config), digest(core)
    protected_runtime = runtime_invariants(server_config) if os.environ.get('SBOX_POLICY_RUNTIME') == '1' else None
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if backup_root.is_symlink():
        raise RuntimeError('backup root must not be a symlink')
    os.chmod(backup_root, 0o700)
    # Fail closed: refuse to start a new policy transaction while a previous one
    # awaits recovery, so an immediate retry after a crash cannot bury the
    # recovery pointer (AUD-04).
    if journal_path(backup_root).exists():
        raise RuntimeError('an interrupted policy transaction awaits recovery (run: sbox recover); refusing to start a new one')

    rollback_source = None
    desired_helper_meta = []
    desired_helpers = []
    allowed_helper_targets = {
        str(manager_file.parent / 'sbox-state'),
        str(manager_file.parent / 'sbox-policy'),
    }
    if action == 'rollback':
        rollback_source = Path(source)
        if rollback_source.is_symlink() or rollback_source.resolve().parent != backup_root.resolve() or not rollback_source.name.startswith('policy-'):
            raise RuntimeError('rollback requires an immediate policy-* snapshot under the manager backup directory')
        regular_tree(rollback_source)
        hashes = json.loads((rollback_source / 'hashes.json').read_text(encoding='utf-8'))
        observed = tree_hashes(rollback_source)
        observed.pop('hashes.json', None)
        if hashes != observed:
            raise RuntimeError('policy snapshot integrity check failed')
        rollback_meta = json.loads((rollback_source / 'snapshot.json').read_text(encoding='utf-8'))
        if rollback_meta.get('format') != 1 or rollback_meta.get('server_config_sha256') != config_sha or rollback_meta.get('core_sha256') != core_sha:
            raise RuntimeError('server config/core changed since snapshot; policy-only rollback refused')
        # A client-policy rollback may not roll back quota charging decisions or
        # portal revocations. Use their explicit audited commands instead.
        current_metadata=json.loads(state_file.read_text())
        restored_metadata=json.loads((rollback_source/'state.json').read_text())
        def usage_metadata(v):return {'users':{u['id']:{k:u.get(k) for k in ('quota','portal')} for u in v.get('managed_users',[])},'accounting':v.get('accounting')}
        if usage_metadata(current_metadata)!=usage_metadata(restored_metadata):raise RuntimeError('Quota/portal policy changed since this snapshot; client-policy rollback cannot undo usage controls. Use explicit quota/portal commands.')
        candidate_state = rollback_source / 'state.json'
        candidate_manager = rollback_source / 'manager'
        candidate_exports = rollback_source / 'exports'
        if 'helpers' in rollback_meta:
            desired_helper_meta = validate_helper_meta(rollback_meta.get('helpers', []))
            if any(str(entry['target']) not in allowed_helper_targets for entry in desired_helper_meta):
                raise RuntimeError('policy snapshot contains an unexpected helper target')
        else:
            # Older policy snapshots did not carry helper bytes. Leave current
            # persistent helpers untouched rather than guessing or silently deleting them.
            desired_helper_meta = []
            print('Policy snapshot predates helper-aware rollback; persistent helpers will be left unchanged.', file=sys.stderr)
    elif action == 'apply':
        candidate_state, candidate_manager, candidate_exports = Path(source), Path(manager_source), Path(rendered)
        desired_helpers = parse_helpers(helpers_json)
        if any(str(target) not in allowed_helper_targets for _, target in desired_helpers):
            raise RuntimeError('policy operation requested an unexpected helper target')
    else:
        raise RuntimeError('unknown policy action')

    regular(candidate_state)
    regular(candidate_manager)
    regular_tree(candidate_exports)
    if server_state(candidate_state) != before_state:
        raise RuntimeError('non-policy server state would change; policy-only operation refused')
    if json.loads((candidate_exports / 'server.json').read_text(encoding='utf-8')) != json.loads(server_config.read_text(encoding='utf-8')):
        raise RuntimeError('rendered server config differs from live config; inspect the drift before applying client-only changes')
    if '# Managed by sbox-manager' not in candidate_manager.read_text(encoding='utf-8').splitlines()[:12]:
        raise RuntimeError('candidate manager is not recognized')
    subprocess.run(['bash', '-n', str(candidate_manager)], check=True)
    expected_state_sha, expected_manager_sha = digest(candidate_state), digest(candidate_manager)

    # Snapshot the CURRENT policy layer before touching it. This snapshot is
    # independent from rollback_source: during a rollback operation the source
    # snapshot is the desired old state, while this new snapshot is what an
    # automatic rollback must restore if the rollback itself fails.
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-')
    snapshot = Path(tempfile.mkdtemp(prefix='policy-' + stamp, dir=str(backup_root)))
    shutil.copyfile(state_file, snapshot / 'state.json')
    shutil.copyfile(manager_file, snapshot / 'manager')
    shutil.copytree(exports, snapshot / 'exports')
    helper_targets = [target for _, target in desired_helpers] if action == 'apply' else [Path(entry['target']) for entry in desired_helper_meta]
    prechange_helper_meta = snapshot_helper_files(snapshot, helper_targets)
    (snapshot / 'snapshot.json').write_text(json.dumps({
        'format': 1, 'operation': action,
        'server_config_sha256': config_sha, 'core_sha256': core_sha,
        'helpers': prechange_helper_meta,
        'runtime_invariants': protected_runtime,
        'boot_id': boot_id() if protected_runtime is not None else None,
        'service_facts_before': service_facts() if protected_runtime is not None else None,
        'created_at': datetime.now(timezone.utc).isoformat(),
    }, indent=2) + '\n')
    (snapshot / 'hashes.json').write_text(json.dumps(tree_hashes(snapshot), indent=2, sort_keys=True) + '\n')
    private_tree(snapshot)
    durable_tree(snapshot)
    print(f'Policy snapshot: {snapshot}', flush=True)

    # Durable recovery pointer: written (exclusively) BEFORE any destructive
    # rename, so a SIGKILL/power-loss during the exports swap leaves a journal
    # that `sbox recover` can act on even though the live exports directory is
    # momentarily absent (AUD-03/AUD-05). Cleared only on verified completion.
    write_policy_journal(backup_root, {
        'format': 1, 'operation': action, 'snapshot': str(snapshot),
        'state_file': str(state_file), 'exports': str(exports),
        'manager_file': str(manager_file), 'created_at': datetime.now(timezone.utc).isoformat(),
    })

    work = Path(tempfile.mkdtemp(prefix='.client-policy-', dir=str(exports.parent)))
    moved_exports = False
    installed_exports = False
    touched = False
    try:
        if action == 'apply':
            # Preserve user-added export files while replacing generated outputs.
            shutil.copytree(exports, work / 'exports')
            for item in candidate_exports.iterdir():
                regular(item)
                target = work / 'exports' / item.name
                if target.is_dir():
                    raise RuntimeError(f'generated filename conflicts with a directory: {item.name}')
                shutil.copyfile(item, target)
        else:
            shutil.copytree(candidate_exports, work / 'exports')
        private_tree(work / 'exports')
        durable_tree(work / 'exports')
        expected_exports = tree_hashes(work / 'exports')
        # Copy sources before commit: rollback sources may live in old exports.
        shutil.copyfile(candidate_state, work / 'state.json')
        shutil.copyfile(candidate_manager, work / 'manager')
        touched = True
        os.replace(exports, work / 'previous-exports')
        moved_exports = True
        fsync_dir(exports.parent)
        fsync_dir(work)
        os.replace(work / 'exports', exports)
        installed_exports = True
        fsync_dir(exports.parent)
        atomic_file(work / 'state.json', state_file, 0o600)
        atomic_file(work / 'manager', manager_file, 0o755)
        if action == 'apply':
            for helper_source, helper_target in desired_helpers:
                atomic_file(helper_source, helper_target, 0o755)
        elif desired_helper_meta:
            restore_helper_files(rollback_source, desired_helper_meta)
        if digest(state_file) != expected_state_sha or digest(manager_file) != expected_manager_sha or tree_hashes(exports) != expected_exports:
            raise RuntimeError('installed policy verification failed')
        if action == 'apply':
            for helper_source, helper_target in desired_helpers:
                if helper_target.is_symlink() or digest(helper_target) != digest(helper_source):
                    raise RuntimeError(f'installed helper verification failed: {helper_target}')
        elif desired_helper_meta and not helper_files_match(rollback_source, desired_helper_meta):
            raise RuntimeError('restored helper verification failed')
        if protected_runtime is not None and runtime_invariants(server_config) != protected_runtime:
            raise RuntimeError('policy runtime invariants changed during transaction')
        if digest(server_config) != config_sha or digest(core) != core_sha:
            raise RuntimeError('server config/core changed during policy transaction')
    except BaseException:
        if touched:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if hasattr(signal, 'SIGHUP'):
                signal.signal(signal.SIGHUP, signal.SIG_IGN)
            try:
                if installed_exports and exports.exists():
                    shutil.rmtree(exports)
                if moved_exports:
                    os.replace(work / 'previous-exports', exports)
                atomic_file(snapshot / 'state.json', state_file, 0o600)
                atomic_file(snapshot / 'manager', manager_file, 0o755)
                restore_helper_files(snapshot, prechange_helper_meta)
                # In-process rollback succeeded, so the durable journal is no
                # longer needed. (A hard SIGKILL cannot reach here; that case is
                # exactly what the journal + `recover` handle.)
                if protected_runtime is not None and runtime_invariants(server_config) != protected_runtime:
                    raise RuntimeError('runtime drift during automatic rollback; journal preserved')
                verify_server_identity({'format': 1, 'server_config_sha256': config_sha, 'core_sha256': core_sha}, server_config, core)
                if (digest(state_file) != digest(snapshot / 'state.json') or
                    digest(manager_file) != digest(snapshot / 'manager') or
                    tree_hashes(exports) != tree_hashes(snapshot / 'exports') or
                    not helper_files_match(snapshot, prechange_helper_meta)):
                    raise RuntimeError('automatic policy rollback verification failed; journal preserved')
                durable_tree(exports)
                clear_policy_journal(backup_root)
                print('Policy operation failed; previous manager/state/helpers/exports restored.', file=sys.stderr)
            except BaseException as exc:
                print(f'AUTOMATIC ROLLBACK INCOMPLETE: {exc}. Run: sbox recover. Keep snapshot: {snapshot}; staging: {work}', file=sys.stderr)
                raise
        else:
            clear_policy_journal(backup_root)
        raise
    else:
        clear_policy_journal(backup_root)
        shutil.rmtree(work, ignore_errors=True)
        if desired_helpers:
            print('Manager helpers updated: ' + ', '.join(str(target) for _, target in desired_helpers))
        print('Policy operation completed. No service restart, core update, firewall or certificate change was requested.')
        if action == 'rollback':
            print('Snapshot policy/exports restored verbatim. Inspect the restored policy and reimport/reload YAML; client-local choices may persist.')
        else:
            print('Reimport/reload the complete client YAML and select 🛡 Anti-Block Auto (fresh default). Client-local stored choices may persist.')
        print('A policy snapshot contains credentials; do not publish or send it unredacted.')


def main():
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, interrupt)
    args = sys.argv[1:]
    try:
        if args and args[0] == 'recover':
            # layout: recover src rendered manager_source state_file exports manager_file server_config core backup_root [helpers]
            state_file, exports, manager_file = args[4], args[5], args[6]
            server_config, core, backup_root = args[7], args[8], args[9]
            recover(backup_root, state_file, exports, manager_file, server_config, core)
        elif args and args[0] == 'journal-status':
            # args: journal-status ... backup_root  -> print the pending snapshot path, exit 2 if pending
            backup_root = args[9]
            jp = journal_path(backup_root)
            if jp.exists():
                print(json.loads(jp.read_text()).get('snapshot', ''))
                raise SystemExit(2)
            raise SystemExit(0)
        else:
            transaction(*args)
    except SystemExit:
        raise
    except (Exception, KeyboardInterrupt) as exc:
        print(f'POLICY ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
