#!/usr/bin/env python3
"""Non-mutating deterministic build. Seal ZGO separately with seal_zgo.py."""
from pathlib import Path
import base64,gzip,hashlib,io,json,re,subprocess,tarfile,tempfile,os,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import core_migration
from product_version import identity
def sha(b):return hashlib.sha256(b).hexdigest()
def packed(b):
 p=bytearray(gzip.compress(b,compresslevel=9,mtime=0));p[9]=255;return bytes(p)
def assets():
 subprocess.run(['python3',str(ROOT/'shared_webui/tools/build_frontend.py'),'--check'],check=True)
 files={str(p.relative_to(ROOT/'shared_webui')):p.read_bytes() for d in ('backend','frontend','privileged-bridge','api-spec','licenses') for p in sorted((ROOT/'shared_webui'/d).rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.inc','.sh')}
 files['MANIFEST.json']=(json.dumps({n:sha(b) for n,b in files.items()},sort_keys=True,indent=2)+'\n').encode()
 buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tf:
  for n,b in sorted(files.items()):
   m=tarfile.TarInfo(n);m.size=len(b);m.mode=0o644;m.mtime=0;m.uid=m.gid=0;tf.addfile(m,io.BytesIO(b))
 blob=packed(buf.getvalue())
 return (ROOT/'src/assets_writer.template').read_text().replace('@BASE64@',base64.b64encode(blob).decode()).replace('@SHA@',sha(blob))
def fallback_web():
 # SBOX Personal Cloud (self-hosted REALITY fallback): the hardened server and
 # the generated read-only site. Deterministic tar.gz with a content manifest.
 subprocess.run(['python3',str(ROOT/'src/fallback-web/build_site.py'),'--check'],check=True,stdout=subprocess.DEVNULL)
 base=ROOT/'src/fallback-web'
 files={'server.py':(base/'server.py').read_bytes()}
 files.update({'site/'+str(p.relative_to(base/'site')):p.read_bytes() for p in sorted((base/'site').rglob('*')) if p.is_file()})
 files['MANIFEST.json']=(json.dumps({n:sha(b) for n,b in files.items() if n!='MANIFEST.json'},sort_keys=True,indent=2)+'\n').encode()
 buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tf:
  for n,b in sorted(files.items()):
   m=tarfile.TarInfo(n);m.size=len(b);m.mode=0o644;m.mtime=0;m.uid=m.gid=0;tf.addfile(m,io.BytesIO(b))
 blob=packed(buf.getvalue());encoded=base64.b64encode(blob).decode()
 return '\n'.join(encoded[i:i+120] for i in range(0,len(encoded),120)),sha(blob)
def merge_helper(base,common,variant):
 # Preserve the owner's private variant, applying only common-source changes.
 # Conflicts are never printed because their text may contain private material.
 if common==base:return variant
 if variant==base or variant==common:return common
 with tempfile.TemporaryDirectory(prefix='sbox-private-helper-') as td:
  paths=[Path(td)/n for n in ('common','base','variant')]
  for p,value in zip(paths,(common,base,variant)):p.write_text(value);p.chmod(0o600)
  env={**os.environ,'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1'}
  try:r=subprocess.run(['git','merge-file','-p',*[str(p) for p in paths]],capture_output=True,text=True,env=env,timeout=30)
  except FileNotFoundError:raise ValueError('Git is required to merge private variant helper changes') from None
  if r.returncode:raise ValueError('Private helper conflicts with common source; resolve privately before sealing')
  return r.stdout
def integrate(text,variant,legacy_yaml=None):
 # Accept a private .4 manager or the public template, with no source mutations.
 if '# BEGIN SHARED WEBUI INTEGRATION' in text:
  text=text[:text.index('# BEGIN SHARED WEBUI INTEGRATION')]+ '@@WEBUI_INTEGRATION@@\nmain "$@"\n'
 # Both products obtain the VPN core only from the verified pinned core or a
 # SHA-256-verified local file. Older sealed managers are migrated exactly.
 text=core_migration.migrate(text)
 if legacy_yaml is not None:
  if variant!='zgocloud':raise ValueError('Original YAML is only valid for the private product')
  # Only ciphertext is public. Preserve the supplied document bytes, including
  # comments, ordering and line endings, rather than reconstructing a profile.
  encoded=base64.b64encode(legacy_yaml).decode()
  original='zgo_write_original_yaml() {\n  base64 -d > "$1" <<\'SBOX_ORIGINAL_YAML_BASE64\'\n'+encoded+'\nSBOX_ORIGINAL_YAML_BASE64\n  chmod 0600 "$1"\n}\n'
  if 'zgo_write_original_yaml()' in text:raise ValueError('Original document hook already present; use the original owner source')
  text=text.replace('@@WEBUI_INTEGRATION@@',original+'\n@@WEBUI_INTEGRATION@@')
 # Share only the exact known recovery comparison site with the private
 # original. A different private implementation fails before sealing.
 comparison=(ROOT/'src/snapshot_compare.inc').read_text().rstrip('\n')
 old_compare="    other=Path(sys.argv[3])\n    if inventory(root)!=inventory(other):raise SystemExit('restored tree differs from snapshot: '+str(other))"
 if text.count('@@SNAPSHOT_COMPARE@@')==1:text=text.replace('@@SNAPSHOT_COMPARE@@',comparison)
 elif text.count(old_compare)==1:text=text.replace(old_compare,comparison)
 elif text.count(comparison)==1:pass  # A previously integrated current manager.
 elif text.count((ROOT/'src/helper-merge-baselines/snapshot_compare.inc').read_text().rstrip('\n'))==1:
  # The exact previous shared comparison (1.8.x-1.9.0rc) gains quota-limit support.
  text=text.replace((ROOT/'src/helper-merge-baselines/snapshot_compare.inc').read_text().rstrip('\n'),comparison)
 else:raise ValueError('Shared snapshot comparison hook not recognized')
 old_verify='    runtime_snapshot_tool compare "$snap/base" "$BASE_DIR" || return 1'
 new_verify='    runtime_snapshot_tool compare "$snap/base" "$BASE_DIR" "${3:-strict}" || return 1'
 if text.count(old_verify)==1:text=text.replace(old_verify,new_verify)
 elif text.count(new_verify)!=1:raise ValueError('Shared staging verification hook not recognized')
 ext=(ROOT/'shared_webui/privileged-bridge/manager_extension.sh').read_text().replace('@VARIANT@',variant)
 retention=(ROOT/'src/retention.py').read_text()
 ext+='\nwrite_retention_helper() {\n  cat <<\'SBOX_RETENTION_PY\'\n'+retention+'SBOX_RETENTION_PY\n}\n'
 network=(ROOT/'shared_webui/backend/network_policy.py').read_text()
 ext+='\nwrite_network_helper() {\n  cat <<\'SBOX_NETWORK_PY\'\n'+network+'SBOX_NETWORK_PY\n}\n'
 text=text.replace('snapshot_runtime() {','snapshot_runtime_base() {').replace('restore_runtime() (','restore_runtime_base() (')
 if variant=='universal':text=text.replace('    fallback_web_verify_relay "$candidate_state"\n','    fallback_web_verify_relay "$candidate_state"\n    webui_network_apply "$candidate_state"\n')
 ext+='\nunified_backup_dispatch() {\n  if [ "${1:-}" = retention ]; then\n    shift; need_root; require_installed; acquire_lock; guard_no_pending_transaction\n    write_retention_helper | python3 - --root "$BACKUP_DIR" --base "$BASE_DIR" "$@"\n  else\n    [ "$#" -eq 0 ] || die "Usage: sbox backup [retention [--keep-backups N --keep-policies N --prune]]"\n    backup_command\n  fi\n}\n'
 # Reuse the full generic state-driven performance dispatcher in both managers.
 if variant=='zgocloud':
  source=(ROOT/'src/manager.sh').read_text()
  dispatcher=source[source.index('performance_command() ('):source.index('\nmain() {',source.index('performance_command() ('))]
  text=re.sub(r'^performance_command\(\) \(.*?^\)\n',lambda m:dispatcher+'\n',text,count=1,flags=re.M|re.S)
 text=text.replace('backup) backup_command ;;','backup) unified_backup_dispatch "$@" ;;')
 if variant=='zgocloud':
  # TCP Fast Open is a supported opt-in socket flag, not an identity. Preserve
  # every other protocol field plus domain/TLS/firewall checks exactly.
  old_guard='.protocols == $e[0].protocols and .firewall.enabled == true and'
  new_guard='(.protocols.reality.tcp_fast_open // false | type) == "boolean" and\n    (.protocols | del(.reality.tcp_fast_open)) == ($e[0].protocols | del(.reality.tcp_fast_open)) and .firewall.enabled == true and'
  if old_guard in text:
   if text.count(old_guard)!=1:raise ValueError('Protected identity guard is ambiguous')
   text=text.replace(old_guard,new_guard)
  elif text.count(new_guard)!=1:raise ValueError('Protected identity guard not recognized; no compatibility bypass')
  old_identity='($actual.protocols.reality == $e.protocols.reality)'
  new_identity='(($actual.protocols.reality | del(.tcp_fast_open)) == ($e.protocols.reality | del(.tcp_fast_open)))'
  if old_identity in text:text=text.replace(old_identity,new_identity)
  elif text.count(new_identity)!=1:raise ValueError('Protected verification identity projection not recognized')
  live_hook=".certificate=$live[0].certificate | .managed_users=($live[0].managed_users // []) | if $live[0].accounting then .accounting=$live[0].accounting else . end"
  live_with_performance=".certificate=$live[0].certificate | .managed_users=($live[0].managed_users // []) | .protocols.reality.tcp_fast_open=($live[0].protocols.reality.tcp_fast_open // false) | .server_dns=($live[0].server_dns // {}) | if $live[0].accounting then .accounting=$live[0].accounting else . end"
  if live_hook in text:text=text.replace(live_hook,live_with_performance)
  elif text.count(live_with_performance)!=1:raise ValueError('Protected live config verification hook not recognized')


 # The inherited early parser forbids arguments for backup; the new dispatcher
 # validates them and preserves rejection for every other command.
 text=re.sub(r'(^[^\n]*\|backup\|[^\n]*\)\n[ \t]+\[ "\$#" -eq 0 \])',lambda m:m[0].replace('|backup|','|'),text,flags=re.M)

 # Doctor JSON and its WebUI rendering use the same bounded cached APT check.
 doctor_update='  local os_updates\n  os_updates="$(write_performance_helper | python3 - --os-updates)"\n  doctor_record info "OS maintenance (cached APT; no changes): $os_updates"\n'
 doctor_start=text.index('doctor_command() {')
 doctor_end=text.index('\n}\n',doctor_start)
 body=text[doctor_start:doctor_end]
 if 'OS maintenance (cached APT' not in body:
  body=body.replace('  if [ "$DOCTOR_JSON" = true ]; then',doctor_update+'  if [ "$DOCTOR_JSON" = true ]; then')
  text=text[:doctor_start]+body+text[doctor_end:]

 # Universal-only self-hosted REALITY website. The private ZgoCloud manager has
 # no such hook, so its text is never changed by this step.
 if '@@FALLBACK_WEB_BUNDLE@@' in text:
  if variant=='universal':
   bundle,digest=fallback_web()
  else:
   # A ZgoCloud build never carries the website: no payload, explicit marker.
   bundle,digest='','disabled'
  text=text.replace('@@FALLBACK_WEB_BUNDLE@@',bundle).replace('@@FALLBACK_WEB_SHA256@@',digest)
 text=text.replace('@@WEBUI_INTEGRATION@@','# BEGIN SHARED WEBUI INTEGRATION\n'+(ROOT/'src/certificate_reuse.sh').read_text()+'\n'+assets()+'\n'+ext+'\n# END SHARED WEBUI INTEGRATION')
 for name,marker in [('state','PY'),('policy','PYPOLICY'),('performance','SBOX_PERFORMANCE_PY'),('security','SBOX_SECURITY_PY'),('hardening','SBOX_HARDENING_PY')]:
  token=f'@@HELPER_{name.upper()}@@'
  common=(ROOT/'src'/f'{name}.py').read_text()
  if token in text:
   helper=f"write_{name}_helper() {{\n  cat <<'{marker}'\n"+common+f'{marker}\n}}'
   text=text.replace(token,helper)
  else:
   pattern=r"^write_"+name+r"_helper\(\) \{\n  cat <<'"+marker+r"'\n(.*?)^"+marker+r"\n\}"
   matches=list(re.finditer(pattern,text,flags=re.M|re.S))
   # 1.8.0: the default-drop gate (D4) is a Generic-manager feature. A protected
   # manager that never had the helper keeps its own firewall code unchanged.
   if name=='hardening' and variant=='zgocloud' and not matches:continue
   if len(matches)!=1:raise ValueError('Expected one corresponding '+name+' helper')
   body=common
   if variant=='zgocloud':
    merge_base=ROOT/'src/helper-merge-baselines'/f'{name}.py'
    if not merge_base.exists():merge_base=ROOT/'src/helper-baselines'/f'{name}.py'
    body=merge_helper(merge_base.read_text(),common,matches[0][1])
   helper=f"write_{name}_helper() {{\n  cat <<'{marker}'\n"+body+f'{marker}\n}}'
   text=re.sub(pattern,lambda m:helper,text,flags=re.M|re.S)
 text=text.replace('  local range conflict\n  range="$(jq -r \'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end\' "$state")"\n  if [ -n "$range" ]; then\n','  local range conflict current_range=\'\'\n  range="$(jq -r \'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end\' "$state")"\n  # Keeping an already owned NAT range does not claim new listener ports.\n  # Resolver/outbound sockets can temporarily use ephemeral ports in that range.\n  if state_exists; then current_range="$(jq -r \'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end\' "$STATE_FILE")"; fi\n  if [ -n "$range" ] && [ "$range" != "$current_range" ]; then\n')
 text=text.replace('requested="${OPT_core:-1.13.14}"','requested="${OPT_core:-${SBOX_ACCOUNTING_CORE_SOURCE:-1.13.14}}"')
 if variant=='zgocloud':
  old='[ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = 24.04 ] && [ "$(uname -m)" = x86_64 ]'
  new='[ "${ID:-}" = ubuntu ] && { [ "${VERSION_ID:-}" = 24.04 ] || [ "${VERSION_ID:-}" = 26.04 ]; } && [ "$(uname -m)" = x86_64 ]'
  if old not in text and new not in text:raise ValueError('ZgoCloud OS guard not recognized')
  text=text.replace(old,new).replace('Automatic deployment is supported on Ubuntu 24.04 x86_64.','Automatic deployment is supported on Ubuntu 24.04/26.04 x86_64.')
  needle='  state_tool render "$state" "$out"\n'
  if legacy_yaml is not None:
   if text.count(needle)!=1:raise ValueError('Private render hook not recognized')
   text=text.replace(needle,needle+'  zgo_write_original_yaml "$out/ZgoCloud-original.yaml"\n')
 # Validate supported probe policy values in the protected shell as well;
 # original fixed YAML bytes and identity literals remain untouched.
 text=text.replace("assert groups['🧠 Smart Auto']['tolerance'] == 120", "assert type(groups['🧠 Smart Auto']['tolerance']) is int and 10 <= groups['🧠 Smart Auto']['tolerance'] <= 300")
 text=text.replace("assert str(groups['🧠 Smart Auto']['expected-status']) == '204'", "assert str(groups['🧠 Smart Auto']['expected-status']) in {'200','204','200/204'}")
 text=text.replace("assert str(groups['🛡 Anti-Block Auto']['expected-status']) == '204'", "assert groups['🛡 Anti-Block Auto']['expected-status'] == groups['🧠 Smart Auto']['expected-status']")
 # 1.8.0 D1: the VPN selector default is an owner choice (Anti-Block or Smart Auto).
 text=text.replace("assert vpn['default-selected'] == '🛡 Anti-Block Auto'", "assert vpn['default-selected'] in ('🛡 Anti-Block Auto', '🧠 Smart Auto')")
 # 1.8.0 D6: health-check timing is an owner setting (validated in state.py).
 text=text.replace("    assert groups['🧠 Smart Auto']['interval'] == 60\n    assert groups['🧠 Smart Auto']['timeout'] == 5000\n", "    assert type(groups['🧠 Smart Auto']['interval']) is int and 30 <= groups['🧠 Smart Auto']['interval'] <= 600\n    assert type(groups['🧠 Smart Auto']['timeout']) is int and 1000 <= groups['🧠 Smart Auto']['timeout'] < groups['🧠 Smart Auto']['interval'] * 1000\n")
 text=text.replace("    assert groups['🧠 Smart Auto']['max-failed-times'] == 2\n", "    assert type(groups['🧠 Smart Auto']['max-failed-times']) is int and 1 <= groups['🧠 Smart Auto']['max-failed-times'] <= 5\n")
 text=text.replace("    assert groups['🛡 Anti-Block Auto']['interval'] == 60\n    assert groups['🛡 Anti-Block Auto']['timeout'] == 5000\n    assert groups['🛡 Anti-Block Auto']['max-failed-times'] == 2\n", "    for key in ('interval', 'timeout', 'max-failed-times'):\n        assert groups['🛡 Anti-Block Auto'][key] == groups['🧠 Smart Auto'][key]\n")
 # A built, tested resolver result may change engine version without losing quotas.
 old_update='  apply_candidate "$candidate" "$binary" "sing-box core update"'
 new_update='''  if jq -e '.accounting.enabled == true' "$current" >/dev/null; then
    local new_sha old_sha
    new_sha="$(sha256sum "$binary" | cut -d' ' -f1)"; old_sha="$(jq -r .accounting.core_sha256 "$current")"
    if [ "$new_sha" != "$old_sha" ]; then
      [ -f "$binary.provenance.json" ] && jq -e --arg sha "$new_sha" --arg version "$version" \\
        '.sha256==$sha and .version==$version and (.tests_passed==true or .origin=="bundled") and ([.coverage.reality,.coverage.vmess,.coverage.hy2,.coverage.tuic,.coverage.anytls]|all)' "$binary.provenance.json" >/dev/null || die 'Accounting core update lacks tested patch provenance; current core retained.'
      jq --arg sha "$new_sha" '.accounting.core_sha256=$sha' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"
    fi
  fi
  apply_candidate "$candidate" "$binary" "sing-box core update"
  if jq -e '.accounting.enabled == true' "$candidate" >/dev/null; then accounting_start_ready; fi'''
 if new_update not in text:
  if text.count(old_update)!=1:raise ValueError('Accounting update integration site not recognized')
  text=text.replace(old_update,new_update)
 # A backup authenticates its own exact core against its accounting state.
 text=text.replace('$(jq -r .sha256 /usr/local/lib/sbox-accounting/current/core_manifest.json)', '$(jq -r .accounting.core_sha256 "$candidate")')
 version=json.loads((ROOT/'assets/release.json').read_text())['products'][variant]
 text=re.sub(r'^MANAGER_VERSION="[^"]+"',f'MANAGER_VERSION="{version}"',text,flags=re.M)
 text=text.replace('rsyslog python3-systemd python3 python3-yaml qrencode','rsyslog python3-systemd python3 python3-yaml python3-h2 qrencode')
 old_cert='    cert="$(jq -r \'.certificate.source_fullchain\' "$candidate_state")"; key="$(jq -r \'.certificate.source_key\' "$candidate_state")"\n    certificate_pair_ok "$cert" "$key" || { rm -rf "$tx"; die "Candidate certificate/key pair is invalid."; }'
 new_cert='    select_candidate_certificate "$candidate_state" || { rm -rf "$tx"; die "Candidate certificate/key pair is invalid."; }\n    cert="$EFFECTIVE_CERT"; key="$EFFECTIVE_KEY"'
 text=text.replace(old_cert,new_cert)
 if 'select_candidate_certificate "$candidate_state"' not in text:raise ValueError('Shared managed-certificate call site missing')
 # Refresh the independent collector around native tree restoration in both
 # products. Private source must match the exact known legacy hook sites.
 for label,needle in (
  ('PAUSE',"  restore_attempt 'base tree' restore_tree base \"$BASE_DIR\""),
  ('RESUME','  [ \"$failed\" -eq 0 ] || warn \"Recovery completed its VPN attempts with failures; snapshot/journal must be retained.\"')):
  hook=(ROOT/'src'/('collector_restore_'+label.lower()+'.inc')).read_text().rstrip('\n')
  token='@@COLLECTOR_RESTORE_'+label+'@@'
  if text.count(token)==1:text=text.replace(token,hook)
  elif text.count(hook)==1:pass
  elif text.count(needle)==1:text=text.replace(needle,hook+'\n'+needle)
  else:raise ValueError('Native collector recovery hook not recognized')
 # Full backups must include the panel DB, where subscription hashes, MFA and
 # administrator accounts live. Both products use the same optional hooks.
 backup_hook='  printf \'%s\\n\' "$MANAGER_VERSION" > "$payload/manager-version.txt"\n'
 restore_hook='  SBOX_INITIALIZE_SECURITY=true RESTORE_EXPORT_SOURCE="$root/exports" apply_candidate "$candidate" "$binary" "backup restore"\n'
 for needle in (backup_hook,restore_hook):
  if text.count(needle)!=1:raise ValueError('Shared panel backup/restore hook not recognized')
 if '  webui_backup_snapshot "$payload"\n' not in text:text=text.replace(backup_hook,'  webui_backup_snapshot "$payload"\n'+backup_hook)
 if '  webui_restore_data validate "$root"\n' not in text:text=text.replace(restore_hook,'  webui_restore_data validate "$root"\n'+restore_hook+'  webui_restore_data restore "$root"\n')
 old_restore_collector='    python3 -B /usr/local/lib/sbox-accounting/current/accounting.py reconcile --inherited-lock >&2\n    systemctl enable --now sbox-accounting.service\n'
 text=text.replace(old_restore_collector,'    accounting_start_ready\n')
 if '    accounting_start_ready\n' not in text:raise ValueError('Backup collector refresh hook not recognized')
 # Disable inherited xtrace before handling any identity or generated credentials.
 text=re.sub(r'\A(#!/usr/bin/env bash\n)(?:set \+xv\n)*',r'\1set +xv\n',text,count=1)
 canonical=re.sub(r'MANAGER_BUILD_ID="[^"]+"','MANAGER_BUILD_ID="@BUILD_ID@"',text)
 return re.sub(r'MANAGER_BUILD_ID="[^"]+"','MANAGER_BUILD_ID="b-'+sha(canonical.encode())[:24]+'"',text).encode()
def reproducible_zlib():
 # The recorded installer bytes are produced by stock zlib (Ubuntu 24.04
 # zlib1g 1.3). zlib-ng and other forks emit different, equally valid DEFLATE
 # streams, which would silently break byte-for-byte reproducibility.
 import zlib
 version=zlib.ZLIB_RUNTIME_VERSION
 if ('ng' in version.lower() or version.split('.')[0]!='1') and os.environ.get('SBOX_ALLOW_NONSTANDARD_ZLIB')!='1':
  raise SystemExit('tools/build.py: Python uses zlib '+version+'; reproducible builds need stock zlib 1.x (see docs/development.md). Set SBOX_ALLOW_NONSTANDARD_ZLIB=1 only for a non-release experiment.')
def main():
 reproducible_zlib()
 out=ROOT/'.build';(out/'src').mkdir(parents=True,exist_ok=True)
 manager=integrate((ROOT/'src/manager.sh').read_text(),'universal');(out/'src/manager.sh').write_bytes(manager)
 for f in ('state.py','policy.py','security.py','performance.py'):(out/'src'/f).write_bytes((ROOT/'src'/f).read_bytes())
 data={'GENERIC':packed(manager),'ZGO':(ROOT/'assets/zgocloud.enc').read_bytes(),'CORE':(ROOT/'assets/sing-box-accounting.gz').read_bytes()}
 zgo=json.loads((ROOT/'assets/zgocloud.json').read_text())
 core=gzip.decompress(data['CORE']);expected=json.loads((ROOT/'shared_webui/backend/core_manifest.json').read_text())['sha256'];assert sha(core)==expected
 manifest={'version':identity()['version'],'repository':identity()['repository'],'generic_manager_sha256':sha(manager),'zgo_manager_sha256':zgo['manager_sha256'],'core_sha256':expected,'core_gzip_sha256':sha(data['CORE']),'generic_gzip_sha256':sha(data['GENERIC']),'zgo_envelope_sha256':sha(data['ZGO'])}
 text=(ROOT/'src/install.template.sh').read_text()
 release=json.loads((ROOT/'assets/release.json').read_text())
 text=text.replace('@@GENERIC_VERSION@@',release['products']['universal']).replace('@@ZGO_VERSION@@',release['products']['zgocloud'])
 for key,b in data.items():
  encoded=base64.b64encode(b).decode();text=text.replace('@@'+key+'_B64@@','\n'.join(encoded[i:i+120] for i in range(0,len(encoded),120)))
 for k,v in manifest.items():text=text.replace('@@'+k.upper()+'@@',v)
 text=text.replace('@@UNLOCK_PY@@',(ROOT/'src/unlock.py').read_text())
 assert '@@' not in text
 (ROOT/'install.sh').write_text(text);(ROOT/'install.sh').chmod(0o755)
 (ROOT/'BUILD.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 subprocess.run(['bash','-n',str(ROOT/'install.sh')],check=True);subprocess.run(['bash','-n',str(out/'src/manager.sh')],check=True)
 print(sha(text.encode())+'  install.sh')
if __name__=='__main__':main()
