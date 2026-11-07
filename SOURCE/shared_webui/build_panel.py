"""Integrate the common source snapshot into either unchanged manager baseline.

Usage: python3 build_panel.py SOURCE_TREE universal|zgocloud [SHARED_SOURCE]
Repeated builds are deterministic and do not require npm/network access.
"""
import base64,gzip,hashlib,io,json,re,shutil,subprocess,sys,tarfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();variant=sys.argv[2]
shared=Path(sys.argv[3]).resolve() if len(sys.argv)>3 else root/'shared_webui'
assert variant in ('universal','zgocloud')
# Generated single-file frontend must match its readable sources (no hand patches).
if (shared/'tools/build_frontend.py').exists():
    subprocess.run([sys.executable,str(shared/'tools/build_frontend.py'),'--check'],check=True)
runtime={}
for dirname in ('backend','frontend','privileged-bridge','api-spec','licenses'):
    for p in sorted((shared/dirname).rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.inc','.sh'):
            runtime[str(p.relative_to(shared))]=p.read_bytes()
manifest={n:hashlib.sha256(b).hexdigest() for n,b in runtime.items()}
runtime['MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as archive:
    for name,data in sorted(runtime.items()):
        member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o644;member.mtime=0;member.uid=member.gid=0
        archive.addfile(member,io.BytesIO(data))
blob=bytearray(gzip.compress(buf.getvalue(),compresslevel=9,mtime=0))
# Python 3.11/3.12 delegated mtime=0 gzip to zlib (OS byte 3 on Linux),
# while 3.13+ emits 255. Canonicalize the header across supported runtimes.
blob[9]=255;blob=bytes(blob)
encoded=base64.b64encode(blob).decode();sha=hashlib.sha256(blob).hexdigest()
writer='''write_webui_assets() {
  python3 - "$1" <<'SBOX_WEBUI_ASSETS'
import base64,gzip,hashlib,io,json,os,sys,tarfile
from pathlib import Path,PurePosixPath
blob=base64.b64decode('@BASE64@',validate=True)
if hashlib.sha256(blob).hexdigest()!='@SHA@':raise SystemExit('Panel asset digest mismatch')
root=Path(sys.argv[1])
if root.is_symlink() or not root.is_dir():raise SystemExit('Unsafe panel extraction target')
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(blob))) as archive:
    members=archive.getmembers();seen=set();files={}
    for m in members:
        p=PurePosixPath(m.name)
        if not m.isfile() or m.name in seen or p.is_absolute() or '..' in p.parts or str(p)!=m.name or m.size>1048576:raise SystemExit('Unsafe panel member')
        seen.add(m.name);files[m.name]=archive.extractfile(m).read()
    manifest=json.loads(files.pop('MANIFEST.json'))
    if set(files)!=set(manifest):raise SystemExit('Panel manifest mismatch')
    for name,data in files.items():
        if hashlib.sha256(data).hexdigest()!=manifest[name]:raise SystemExit('Panel component digest mismatch')
    files['MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\\n').encode()
    for name,data in files.items():
        target=root/name
        if root.resolve() not in target.resolve().parents:raise SystemExit('Panel traversal refused')
        target.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'wb') as stream:stream.write(data)
SBOX_WEBUI_ASSETS
}
'''.replace('@BASE64@',encoded).replace('@SHA@',sha)
manager=root/'src/manager.sh';text=manager.read_text()
start='# BEGIN SHARED WEBUI INTEGRATION\n';end='# END SHARED WEBUI INTEGRATION\n'
if start in text:text=text[:text.index(start)]+text[text.index(end)+len(end):]
extension=(shared/'privileged-bridge/manager_extension.sh').read_text().replace('@VARIANT@',variant)
assert text.endswith('main "$@"\n')
text=text[:-len('main "$@"\n')]+start+writer+'\n'+extension+'\n'+end+'main "$@"\n'
if '    webui) webui_command "$@" ;;' not in text:
    text=text.replace('    performance) performance_command "$@" ;;','    webui) webui_command "$@" ;;\n    _webui-control) webui_control_command "$@" ;;\n    performance) performance_command "$@" ;;')
    text=text.replace('  performance report [--json]', '  webui install|upgrade|start|stop|status|doctor|reset-admin|rollback|uninstall\n  performance report [--json]',1)
    # Fresh guided generic and explicit ZGO installer share this call-site.
    text=text.replace('  rm -rf "$temp"\n  print_completion_summary\n}', '  rm -rf "$temp"\n  webui_install_if_enabled\n  print_completion_summary\n}',1)
    if variant=='zgocloud':
        text=text.replace('  zgo_stage complete\n  rm -rf -- "$temp"\n  print_completion_summary', '  webui_install_if_enabled\n  zgo_stage complete\n  rm -rf -- "$temp"\n  print_completion_summary',1)
        text=text.replace("        ok 'Existing installation is healthy;", "        webui_install_if_enabled\n        ok 'Existing installation is healthy;",1)
        text=text.replace('    zgo_stage complete\n    return 0', '    webui_install_if_enabled\n    zgo_stage complete\n    return 0',1)
manager.write_text(text)
text=manager.read_text()
uninstall_marker='  # Non-runtime cleanup follows the verified commit;'
if 'Panel lifecycle cleanup follows verified VPN uninstall' not in text:
    text=text.replace(uninstall_marker,'''  # Panel lifecycle cleanup follows verified VPN uninstall.
  if [ -f /etc/systemd/system/sbox-webui.service ] && [ -f /usr/local/lib/sbox-webui/current/backend/install.py ]; then
    python3 /usr/local/lib/sbox-webui/current/backend/install.py uninstall
  fi
'''+uninstall_marker,1)
manager.write_text(text)
state=root/'src/state.py';text=state.read_text()
v='# BEGIN WEBUI USER VALIDATION\n';rend='# BEGIN WEBUI USER RENDER\n'
if v not in text:
    text=text.replace("if action == 'validate':",v+(shared/'backend/state_validation.inc').read_text()+"\n# END WEBUI USER VALIDATION\n\nif action == 'validate':",1)
    text=text.replace("route_rules = []",rend+(shared/'backend/state_render.inc').read_text()+"\n# END WEBUI USER RENDER\n\nroute_rules = []",1)
else:
    text=re.sub(r'# BEGIN WEBUI USER VALIDATION\n.*?# END WEBUI USER VALIDATION',lambda m:v+(shared/'backend/state_validation.inc').read_text()+'\n# END WEBUI USER VALIDATION',text,flags=re.S)
    text=re.sub(r'# BEGIN WEBUI USER RENDER\n.*?# END WEBUI USER RENDER',lambda m:rend+(shared/'backend/state_render.inc').read_text()+'\n# END WEBUI USER RENDER',text,flags=re.S)
dns_start='    # BEGIN WEBUI CLIENT DNS\n';dns_end='    # END WEBUI CLIENT DNS'
if dns_start not in text:
    text=text.replace('    return dns',dns_start+(shared/'backend/state_dns.inc').read_text()+'\n'+dns_end+'\n    return dns',1)
    text=text.replace("    rules.append(f'MATCH,{vpn_group_name}')","    if profile != 'internal':rules=list(client_rules)+rules\n    rules.append(f'MATCH,{vpn_group_name}')",1)
else:
    text=re.sub(r'    # BEGIN WEBUI CLIENT DNS\n.*?    # END WEBUI CLIENT DNS',lambda m:dns_start+(shared/'backend/state_dns.inc').read_text()+'\n'+dns_end,text,flags=re.S)
state.write_text(text)
subprocess.run([sys.executable,str(root/'tools/build_core.py')],check=True)
if variant=='universal':shutil.copyfile(root/'universal-installer.sh',root/'SBOX-Universal-Install.sh');(root/'SBOX-Universal-Install.sh').chmod(0o755)
print('Shared panel assets SHA256: '+sha)
