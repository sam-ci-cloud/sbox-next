"""Execution tests for CLI secret argv and noninteractive package boundaries."""
import os,pathlib,subprocess,sys,tempfile,unittest,json,importlib.util
from unittest.mock import patch
DEFAULT=pathlib.Path(__file__).resolve().parents[2]
ROOT=pathlib.Path(os.environ.get('SBOX_TEST_SOURCE', str(DEFAULT if (DEFAULT/'src').is_dir() else DEFAULT/'GENERIC/source'))).resolve()
if __name__=='__main__' and len(sys.argv)>1 and pathlib.Path(sys.argv[1]).is_dir():
    ROOT=pathlib.Path(sys.argv.pop(1)).resolve()
class Shell(unittest.TestCase):
    def test_nft_106_table_comment_uses_verified_text_fallback(self):
        spec=importlib.util.spec_from_file_location('tested_security',ROOT/'src/security.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        fixture=(pathlib.Path(__file__).parent/'nft-1.0.6.json').read_text()
        def fake(args,check=True):
            text=fixture if '-j' in args else 'table inet sbox_guard {\n comment "Managed by sbox-manager"\n set banned4 { type ipv4_addr; }\n}\n'
            return subprocess.CompletedProcess(args,0,stdout=text,stderr='')
        with patch.object(module,'run',side_effect=fake):self.assertIsNotNone(module.nft_state())
        def foreign(args,check=True):return subprocess.CompletedProcess(args,0,stdout=fixture if '-j' in args else 'table inet sbox_guard {\n comment "OTHER OWNER"\n}',stderr='')
        with patch.object(module,'run',side_effect=foreign),self.assertRaises(RuntimeError):module.nft_state()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        source=(ROOT/'src/manager.sh').read_text().removesuffix('main "$@"\n')
        for prefix in ['/etc/','/var/','/run/','/usr/local/']:source=source.replace(prefix,str(self.root)+prefix)
        self.functions=self.root/'functions';self.functions.write_text(source)
    def tearDown(self):self.tmp.cleanup()
    def bash(self,body):
        p=subprocess.run(['bash','-c','source "$FUNCTIONS"\n'+body],env={**os.environ,'FUNCTIONS':str(self.functions),'FIXTURE':str(self.root)},stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15)
        self.assertEqual(p.returncode,0,p.stderr[-1000:]+p.stdout[-1000:])
    def test_rotation_keeps_password_out_of_external_argv(self):
        self.bash('''mkdir -p "$FIXTURE/bin" "$RUNTIME_DIR"
printf '%s' '{"protocols":{"hy2":{"password":"INITIAL-SYNTHETIC"}}}' > "$FIXTURE/seed"
need_root() { :; }; require_installed() { :; }; acquire_session() { :; }
ensure_runtime_dir() { mkdir -p "$RUNTIME_DIR"; }
normalized_current_state() { cp "$FIXTURE/seed" "$1"; }
random_hex() { echo SYNTHETIC-NEW-SECRET-123456789; }
state_tool() { :; }; yes_no() { echo true; }; apply_candidate() { :; }
cat > "$FIXTURE/bin/jq" <<'SPY'
#!/bin/sh
printf '%s\\n' "$@" >> "$FIXTURE/jq-args"
exec /usr/bin/jq "$@"
SPY
chmod +x "$FIXTURE/bin/jq"; PATH="$FIXTURE/bin:$PATH"
rotate_command hy2
! grep -q SYNTHETIC-NEW-SECRET "$FIXTURE/jq-args"
''')
    def test_fresh_state_uses_private_jq_and_preserves_string_bytes(self):
        source=(ROOT/'src/manager.sh').read_text()
        guided=source.split('build_guided_state() {',1)[1].split('\n}',1)[0]
        self.assertIn('private_jq -n',guided)
        self.bash('''mkdir -p "$FIXTURE/bin"
ensure_runtime_dir() { mkdir -p "$RUNTIME_DIR"; }
cat > "$FIXTURE/bin/jq" <<'SPY'
#!/bin/sh
printf '%s\\n' "$@" > "$FIXTURE/jq-args"
exec /usr/bin/jq "$@"
SPY
chmod +x "$FIXTURE/bin/jq"; PATH="$FIXTURE/bin:$PATH"
value=$'SYNTHETIC-PRIVATE-STATE\\nwith spaces\\n'
private_jq -n --arg secret "$value" --arg empty '' '{secret:$secret,empty:$empty}' > "$FIXTURE/result"
! grep -q SYNTHETIC-PRIVATE-STATE "$FIXTURE/jq-args"
[ "$(jq -r .empty "$FIXTURE/result")" = '' ]
jq -e '.secret == "SYNTHETIC-PRIVATE-STATE\\nwith spaces\\n"' "$FIXTURE/result" >/dev/null
[ -z "$(find "$RUNTIME_DIR" -mindepth 1 -print -quit)" ]
''')
    def test_qr_receives_uri_on_stdin(self):
        self.bash('''mkdir -p "$FIXTURE/bin" "$EXPORT_DIR"
printf '[Synthetic]\\nvless://SYNTHETIC-SECRET@example.test:443\\n' > "$EXPORT_DIR/links.txt"
need_root() { :; }; require_installed() { :; }
cat > "$FIXTURE/bin/qrencode" <<'SPY'
#!/bin/sh
printf '%s\\n' "$@" > "$FIXTURE/qr-args"
cat > "$FIXTURE/qr-stdin"
SPY
chmod +x "$FIXTURE/bin/qrencode"; PATH="$FIXTURE/bin:$PATH"
links_command qr >/dev/null
! grep -q SYNTHETIC-SECRET "$FIXTURE/qr-args"
grep -q SYNTHETIC-SECRET "$FIXTURE/qr-stdin"
''')
    def test_packages_never_request_foreign_service_restarts(self):
        self.bash('''mkdir -p "$FIXTURE/bin"
base_dependencies_ready() { [ -f "$FIXTURE/installed" ]; }
wait_for_apt() { :; }; retry() { "$@"; }; logger() { :; }
cat > "$FIXTURE/bin/apt-get" <<'SPY'
#!/bin/sh
[ "$DEBIAN_FRONTEND" = noninteractive ]
[ "$NEEDRESTART_MODE" = l ] || exit 42
[ ! -t 0 ] || exit 43
touch "$FIXTURE/installed"
SPY
chmod +x "$FIXTURE/bin/apt-get"; PATH="$FIXTURE/bin:$PATH"
install_dependencies
''')
if __name__=='__main__':unittest.main(verbosity=2)
