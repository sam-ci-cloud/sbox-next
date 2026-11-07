"""Inject a postcommit health failure into real manager functions in a disposable VM.
The staged config is installed and the real core restarted, then one health check
returns failure. The unmodified rollback/verification paths must restore state.
"""
from pathlib import Path
import subprocess,json,hashlib,os,time
assert os.geteuid()==0 and Path('/root/lab-ready').is_file()
os.umask(0o077)
p=Path('/opt/sbox-lab/postcommit-failure');p.mkdir(exist_ok=True)
state=Path('/etc/sbox-manager/state.json');config=Path('/etc/sbox-manager/config.json')
before={'state':hashlib.sha256(state.read_bytes()).hexdigest(),'config':hashlib.sha256(config.read_bytes()).hexdigest()};old=json.loads(state.read_text())
source=Path('/usr/local/lib/sbox-manager/manager').read_text().removesuffix('main "$@"\n')
marker=p/'postcommit-health-failed';marker.unlink(missing_ok=True)
body=source+'''
SBOX_MANAGER_SOURCE=/usr/local/lib/sbox-manager/manager
ensure_runtime_dir; acquire_lock; guard_no_pending_transaction
original_listen=$(jq -r '.server.listen' "$STATE_FILE")
eval "$(declare -f service_stable | sed '1s/service_stable/service_stable_real/')"
service_stable() {
 if [ "$(jq -r '.server.listen' "$STATE_FILE")" != "$original_listen" ]; then
  touch /opt/sbox-lab/postcommit-failure/postcommit-health-failed
  return 1
 fi
 service_stable_real "$@"
}
temp=$(mktemp -d "$RUNTIME_DIR/health-fail.XXXXXXXX")
normalized_current_state "$temp/state"
jq '.server.listen=(if .server.listen=="::" then "0.0.0.0" else "::" end)' "$temp/state" > "$temp/candidate"
apply_candidate "$temp/candidate" '' 'disposable postcommit health injection'
'''
f=p/'inject.sh';f.write_text(body);f.chmod(0o700)
r=subprocess.run(['bash',str(f)],capture_output=True,text=True,timeout=240);(p/'private.log').write_text(r.stdout+r.stderr)
assert marker.exists(),'real postcommit gate was not reached'
assert r.returncode!=0,'failed postcommit was incorrectly successful'
assert 'previous runtime was restored and verified' in r.stdout+r.stderr
assert before=={'state':hashlib.sha256(state.read_bytes()).hexdigest(),'config':hashlib.sha256(config.read_bytes()).hexdigest()}
assert not Path('/var/lib/sbox-manager/transaction.json').exists()
assert json.loads(state.read_text())['protocols']==old['protocols']
doctor=subprocess.run(['sbox','doctor','--json'],capture_output=True,text=True,timeout=120);assert doctor.returncode==0;assert json.loads(doctor.stdout)['failures']==0
result={'status':'PASS','scope':'Real installed KVM core, candidate committed and restarted; injected service_stable failure; unmodified automatic rollback','gate_reached':True,'apply_exit':r.returncode,'state_and_config_restored':True,'all_protocol_identities_restored':True,'journal_cleared_after_verified_rollback':True,'doctor_failures':0}
(p/'postcommit-failure.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
