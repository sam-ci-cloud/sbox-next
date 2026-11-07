"""REALITY relay health targets the VPN listener, not its separate fallback."""
from pathlib import Path
import json,os,re,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
class RelayFamily(unittest.TestCase):
 def test_vpn_listener_selects_probe_family(self):
  text=(ROOT/'src/manager.sh').read_text();body=re.search(r'^fallback_web_check\(\) \{\n(.*?)^\}',text,re.M|re.S)[0]
  for listener,fallback,expected in [('::1','127.0.0.1','::1'),('2001:db8::1','127.0.0.1','2001:db8::1'),('192.0.2.1','::1','192.0.2.1'),('0.0.0.0','::1','127.0.0.1'),('::','::1','127.0.0.1')]:
   with self.subTest(listener=listener,fallback=fallback),tempfile.TemporaryDirectory() as td:
    d=Path(td);(d/'python3').write_text('#!/bin/sh\nprintf "%s\\0" "$@"\n');(d/'python3').chmod(0o755);state=d/'state';state.write_text(json.dumps({'server':{'listen':listener},'protocols':{'reality':{'port':24443,'fallback':{'listen':fallback,'port':8443,'hostname':'cloud.sbox.test'}}}}));r=subprocess.run(['bash','-c',body+'\nFALLBACK_WEB_DIR=/synthetic; fallback_web_check "$1" via','test',str(state)],env={**os.environ,'PATH':str(d)+':'+os.environ['PATH']},capture_output=True);self.assertEqual(r.returncode,0,r.stderr.decode());args=r.stdout.decode().split('\0');self.assertEqual(args[args.index('--connect-host')+1],expected)
if __name__=='__main__':unittest.main(verbosity=2)
