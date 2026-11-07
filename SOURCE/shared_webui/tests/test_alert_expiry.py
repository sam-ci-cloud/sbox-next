"""Expiry alerts must name the certificate and its unambiguous UTC deadline."""
import os,pathlib,sys,time,unittest
ROOT=pathlib.Path(os.environ.get('SBOX_WEBUI_ROOT',pathlib.Path(__file__).resolve().parents[1]));sys.path.insert(0,str(ROOT/'backend'))
import monitor
class Expiry(unittest.TestCase):
 def test_expired_critical_and_warning_include_exact_deadline(self):
  now=1792800000
  for offset in [-86400,86400,10*86400]:
   expires=now+offset;_,active=monitor.evaluate_alerts({'service':{'ActiveState':'active'}},{'domain':'vpn.example.test','expires_at':expires},None,0,now=now)
   detail=active['cert.expiry'][2]
   self.assertIn('vpn.example.test',detail)
   self.assertIn(time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime(expires)),detail)
if __name__=='__main__':unittest.main(verbosity=2)
