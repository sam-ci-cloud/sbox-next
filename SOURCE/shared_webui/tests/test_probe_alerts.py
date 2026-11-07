"""Source-labelled network alerts resolve through the normal alert families."""
import sys,time,unittest,os
from pathlib import Path
sys.path.insert(0,str(Path(os.environ.get('SBOX_WEBUI_ROOT',Path(__file__).resolve().parents[1]))/'backend'))
from monitor import evaluate_alerts
import probes
class ProbeAlerts(unittest.TestCase):
 def test_latency_loss_dns_alerts_and_resolution_family(self):
  overview={'sampled_at':time.time(),'service':{'ActiveState':'active'},'probes':[{'target':'example.com','kind':'tcp','status':'loss','latency_ms':300,'loss_percent':33.3,'sampled_at':time.time()},{'target':'example.net','kind':'dns','status':'ok','dns_mismatch':True,'sampled_at':time.time()}]}
  families,alerts=evaluate_alerts(overview,{},None,0)
  self.assertIn('probe',families);self.assertEqual(len([k for k in alerts if k.startswith('probe.')]),3)
  for key in alerts:
   if key.startswith('probe.'):self.assertIn('this VPS',alerts[key][3])
  overview['probes']=[];families,alerts=evaluate_alerts(overview,{},None,0);self.assertIn('probe',families);self.assertFalse(any(k.startswith('probe.') for k in alerts))
 def test_expected_dns_addresses_must_be_public(self):
  for value in [['127.0.0.1'],['169.254.169.254'],['bad'], '1.1.1.1']:
   with self.assertRaises(Exception):probes.validate([{'host':'example.com','kind':'dns','expected_ips':value}])
  probes.validate([{'host':'example.com','kind':'dns','expected_ips':['1.1.1.1']}])
if __name__=='__main__':unittest.main()
