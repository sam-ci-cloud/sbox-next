from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend import monitor
class AccountingDashboard(unittest.TestCase):
 def dashboard(self):return {'status':'ok','tiles':[]}
 def test_degraded_is_not_green(self):
  value=self.dashboard();monitor.accounting_health(value,{'status':'degraded','reason':'Collector stopped','sampled_at':100},now=101)
  self.assertEqual(value['status'],'warning');self.assertEqual(value['tiles'][0]['detail']['reason'],'Collector stopped')
 def test_stale_ready_is_not_green(self):
  value=self.dashboard();monitor.accounting_health(value,{'status':'ready','sampled_at':1,'poll_seconds':2},now=100)
  self.assertEqual(value['status'],'warning')
 def test_unavailable_not_green_and_does_not_hide_other_errors(self):
  value=self.dashboard();value['status']='error';monitor.accounting_health(value,{},now=100)
  self.assertEqual(value['status'],'error');self.assertEqual(value['tiles'][0]['status'],'warning')
 def test_fresh_ready(self):
  value=self.dashboard();monitor.accounting_health(value,{'status':'ready','sampled_at':99,'poll_seconds':2},now=100)
  self.assertEqual(value['status'],'ok');self.assertEqual(value['tiles'][0]['status'],'ok')
 def test_explicit_advanced_dimensions_are_not_mislabelled_as_legacy(self):
  family={'mode':'preserve','policies':{'inbound':'ipv4','egress':'dual','dns':'dual','client':'ipv4'}};value=monitor.dashboard({'deployment_family':family},{},now=100);tile=next(t for t in value['tiles'] if t['key']=='network');self.assertEqual(tile['value'],'advanced');self.assertEqual(tile['detail']['policies'],family['policies'])
if __name__=='__main__':unittest.main(verbosity=2)
