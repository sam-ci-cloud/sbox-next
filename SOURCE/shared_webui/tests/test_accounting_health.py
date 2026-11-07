"""Fresh-looking persisted health cannot hide a failed collector or full disk."""
import json,os,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
import accounting as a
class Health(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name);self.engine=a.Engine(self.base,self.base/'data');self.health=self.engine.data/'health.json'
  self.health.write_text(json.dumps({'status':'ready','sampled_at':time.time(),'poll_seconds':2}))
 def tearDown(self):self.temp.cleanup()
 def test_full_disk_cannot_report_fresh_ready(self):
  with patch.object(a.os,'statvfs',return_value=SimpleNamespace(f_bavail=0,f_frsize=4096,f_flag=0)):
   self.assertEqual(self.engine.health()['status'],'degraded')
 def test_readonly_or_unwritable_storage_is_degraded(self):
  self.engine.data.chmod(0o500)
  try:self.assertEqual(self.engine.health()['status'],'degraded')
  finally:self.engine.data.chmod(0o700)
 def test_failed_service_overrides_fresh_ready_file(self):
  with patch.object(a.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='ActiveState=failed\nSubState=failed\nMainPID=0\n',stderr='')):
   self.assertEqual(self.engine.health()['status'],'degraded')
 def test_stale_and_future_heartbeat_are_not_ready(self):
  for stamp in [time.time()-60,time.time()+60]:
   self.health.write_text(json.dumps({'status':'ready','sampled_at':stamp}));self.assertEqual(self.engine.health()['status'],'degraded')
 def test_recovered_storage_and_fresh_live_service_ready(self):
  with patch.object(a.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='ActiveState=active\nSubState=running\nMainPID=123\n',stderr='')):
   self.assertEqual(self.engine.health()['status'],'ready')
 def test_unknown_collector_service_cannot_look_ready(self):
  with patch.object(a.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='not found')):
   self.assertEqual(self.engine.health()['status'],'degraded')
 def test_bad_heartbeat_type_is_unavailable(self):
  self.health.write_text('{"status":"ready","sampled_at":"bad"}');self.assertEqual(self.engine.health()['status'],'unavailable')
if __name__=='__main__':unittest.main(verbosity=2)
