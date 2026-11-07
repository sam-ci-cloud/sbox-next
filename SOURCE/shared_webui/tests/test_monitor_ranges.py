"""Selected host-monitor ranges must reach storage and preserve exact chart bounds."""
from pathlib import Path
import sys,tempfile,time,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
import monitor
from store import Store
class MonitorRanges(unittest.TestCase):
 def test_presets_custom_bounds_and_storage_exclude_future_samples(self):
  now=time.time(); windows={'1h':3600,'6h':21600,'24h':86400,'7d':604800,'30d':2592000}
  for name,seconds in windows.items():self.assertEqual(monitor.selected_range({'window':name},now),(seconds,now))
  start,end=int(now)-1000,int(now)-400
  self.assertEqual(monitor.selected_range({'window':'custom','start':str(start),'end':str(end)},now),(600,end))
  for query in ({'window':'bad'},{'window':'custom','start':'nan','end':str(end)},{'window':'custom','start':str(end),'end':str(start)},{'window':'custom','start':str(now-40*86400),'end':str(end)},{'window':'1h','start':str(start)}):
   with self.subTest(query=query),self.assertRaises(ValueError):monitor.selected_range(query,now)
  with tempfile.TemporaryDirectory() as d:
   store=Store(Path(d)/'panel.sqlite')
   for at in (start-30,start,start+30,end,end+30):store.sample({'sampled_at':at,'network':{'eth0':{'rx':int(at),'tx':int(at)}}})
   samples=store.history(600,end=end)
   self.assertEqual([s['sampled_at'] for s in samples],[start,start+30,end])
   rates=monitor.rate_series(samples,600,now=end)
   self.assertEqual((rates['start'],rates['end']),(start,end))
if __name__=='__main__':unittest.main()
