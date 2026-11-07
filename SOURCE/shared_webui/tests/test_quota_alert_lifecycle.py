"""Real compact bridge payload must preserve active quota alerts until reset/topup.

Only quota notifications are counted: host-wide alerts (e.g. disk.space from the
real statvfs of the test machine) are unrelated and made this test depend on the
free space of the CI disk.
"""
import json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'privileged-bridge'),str(ROOT/'tests')]
from accounting import Engine,root_json
from bridge import Control
from server import App
from ui_fixture import FixtureControl
class Alerts(unittest.TestCase):
 def test_active_exhaustion_does_not_resolve_on_next_evaluation(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);ident='a'*32;tag='user>>user-'+ident;user={'id':ident,'name':'actual-unit-user','enabled':True,'protocols':{'reality':{}},'quota':{'quota_bytes':100,'period':'monthly'}};state={'protocols':{'reality':{'enabled':True}},'managed_users':[user],'accounting':{'enabled':True}};(p/'state.json').write_text(json.dumps(state));engine=Engine(p,p/'meter');now=time.time();engine.store().ingest(state,'native-source',{'user>>>user-'+ident+'@reality>>>traffic>>>uplink':120},now);root_json(p/'meter/health.json',{'status':'ready','sampled_at':now});bridge=Control(p);bridge.meter=engine;fixture=FixtureControl('universal',users=0)
   def control(op,data=None):return bridge.accounting_summary() if op=='accounting-summary' else fixture(op,data)
   app=App({'database':str(p/'panel.db')},control);sent=[];app.store.set_setting('notifications',{'enabled':True})
   try:
    # Quota-only fixture: collector-failure alerts have separate health tests.
    with patch.object(engine,'health',return_value={'status':'ready','sampled_at':now}), patch.object(app,'notify',side_effect=lambda event,detail:sent.append(event)):
     app.evaluate();app.evaluate()
    alerts=[a for a in app.store.alerts() if a['key'].startswith('vpn.')];self.assertEqual(len(alerts),3);self.assertTrue(all(a['resolved_at'] is None for a in alerts));quota_sent=[e for e in sent if e.startswith('alert:vpn.')];self.assertEqual(len(quota_sent),3,sent)
   finally:app.store.close()
if __name__=='__main__':unittest.main()
