"""A manager backup must retain real panel accounts, MFA and subscriptions."""
from pathlib import Path
import sys,tempfile,sqlite3,unittest,os
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from store import Store
from common import Problem
from panel_backup import snapshot,validate
from subscription_vault import SubscriptionVault,KEY_NAME
class Backup(unittest.TestCase):
 def test_snapshot_keeps_panel_records_and_private_permissions(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);store=Store(p/'live.db')
   with store.db() as db:
    db.execute("INSERT INTO subscriptions VALUES('fixture-user','SYNTHETIC-HASH',123)")
    db.execute("INSERT INTO settings VALUES('fixture','42')")
   try:
    out=p/'backup';out.mkdir();self.assertTrue(snapshot(out,p/'live.db'));validate(out/'panel/panel.db');self.assertEqual((out/'panel/panel.db').stat().st_mode&0o777,0o600)
    with sqlite3.connect(out/'panel/panel.db') as db:self.assertEqual(db.execute('SELECT * FROM subscriptions').fetchall(),[('fixture-user','SYNTHETIC-HASH',123.0)]);self.assertEqual(db.execute("SELECT value FROM settings WHERE key='fixture'").fetchone()[0],'42')
   finally:store.close()
 def test_legacy_no_panel_is_optional(self):
  with tempfile.TemporaryDirectory() as td:self.assertFalse(snapshot(td,Path(td)/'absent.db'))
 def test_internal_rollback_capture_preserves_key_loss_without_weakening_backups(self):
  for missing in (True,False):
   with self.subTest(missing_key=missing),tempfile.TemporaryDirectory() as td:
    root=Path(td);store=Store(root/'panel.db');vault=SubscriptionVault(store);raw=vault.issue('fixture-user')
    paired=root/'paired';paired.mkdir();snapshot(paired,store.path)
    key=root/KEY_NAME;key.unlink()
    if not missing:key.write_bytes(b'X'*32);key.chmod(0o600)
    with self.assertRaises(Problem):validate(store.path)
    strict=root/'strict';strict.mkdir()
    with self.assertRaises(Problem):snapshot(strict,store.path)
    rollback=root/'rollback';rollback.mkdir();snapshot(rollback,store.path,require_pair=False)
    validate(rollback/'panel/panel.db',require_pair=False)
    self.assertEqual((rollback/'panel'/KEY_NAME).exists(),not missing)
    if not missing:self.assertEqual((rollback/'panel'/KEY_NAME).read_bytes(),b'X'*32)
    validate(paired/'panel/panel.db')
    recovered=Store(paired/'panel/panel.db')
    try:self.assertEqual(SubscriptionVault(recovered).reveal('fixture-user')['token'],raw)
    finally:recovered.close();store.close()
 def test_corruption_future_schema_and_symlink_are_refused(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);bad=p/'bad';bad.write_bytes(b'NOT-SQLITE')
   with self.assertRaises((Problem,sqlite3.Error)):validate(bad)
   live=p/'db';s=Store(live);s.close()
   link=p/'link';link.symlink_to(live)
   with self.assertRaises(Problem):validate(link)
   with sqlite3.connect(live) as db:db.execute('PRAGMA user_version=999')
   with self.assertRaises(Problem):validate(live)
if __name__=='__main__':unittest.main(verbosity=2)
