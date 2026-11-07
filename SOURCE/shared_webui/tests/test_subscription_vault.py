"""Recoverable bearer links must preserve old hashes and require a separate key."""
from pathlib import Path
import hashlib,os,sqlite3,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from store import Store
from common import Problem,digest
from subscription_vault import SubscriptionVault,key_id
from panel_backup import snapshot,validate

class VaultTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.store=Store(self.root/'panel.db');self.vault=SubscriptionVault(self.store)
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def test_new_token_repeated_reveal_reopen_and_database_only(self):
  raw=self.vault.issue('a'*32)
  self.assertEqual(self.vault.reveal('a'*32)['token'],raw)
  self.store.close();self.store=Store(self.root/'panel.db');self.vault=SubscriptionVault(self.store)
  self.assertEqual(self.vault.reveal('a'*32)['token'],raw)
  with self.store.db() as db:
   dump='\n'.join(db.iterdump());self.assertNotIn(raw,dump);self.assertEqual(db.execute('SELECT hash FROM subscriptions').fetchone()[0],digest(raw))
  self.assertEqual((self.root/'subscription.key').stat().st_mode&0o777,0o600)
 def test_legacy_hash_is_active_nonrecoverable_and_never_changed_by_view(self):
  with self.store.db() as db:db.execute('INSERT INTO subscriptions VALUES(?,?,?)',('a'*32,digest('old-synthetic-link'),123))
  for _ in range(2):
   view=self.vault.reveal('a'*32);self.assertEqual(view['state'],'legacy');self.assertNotIn('token',view)
  with self.store.db() as db:self.assertEqual(tuple(db.execute('SELECT * FROM subscriptions').fetchone()),('a'*32,digest('old-synthetic-link'),123.0))
  self.assertFalse((self.root/'subscription.key').exists())
 def test_new_bearer_keeps_preceding_release_wire_format(self):
  raw=self.vault.issue('a'*32)
  self.assertRegex(raw,r'^[A-Za-z0-9_-]{43}$')
  with self.store.db() as db:self.assertEqual(db.execute('SELECT version FROM subscription_recovery').fetchone()[0],2)
 def test_earlier_candidate_prefix_remains_recoverable_without_replacement(self):
  key=self.vault.key(create=True);nonce='a'*48;ident='b'*32
  raw=self.vault.derive(key,ident,nonce,1)
  with self.store.db() as db:
   db.execute('INSERT INTO subscriptions VALUES(?,?,?)',(ident,digest(raw),123))
   db.execute('INSERT INTO subscription_recovery VALUES(?,?,?,?)',(ident,1,nonce,key_id(key)))
  self.assertTrue(raw.startswith('v1.'));self.assertEqual(self.vault.reveal(ident)['token'],raw)
  with self.store.db() as db:self.assertEqual(db.execute('SELECT created FROM subscriptions').fetchone()[0],123)
 def test_rotate_revoke_and_cross_user_isolation(self):
  a=self.vault.issue('a'*32);b=self.vault.issue('b'*32);new=self.vault.issue('a'*32)
  self.assertNotEqual(a,new);self.assertEqual(self.vault.reveal('b'*32)['token'],b)
  with self.store.db() as db:self.assertIsNone(db.execute('SELECT user FROM subscriptions WHERE hash=?',(digest(a),)).fetchone())
  self.vault.revoke('a'*32);self.assertEqual(self.vault.reveal('a'*32)['state'],'absent');self.assertEqual(self.vault.reveal('b'*32)['token'],b)
 def test_missing_key_never_recreated_when_links_depend_on_it(self):
  self.vault.issue('a'*32);(self.root/'subscription.key').unlink()
  self.assertEqual(self.vault.reveal('a'*32)['state'],'key_unavailable')
  with self.assertRaises(Problem):self.vault.issue('b'*32)
  self.assertFalse((self.root/'subscription.key').exists())
 def test_wrong_key_and_unsafe_key_refused(self):
  raw=self.vault.issue('a'*32);key=self.root/'subscription.key';old=key.read_bytes();key.write_bytes(os.urandom(32))
  self.assertEqual(self.vault.reveal('a'*32)['state'],'key_unavailable')
  with self.assertRaises(Problem):self.vault.issue('b'*32)
  key.write_bytes(old);key.chmod(0o644);self.assertEqual(self.vault.reveal('a'*32)['state'],'key_unavailable')
  with self.assertRaises(Problem):self.vault.issue('b'*32)
 def test_old_release_rotation_or_revoke_does_not_reveal_stale_token(self):
  self.vault.issue('a'*32)
  with self.store.db() as db:db.execute('UPDATE subscriptions SET hash=? WHERE user=?',(digest('old-build-new-token'),'a'*32))
  self.assertEqual(self.vault.reveal('a'*32)['state'],'legacy')
  with self.store.db() as db:db.execute('DELETE FROM subscriptions')
  self.assertEqual(self.vault.reveal('a'*32)['state'],'absent')
 def test_backup_keeps_key_separate_and_validates_key_loss(self):
  raw=self.vault.issue('a'*32);out=self.root/'backup';out.mkdir();snapshot(out,self.store.path)
  self.assertEqual((out/'panel/subscription.key').read_bytes(),(self.root/'subscription.key').read_bytes());validate(out/'panel/panel.db')
  restored=Store(out/'panel/panel.db')
  try:self.assertEqual(SubscriptionVault(restored).reveal('a'*32)['token'],raw)
  finally:restored.close()
  (out/'panel/subscription.key').unlink()
  with self.assertRaises(Problem):validate(out/'panel/panel.db')
 def test_symlink_key_not_followed(self):
  outside=self.root/'other';outside.write_bytes(os.urandom(32));outside.chmod(0o600);(self.root/'subscription.key').symlink_to(outside)
  with self.assertRaises(Problem):self.vault.issue('a'*32)

 def test_simultaneous_creation_uses_one_durable_key(self):
  from concurrent.futures import ThreadPoolExecutor
  ids=[format(i,'032x') for i in range(12)]
  with ThreadPoolExecutor(max_workers=6) as pool:tokens=list(pool.map(self.vault.issue,ids))
  self.assertEqual(len(set(tokens)),12)
  for ident,raw in zip(ids,tokens):self.assertEqual(self.vault.reveal(ident)['token'],raw)

if __name__=='__main__':unittest.main()
