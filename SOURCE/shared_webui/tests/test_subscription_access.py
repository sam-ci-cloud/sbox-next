"""Real HTTP auth/CSRF and per-user root-session tests for connection reveals."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_panel_v2 import Panel
from common import digest

class ConnectionAccess(Panel):
 def test_repeat_view_is_stable_secret_safe_and_reader_denied(self):
  h=self.admin();ident=self.control('users')[1]['id']
  code,_,issued=self.req('/api/v1/subscriptions/rotate-token',{'id':ident},h);self.assertEqual(code,200,issued)
  for _ in range(2):
   code,headers,view=self.req('/api/v1/subscriptions/reveal',{'id':ident},h);self.assertEqual(code,200,view);self.assertEqual(view['urls'],issued['urls']);self.assertEqual(view['state'],'ready');self.assertEqual(headers['Cache-Control'],'no-store');self.assertEqual(headers['Referrer-Policy'],'no-referrer')
  path=issued['urls']['global'].replace('https://panel.example.test','')
  self.assertEqual(self.req(path)[0],200)
  raw=issued['urls']['global'].split('/sub/')[1].split('/')[0]
  with self.app.store.db() as db:
   self.assertNotIn(raw,'\n'.join(db.iterdump()))
   self.assertEqual(db.execute('SELECT hash FROM subscriptions WHERE user=?',(ident,)).fetchone()[0],digest(raw))
  reader=self.admin('read-only','reader')
  self.assertEqual(self.req('/api/v1/subscriptions/reveal',{'id':ident},reader)[0],403)
  self.assertEqual(self.req('/api/v1/subscriptions/reveal',{'id':ident},{'Cookie':h['Cookie']})[0],403)
 def test_legacy_reveal_does_not_replace_and_missing_user_is_refused(self):
  h=self.admin();ident=self.control('users')[1]['id']
  self.app.subscriptions.revoke(ident)
  with self.app.store.db() as db:db.execute('INSERT INTO subscriptions VALUES(?,?,?)',(ident,digest('synthetic-legacy-bearer'),123))
  code,_,v=self.req('/api/v1/subscriptions/reveal',{'id':ident},h);self.assertEqual(code,200,v);self.assertEqual(v['state'],'legacy');self.assertNotIn('urls',v)
  with self.app.store.db() as db:self.assertEqual(db.execute('SELECT hash FROM subscriptions WHERE user=?',(ident,)).fetchone()[0],digest('synthetic-legacy-bearer'))
  self.assertEqual(self.req('/api/v1/subscriptions/reveal',{'id':'f'*32},h)[0],404)

if __name__=='__main__':
 import unittest
 unittest.main()
