"""Only explicit pruning may remove validated, unreferenced backup snapshots."""
import hashlib,importlib.util,io,json,os,tarfile,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('retention',Path(__file__).resolve().parents[1]/'src/retention.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Retention(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.base=self.root/'base';self.base.mkdir();self.backups=self.root/'backups';self.backups.mkdir()
 def tearDown(self):self.temp.cleanup()
 def backup(self,name,stamp):
  p=self.backups/('sbox-manual-'+name+'.tar.gz');files={'state.json':b'{}','sing-box':b'synthetic test core'};files['SHA256SUMS']=''.join(hashlib.sha256(b).hexdigest()+'  '+n+'\n' for n,b in files.items()).encode()
  with tarfile.open(p,'w:gz') as t:
   for n,b in files.items():m=tarfile.TarInfo('payload/'+n);m.size=len(b);t.addfile(m,io.BytesIO(b))
  os.utime(p,(stamp,stamp));return p
 def policy(self,name,stamp):
  p=self.backups/('policy-'+name);p.mkdir();(p/'state.json').write_text('{}');(p/'hashes.json').write_text(json.dumps({'state.json':hashlib.sha256(b'{}').hexdigest()}));os.utime(p,(stamp,stamp));return p
 def test_dry_run_never_deletes_and_prune_keeps_newest_validated(self):
  old=self.backup('old',1);new=self.backup('new',2);report=r.retain(self.backups,self.base,keep_backups=1,keep_policies=1);self.assertTrue(old.exists());self.assertEqual(report['would_remove'],[str(old)])
  report=r.retain(self.backups,self.base,keep_backups=1,keep_policies=1,prune=True);self.assertFalse(old.exists());self.assertTrue(new.exists())
 def test_active_backup_and_policy_pointers_are_protected(self):
  old=self.backup('old',1);new=self.backup('new',2);po=self.policy('old',1);pn=self.policy('new',2);(self.backups/'PRE-UPGRADE-BACKUP').write_text(str(old));(self.backups/'.policy-journal.json').write_text(json.dumps({'snapshot':str(po)}))
  r.retain(self.backups,self.base,keep_backups=1,keep_policies=1,prune=True);self.assertTrue(all(p.exists() for p in (old,new,po,pn)))
 def test_symlink_and_corrupt_material_preserved_and_last_good_untouched(self):
  good=self.backup('good',1);bad=self.backups/'sbox-manual-bad.tar.gz';bad.write_bytes(b'bad');link=self.backups/'sbox-manual-link.tar.gz';link.symlink_to(good);last=self.backups/'last-good.db';last.write_bytes(b'recovery')
  r.retain(self.backups,self.base,keep_backups=1,keep_policies=1,prune=True);self.assertTrue(good.exists() and bad.exists() and link.is_symlink());self.assertEqual(last.read_bytes(),b'recovery')
 def test_malformed_active_pointer_fails_closed(self):
  self.backup('old',1);self.backup('new',2);(self.backups/'.policy-journal.json').write_text('broken')
  with self.assertRaises(ValueError):r.retain(self.backups,self.base,keep_backups=1,keep_policies=1,prune=True)
 def test_configuration_cannot_remove_every_last_good(self):
  with self.assertRaises(ValueError):r.retain(self.backups,self.base,keep_backups=0,keep_policies=1,prune=True)
if __name__=='__main__':unittest.main(verbosity=2)
