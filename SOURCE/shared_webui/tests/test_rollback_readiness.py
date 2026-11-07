"""Rollback must not return success before its HTTPS listener is accepting."""
from pathlib import Path
import os,sys,tempfile,json,unittest
from unittest.mock import patch
ROOT=Path(os.environ.get('SBOX_WEBUI_ROOT',Path(__file__).resolve().parents[1]));sys.path.insert(0,str(ROOT/'backend'))
import install
from common import Problem
class Rollback(unittest.TestCase):
 def test_not_ready_rollback_is_not_reported_successful(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);lib=p/'lib';lib.mkdir();etc=p/'etc';etc.mkdir();(etc/'settings.json').write_text(json.dumps({'listen':'0.0.0.0','port':9443}));(lib/'current').symlink_to('release-a');(lib/'previous').symlink_to('release-b')
   with patch.object(install,'LIB',lib),patch.object(install,'ETC',etc),patch.object(install,'verify'),patch.object(install,'run'),patch.object(install.os,'geteuid',return_value=0),patch.object(sys,'argv',['install.py','rollback']),patch.object(install,'wait_listening',return_value=False) as wait:
    with self.assertRaises(Problem):install.main()
    wait.assert_called_once_with('0.0.0.0',9443,30)
if __name__=='__main__':unittest.main(verbosity=2)
