"""Certificate-hostname synchronization with retained loopback settings."""
import importlib.util,os,pathlib,subprocess,tempfile,types,unittest,sys
from unittest.mock import patch,MagicMock
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
spec=importlib.util.spec_from_file_location('panel_install_origin',ROOT/'backend/install.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Origin(unittest.TestCase):
 def test_existing_loopback_settings_follow_current_validated_certificate_hostname(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp);cert=p/'cert';key=p/'key';cert.write_bytes(b'SYNTHETIC CERT');key.write_bytes(b'SYNTHETIC KEY');etc=p/'etc';etc.mkdir()
   state={'domain':'new.example.test','certificate':{'mode':'existing','source_fullchain':str(cert),'source_key':str(key)}};cfg={'port':9443,'listen':'127.0.0.1','origin':'https://localhost:9443','panel_certificate_mode':'local TLS over SSH tunnel'}
   def secure(path,*a):path.mkdir(parents=True,exist_ok=True)
   observed=subprocess.CompletedProcess([],0,'Hostname new.example.test does match certificate\n','')
   with patch.object(module,'ETC',etc),patch.object(module,'secure_dir',secure),patch.object(module.os,'chown'),patch.object(module.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_gid=os.getgid())),patch.object(module.subprocess,'run',return_value=observed),patch.object(module.ssl,'SSLContext',return_value=MagicMock()):module.certificate(cfg,state)
   self.assertEqual(cfg['origin'],'https://new.example.test:9443');self.assertEqual(cfg['listen'],'127.0.0.1');self.assertNotIn('panel_certificate_mode',cfg)
if __name__=='__main__':unittest.main(verbosity=2)
