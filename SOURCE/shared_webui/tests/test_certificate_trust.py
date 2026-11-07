"""Real OpenSSL trust/hostname/server-EKU contracts against either CLI source."""
from pathlib import Path
import datetime,os,subprocess,tempfile,unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
SOURCE=Path(os.environ.get('SBOX_MANAGER_ROOT',Path(__file__).resolve().parents[2]))/'src/manager.sh'
class Trust(unittest.TestCase):
 def test_real_trusted_server_accepted_client_only_and_wrong_host_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);now=datetime.datetime.now(datetime.timezone.utc);key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SBOX test root')])
   ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=5)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256());(p/'ca').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
   source=SOURCE.read_text().removesuffix('main "$@"\n').replace('/etc/ssl/certs/ca-certificates.crt',str(p/'ca'));f=p/'functions';f.write_text(source)
   for label,eku,expected in [('server',ExtendedKeyUsageOID.SERVER_AUTH,True),('client-only',ExtendedKeyUsageOID.CLIENT_AUTH,False)]:
    leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'vpn.example.test')])).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName('vpn.example.test')]),False).add_extension(x509.ExtendedKeyUsage([eku]),False).sign(key,hashes.SHA256());cert=p/label;cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
    r=subprocess.run(['bash','-c','source "$1"; cert_trusted "$2" "$3"','test',str(f),str(cert),'vpn.example.test'],capture_output=True,text=True)
    self.assertEqual(r.returncode==0,expected,label+': '+r.stderr[-120:])
   r=subprocess.run(['bash','-c','source "$1"; cert_trusted "$2" different.example.test','test',str(f),str(p/'server')],capture_output=True,text=True);self.assertNotEqual(r.returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
