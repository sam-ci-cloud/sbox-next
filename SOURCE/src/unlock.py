"""Authenticated private envelope; no password in argv, environment or logs."""
import getpass,hashlib,hmac,os,stat,subprocess,sys,signal
from pathlib import Path
def cancel_unlock(signum,frame):
 for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
 raise KeyboardInterrupt
for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,cancel_unlock)
try:
 path=os.environ.get('SBOX_ZGO_UNLOCK_FILE')
 if path:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   st=os.fstat(f.fileno())
   if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600 or st.st_uid!=os.geteuid() or st.st_nlink!=1:
    raise ValueError('Unlock file must be owned by the current user, regular, unlinked elsewhere and mode 0600; run chmod 600 on your private file.')
   secret=f.read(4097).splitlines()[0]
   if len(secret)>4096:raise ValueError('Unlock file too large.')
 else:
  try:tty_fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
  except OSError:raise ValueError('ZgoCloud unlock requires a controlling terminal or SBOX_ZGO_UNLOCK_FILE.')
  with os.fdopen(tty_fd,'w') as tty:secret=getpass.getpass('ZgoCloud private unlock passphrase: ',stream=tty).encode()
 if not secret:raise ValueError('Empty unlock passphrase.')
 data=Path(sys.argv[1]).read_bytes()
 if data[:8]!=b'SBOXETM1' or len(data)<104:raise ValueError('Invalid encrypted envelope.')
 salt,tag,cipher=data[8:40],data[40:72],data[72:]
 key=hashlib.pbkdf2_hmac('sha256',secret,salt,400000,32)
 if not hmac.compare_digest(tag,hmac.new(key,data[:40]+cipher,'sha256').digest()):raise ValueError('Incorrect ZgoCloud unlock or damaged authenticated payload.')
 # Ciphertext is public; the private passphrase travels only through an anonymous pipe.
 cp=Path(sys.argv[1]+'.cipher');cp.write_bytes(cipher);cp.chmod(0o600)
 try:
  result=subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','400000','-md','sha256','-pass','stdin','-in',str(cp)],input=secret+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  if result.returncode:raise ValueError('Private decryption failed.')
  Path(sys.argv[2]).write_bytes(result.stdout);Path(sys.argv[2]).chmod(0o600)
 finally:cp.unlink(missing_ok=True)
except (EOFError,KeyboardInterrupt):
 print('[SBOX ERROR] Unlock cancelled.',file=sys.stderr);sys.exit(130)
except (OSError,ValueError,IndexError) as e:
 print('[SBOX ERROR] '+str(e),file=sys.stderr);sys.exit(1)
