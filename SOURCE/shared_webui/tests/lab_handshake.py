"""Isolate REALITY handshake from upstream CDN changes; lab DNS only."""
import os,pathlib,subprocess
assert os.geteuid()==0 and pathlib.Path('/root/lab-ready').is_file()
def run(a):subprocess.run(a,check=True,capture_output=True)
run(['ip','netns','add','sbox-handshake']);run(['ip','link','add','sh-host','type','veth','peer','name','sh-peer']);run(['ip','link','set','sh-peer','netns','sbox-handshake']);run(['ip','addr','add','198.19.101.1/24','dev','sh-host']);run(['ip','link','set','sh-host','up']);run(['ip','netns','exec','sbox-handshake','ip','link','set','lo','up']);run(['ip','netns','exec','sbox-handshake','ip','link','set','sh-peer','up']);run(['ip','netns','exec','sbox-handshake','ip','addr','add','198.19.101.2/24','dev','sh-peer'])
p=pathlib.Path('/opt/sbox-handshake');p.mkdir(exist_ok=True)
run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=www.microsoft.com','-addext','subjectAltName=DNS:www.microsoft.com','-keyout',str(p/'key'),'-out',str(p/'cert')])
hosts=pathlib.Path('/etc/hosts');hosts.write_text(hosts.read_text()+'\n198.19.101.2 www.microsoft.com # SBOX LAB HANDSHAKE ONLY\n')
log=(p/'server.log').open('w');proc=subprocess.Popen(['ip','netns','exec','sbox-handshake','openssl','s_server','-accept','198.19.101.2:443','-cert',str(p/'cert'),'-key',str(p/'key'),'-tls1_3','-www'],stdout=log,stderr=subprocess.STDOUT)
(p/'pid').write_text(str(proc.pid));print('REALITY camouflage TLS target isolated inside test namespace; original SNI/identity unchanged.')
