"""Synthetic generated payloads through actual production QR encoder/sanitizer."""
from pathlib import Path
import sys,json,types,base64
S=Path(__file__).resolve().parents[2];sys.path[:0]=[str(S/'tests'),str(S/'shared_webui/backend'),str(S/'shared_webui/privileged-bridge')]
import reality_fixture as fx
from server import Handler
from network_policy import select_endpoint
s=fx.trusted_certificate(fx.base_state());s['server'].update(mode='dual',scope='internal',listen='::',ipv4='192.0.2.1',ipv6='2001:db8::1')
for p in s['protocols'].values():p['enabled']=True
h=object.__new__(Handler);h.server=types.SimpleNamespace(app=types.SimpleNamespace(qrencode=[sys.executable,str(Path(__file__).with_name('qrencode_ctypes.py'))]));rows=[]
for choice in ['domain','ipv4','ipv6']:
 out=fx.render(select_endpoint(s,choice));links=[l for l in (out/'links.txt').read_text().splitlines() if '://' in l]
 for i,payload in enumerate(links+['https://cloud.sbox.test:9443/sub/'+'A'*43+'/global.yaml?endpoint='+choice]):rows.append({'endpoint':choice,'kind':'subscription' if i==5 else payload.split('://')[0],'payload':payload,'svg':h.qr(payload)})
print(json.dumps(rows))
