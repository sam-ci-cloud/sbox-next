"""Canonical product identity. Component/core versions and API schema are separate."""
from pathlib import Path
import json,re
SOURCE=Path(__file__).resolve().parents[1]
# Repository identity comes only from VERSION.json (no hard-coded owner/name in tools).
REPOSITORY=re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}')
def identity():
 p=json.loads((SOURCE/'VERSION.json').read_text())
 if not (p['schema']==1 and p['product']=='SBOX' and bool(REPOSITORY.fullmatch(str(p['repository']))) and re.fullmatch(r'\d+\.\d+\.\d+',p['version'])):raise ValueError('Invalid canonical SBOX identity')
 return p
