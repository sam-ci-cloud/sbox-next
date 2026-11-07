#!/usr/bin/env python3
"""Verify the source and installer form a self-contained local delivery."""
from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from check_docs import distribution

distribution(ROOT)
# The delivery is the standalone SING-BOX.tar.gz: guides must use its root
# entrypoint and must not point at the retired installer/ + SHA256SUMS.txt layout.
for name in ('README.md','docs/installation.md','docs/getting-started.md','docs/zh-HK.md'):
    text=(ROOT/name).read_text()
    if 'cd /root/SING-BOX' not in text or 'bash install.sh' not in text:
        raise SystemExit(f'{name} does not use the standalone package entrypoint (cd /root/SING-BOX && bash install.sh)')
    for stale in ('installer/install.sh','SHA256SUMS.txt'):
        if stale in text:
            raise SystemExit(f'{name} still refers to the retired delivery layout: {stale}')
data=json.loads((ROOT/'assets/distribution.json').read_text())
if 'repository' in data or 'source_commit' in data:
    raise SystemExit('Delivery metadata still requires a hosted repository or commit')
print('PASS local delivery identity: included installer hash and docs are verified without Git or a remote')
