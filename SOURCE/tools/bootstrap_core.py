#!/usr/bin/env python3
"""Reproduce the bundled accounting binary and deterministic embedded gzip asset."""
from pathlib import Path
import gzip,hashlib,json,subprocess
root=Path(__file__).resolve().parents[1]
subprocess.run(['bash',str(root/'core-source/build.sh')],check=True)
raw=(root/'core-source/sing-box-accounting').read_bytes()
manifest=json.loads((root/'shared_webui/backend/core_manifest.json').read_text())
assert hashlib.sha256(raw).hexdigest()==manifest['sha256'],'Rebuilt core differs from release provenance'
blob=bytearray(gzip.compress(raw,compresslevel=9,mtime=0));blob[9]=255
expected=json.loads((root/'BUILD.json').read_text())['core_gzip_sha256']
assert hashlib.sha256(blob).hexdigest()==expected,'Rebuilt embedded gzip differs'
(root/'assets/sing-box-accounting.gz').write_bytes(blob)
print('PASS reproduced authenticated accounting core and embedded asset')
