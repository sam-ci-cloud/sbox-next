#!/usr/bin/env python3
"""Pin the public bootstrap to one exact package, without any version number.

The release location is content-addressed: tag `pkg-<first 16 hex of SHA-256>`.
The bootstrap keeps the FULL SHA-256 as its trust anchor, so the tag name is only
a locator; a reused or altered tag can never install different bytes.
usage: pin_bootstrap.py PATH/TO/SING-BOX.tar.gz
"""
from pathlib import Path
import hashlib, json, re, sys
from product_version import SOURCE, identity

ROOT = SOURCE.parent


def payload(repo, digest, size):
    tag = 'pkg-' + digest[:16]
    return {'project': 'SBOX', 'asset': 'SING-BOX.tar.gz', 'tag': tag, 'sha256': digest, 'bytes': size,
            'url': 'https://github.com/%s/releases/download/%s/SING-BOX.tar.gz' % (repo, tag),
            'bootstrap_url': 'https://raw.githubusercontent.com/%s/main/install.sh' % repo}


def apply(pin, root=ROOT):
    (root / 'PUBLIC_PAYLOAD.json').write_text(json.dumps(pin, indent=2) + '\n')
    path = root / 'install.sh'
    raw = path.read_text()
    raw = re.sub(r"SBOX_URL='[^']*'", "SBOX_URL='" + pin['url'] + "'", raw)
    raw = re.sub(r"SBOX_SHA256='[^']*'", "SBOX_SHA256='" + pin['sha256'] + "'", raw)
    path.write_text(raw)


def main():
    package = Path(sys.argv[1])
    data = package.read_bytes()
    pin = payload(identity()['repository'], hashlib.sha256(data).hexdigest(), len(data))
    apply(pin)
    print('Pinned', pin['url'], pin['sha256'])


if __name__ == '__main__':
    main()
