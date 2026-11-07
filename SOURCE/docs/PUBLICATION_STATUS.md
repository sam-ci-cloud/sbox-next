# Publication identity

Canonical product/version: SOURCE/VERSION.json. Public repository: https://github.com/sam-ci-cloud/sbox-next . Default branch: main; independent clean root history. Public bootstrap: https://raw.githubusercontent.com/sam-ci-cloud/sbox-next/main/install.sh .

A published release's RELEASE_MANIFEST.json binds commit, tag, version, package/core and bootstrap digests. SHA256SUMS covers public assets. CI evidence must match that commit. Publication is accepted only after anonymous public URL, checksum and installation verification; an empty repository or prepared local file is not a completed release.

Owner-private FULL DELIVERY ZIP, owner decryption key, protected identities and recovery backups must never be uploaded as public release assets. Never replace an existing content-addressed release asset with different bytes.
