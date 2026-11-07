# Embedded assets

| Asset | Purpose |
| --- | --- |
| sing-box-accounting.gz | Pinned modified sing-box 1.14.4 (SBOX accounting patch), Linux amd64 |
| zgocloud.enc | Authenticated encrypted compatibility manager; owner-held unlock required |
| zgocloud.json | Envelope format and decrypted manager digest |
| release.json | Product/component versions, platforms and release hashes |

[BUILD.json](../BUILD.json) pins exact assembly inputs. The core has complete [corresponding source](../core-source/README.md). The envelope preserves the original six-node identity and YAML without publishing plaintext credentials. Ordinary offline assembly reuses these bytes; private resealing is a separate owner operation described in [development](../docs/development.md).

The public VPS installer embeds these assets. It does not fetch application code from another repository, a Gist or a private Release.
