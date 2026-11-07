# Certificates and renewal

SBOX's public WebUI requires a trusted certificate for its configured domain. VPN transports that use TLS also need the matching configuration. A REALITY handshake target and a successful ordinary HTTPS request are different from validation of an actual REALITY client. REALITY's own key pair is not a website certificate. The certificate `reuse` choice means reusing this installation's own still-valid certificate; SBOX never copies a third-party website's certificate or key.

## Self-hosted REALITY website

When the Universal REALITY handshake target is the self-hosted SBOX Personal Cloud website, a **publicly trusted** certificate for the SBOX domain becomes required even if no other TLS protocol is enabled. Self-signed certificates are refused for this mode. Renewal restarts the website service, verifies it locally and through REALITY, and rolls back on failure; `sbox doctor` reports the result. See [REALITY handshake target](reality-fallback.md#certificate-renewal-and-health).

## Supported sources

The manager accepts certificate reuse, Certbot HTTP-01, Cloudflare DNS-01, an existing certificate/key pair and an explicit self-signed VPN setup. A self-signed certificate does not satisfy the public WebUI trust prerequisite.

- **HTTP-01:** DNS points at the server; inbound TCP 80 and ACME reachability are required.
- **Cloudflare DNS-01:** use a narrowly scoped token in a protected file and the documented propagation interval. Never put its value in an issue, argv example or public repository.
- **Existing pair:** use readable root-owned private paths and preserve the source files referenced by the native certificate plan.

After installation, `sbox certificate` runs the certificate workflow. To select HTTP-01 explicitly:

```bash
sbox certificate --cert certbot-http01 --email none --yes
```

Use an email instead of `none` if desired. `sbox renew-test` runs the applicable Certbot renewal dry run; it does not promise that unrelated provider DNS/firewall failures will be repaired. Inspect `sbox doctor` and `sbox webui doctor` afterward.

The manager validates certificate/key pairing and reuses an exact unchanged managed plan without relaxing TLS or sandbox checks. Existing source paths must remain present until replaced through the native workflow. An intentional full restore may need normal certificate/renewal reconfiguration; verify the chosen plan and real HTTPS after restoring.

Protected ZgoCloud retains its original SNI/domain/identity. Use only the authorized deployment domain and a valid trusted certificate. The product does not distribute private CA material, keys or original credentials.
