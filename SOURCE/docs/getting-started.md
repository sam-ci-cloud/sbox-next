# Getting started

SBOX is a self-hosted server application. You administer the VPS, its DNS, provider firewall, backups and private client credentials.

## Choose a product

**Universal SBOX** is the configurable choice for a new deployment. It creates the server identity and guides you through network, protocol, certificate and policy choices.

**ZgoCloud** is for an owner who already holds the separately distributed private unlock and original client identity. It preserves the six-node compatibility contract rather than generating a new public example identity. Do not install both variants on one existing OS or try to switch products during an upgrade.

This is a **candidate delivery**. It includes a locally verifiable installer and matching source. Read [candidate status](installation.md#package-and-status) and the acceptance reports at the delivery root for what has been verified and what remains for your own server.

## Prepare the VPS

Use a supported amd64 systemd OS and a root SSH shell. Have a domain pointed at the intended VPS, access to its DNS/ACME prerequisite, the provider console and a separate administrative session. Permit selected VPN ports and HTTPS TCP 9443. HTTP-01 issuance additionally needs inbound TCP 80. Read [installation](installation.md) before using an existing server.

```bash
cd /root && tar -xzf SING-BOX.tar.gz
cd /root/SING-BOX && bash install.sh
```

Choose the matching fresh installation. Use an upgrade on existing SBOX state. Normal OS dependencies and certificate issuance require network access; application components and the patched core are embedded in this one script.

## First sign-in

After a trusted certificate is installed, open your domain on HTTPS port 9443. Retrieve the root-only bootstrap credentials:

```bash
cat /etc/sbox-webui/bootstrap-admin.txt
```

Change the initial administrator password, enroll MFA and save recovery codes privately. Add a managed user in the console, issue their subscription/export and configure their separate portal account if needed. The portal is at `/portal` on the same HTTPS origin.

Verify the server with `sbox doctor` and `sbox webui doctor`, then test a real client. A successful port check is not proof of a working VPN protocol. Store a complete `sbox backup` off the VPS before subsequent changes.

Continue with [users and quotas](users-and-quotas.md), [protocol behavior](protocols.md) and [upgrades/recovery](upgrades-and-recovery.md).
