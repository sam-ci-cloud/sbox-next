# Connect & Export Center (1.10.0)

## Problem
Four implementations offered the same task differently: the users-table Share dialog, a separate
"Download client file" dialog (technical GLOBAL/CN/INTERNAL names, no server-address choice), the
personal portal and the subscription page (three repeated profile cards). Three drop-downs sat side by
side, the difference between a subscription, a QR code and a static file was unclear, single-server links
were hidden, and the sing-box JSON was a local SOCKS proxy that sing-box apps cannot use as a VPN.

## Design
- One catalog (`backend/export_catalog.py`) defines every choice, label (English / Traditional Chinese),
  availability and file name; one component (`frontend-src/shared/export-center.js`) renders it in the
  console (users table, user detail, onboarding, subscriptions page), the portal and the subscription page.
  Each page supplies only a data adapter (admin API, session-bound portal API, token-bound page routes).
- Single column, four grouped steps (fieldset + legend): which app; which traffic uses the VPN; VPN server
  address (saved automatic setting shown, others behind "Use a different server address"); how to connect
  (subscription recommended, file download, single-server links). The sing-box profile type (complete or
  basic) is a conditional reveal under the sing-box choice. Routing choices disappear for the basic proxy
  and for single-server links, where they do not apply; step numbers follow the visible steps.
- One summary of the selection and only the actions for the chosen method. QR captions say whether the code
  holds a subscription URL or one server link. Links and QR codes are labelled as secrets.
- Deviation, recorded deliberately: GOV.UK advises against pre-selected radios. Here every step has a safe
  saved default and the result updates live with no submit, so defaults are pre-selected and the
  recommended options say so.

## sing-box profiles
`singbox` (complete, sing-box 1.12+): nodes, Smart Auto (urltest) and LOCK/VPN selectors, DNS servers taken
from the profile's own resolver lists (literal-address bootstrap), routing derived from the profile's own Mihomo rules in the same order (general browsing: private addresses,
`.lan`/`.local` and the administrator's custom rules; internal: no direct rules, so websites and private
addresses go to the VPN), a TUN
inbound (`address`, `auto_route`, `strict_route`; no deprecated `stack`) and a mixed proxy on 127.0.0.1:2080.
Mainland-China-direct (1.11.0): sing-box 1.12+ has no built-in GeoSite/GeoIP data and SBOX never makes
generated profiles download rule data (tests/test_no_github_runtime.py), so the Mihomo `GEOSITE,CN` and
`GEOIP,CN` rules map to two inline rule sets embedded in the profile (about 260 KB) from a committed, pinned
snapshot (`shared_webui/backend/cn_rules.json`, built by `tools/cn_rules.py` from v2fly domain-list-community
`cn` (MIT) and APNIC CN allocations). Mainland-China names are resolved with the profile's CN resolver directly,
as in the Mihomo `nameserver-policy`; everything else still uses the VPN (never a GLOBAL substitute).
Limits: the snapshot is refreshed at release time, not continuously; APNIC allocation country is not proof of
where an address is used; Mihomo's own geodata may differ slightly. Mihomo's first-alive fallback group has no
sing-box equivalent and is not imitated.

Node candidates (1.11.0), sing-box formats (`singbox` and `json`):
- Hysteria2/TUIC on a dual-stack name: one candidate per address family (resolver strategy `ipv4_only` /
  `ipv6_only`), because sing-box binds a QUIC socket to the first resolved address and never falls back
  (`common/dialer/resolve.go`: `ListenPacket` -> `N.ListenSerial`).
- Bootstrap fallback: the server's own published addresses (the Export Center endpoint choices) as literal
  candidates, so a slow, failing or poisoned local resolver cannot block the VPN. Same TLS server name and
  certificate verification; no extra resolver; nothing is stored on the device.
- Candidates sit in a URL-test group that keeps the node's tag, so Smart Auto, LOCK and saved selections are
  unchanged. This is address-level fallback inside one protocol, not Smart Auto switching protocols.
Mihomo YAML does not contain a TUN section; Mihomo apps enable TUN or system proxy in their own settings.

## Sources
- GOV.UK Design System, radios and conditional reveal: https://design-system.service.gov.uk/components/radios/
- W3C WAI, grouping controls: https://www.w3.org/WAI/tutorials/forms/grouping/
- UK Parliament, designing forms: https://designsystem.parliament.uk/how-tos/designing-forms/
- Home Office, accessible forms: https://design.homeoffice.gov.uk/accessibility/interactivity/forms
- Proton VPN configuration generator: https://protonvpn.com/support/wireguard-configurations
- Outline Manager, sharing access keys: https://developer.getoutline.org/vpn/getting-started/share-access/
- Tailscale QR onboarding: https://tailscale.com/docs/features/access-control/device-management/how-to/set-up-qr-code
- Mihomo DNS and proxy groups: https://wiki.metacubex.one/en/config/dns/ , https://wiki.metacubex.one/en/config/proxy-groups/
- sing-box urltest, TUN, DNS: https://sing-box.sagernet.org/configuration/outbound/urltest/ ,
  https://sing-box.sagernet.org/configuration/inbound/tun/ , https://sing-box.sagernet.org/configuration/dns/
Features were verified against the pinned clients (Mihomo 1.19.33, sing-box 1.14.4), not only documentation.

## Lab acceptance (1.10.0)
Complete sing-box profiles served by the three lab servers were run with the official sing-box 1.14.4
client inside isolated network namespaces with TUN on all six directed paths: general browsing and
everything-through-the-VPN each sent 18/18 unproxied HTTPS requests out through the VPN server, DNS was
answered through the tunnel (94-225 ms), and the namespace's directly connected local network stayed
reachable in both profiles (the operating system routes a connected subnet itself). An earlier build that
used a fixed public resolver for bootstrap failed from Los Angeles (resolver timeouts); the profile now
uses the device resolver for bootstrap only.

## What "all destinations, including private addresses" means

The internal profile has no direct rules: websites and private addresses (10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, `.lan`) are sent to the VPN, for example to reach networks behind the server. It never
means that literally every packet leaves through the VPN:

- the connection to the VPN server itself is always direct;
- in whole-device (TUN) mode the operating system usually keeps the network the device is directly attached
  to (its own subnet, such as the home router) reachable directly; the lab TUN test confirms this for the
  complete sing-box profile (`local_network_reachable: true`);
- in system-proxy mode only applications that use the system proxy are covered;
- custom routing rules apply to the general and mainland-China profiles only.

The interface text (`backend/export_catalog.py`, `PROFILE_TEXT` and `routing_note`) says exactly this.
