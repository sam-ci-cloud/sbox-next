# SBOX IPv4/IPv6 findings

Confirmed and fixed: global Mihomo transport IPv6 incorrectly followed server egress, blocking IPv6 node connections in a valid mixed policy. Native-engine before/after evidence and a permanent full-generated-profile regression cover it.

DNS transition overrides no longer suppress unassigned listener errors. Explicit non-loopback HTTPS requires certificate trust. Network setup and endpoint selection share root validation and authorization; HTTPS family changes are transactional and opt-in on existing systems.

No operating-system address, route, local listener or DNS observation is labelled proof of external firewall reachability. No NAT64 service is invented. See network-modes.md for migration and staged bootstrap.
