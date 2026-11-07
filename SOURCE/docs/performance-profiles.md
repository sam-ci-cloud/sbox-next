# Measured performance profiles

The release keeps conservative runtime and provider kernel defaults. Its optional profiles use the existing validated client-policy transaction; no quota, authentication, original node identity or OS security setting is changed.

```bash
cd /root/SING-BOX
bash performance.sh show
bash performance.sh throughput
# Return to the conservative default:
bash performance.sh stable
```

The throughput profile prefers AnyTLS in newly generated client profiles. Import/reload the subscription and select that preference in clients that retain saved group choices. Existing sessions keep their transport. The stable profile retains the existing TUIC preference. TUIC measured about 370 Mbps in the same workload, versus 735 Mbps for AnyTLS. The original protected six-node YAML remains byte-identical; these preferences apply to the managed generated profiles.

On one owned inter-VPS route, a one-vCPU server with accounting enabled measured median TCP payload rates of about 397 Mbps for VLESS REALITY and 735 Mbps for AnyTLS (three 10-second trials each, 8-MiB responses checked by SHA-256). The approximately 85% difference compares those transports in that workload. It is not a universal engine speedup or a provider bandwidth guarantee. All five protocols remained available, and quotas stayed enabled. AnyTLS's TCP transport can have different UDP/loss behaviour from native QUIC protocols; choose according to the client workload.

The measured fq queue and GOGC=200 experiments did not establish a consistent throughput improvement across protocols. Both were rolled back; neither is a default or promoted throughput setting. A latency profile is intentionally unavailable until a controlled experiment supports it. The final private report preserves all trial data, including regressions, timing, memory and restoration evidence.

Direct-path baselines were measured separately on three owned routes, three 30-second trials each for TCP and UDP. They are not substituted for encrypted VPN measurements. Phones, external ISP paths and long-term provider contention were not inferred from these server results.
