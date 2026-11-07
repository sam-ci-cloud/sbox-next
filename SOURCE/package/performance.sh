#!/usr/bin/env bash
# Explicit client preference profiles; credentials, quotas and kernel stay intact.
set -Eeuo pipefail
case "${1:-show}" in
  stable|conservative)
    echo 'Stable profile: prefer TUIC for new client connections.'
    exec sbox client-policy primary tuic ;;
  throughput)
    echo 'Throughput profile: prefer AnyTLS for new client connections.'
    echo 'Measured on the acceptance route; other routes and UDP workloads may differ.'
    exec sbox client-policy primary anytls ;;
  latency)
    echo 'No latency profile was promoted: the measured experiments did not establish a reliable benefit.' >&2
    exit 2 ;;
  show) exec sbox client-policy show ;;
  *) echo 'Usage: bash performance.sh stable|throughput|latency|show' >&2; exit 2 ;;
esac
