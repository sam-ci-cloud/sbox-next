# Shared by both products; only validated WebUI changes may reuse an active pair.
select_candidate_certificate() {
  local candidate="$1"
  EFFECTIVE_CERT="$(jq -r '.certificate.source_fullchain' "$candidate")"
  EFFECTIVE_KEY="$(jq -r '.certificate.source_key' "$candidate")"
  if certificate_pair_ok "$EFFECTIVE_CERT" "$EFFECTIVE_KEY"; then return 0; fi
  # The bridge keeps ProtectHome enabled. An external /root source can be
  # inaccessible there after a successful installation. Reuse the served pair
  # only when the endpoint and complete certificate plan are unchanged; normal
  # certificate replacement and all trust/date/domain checks remain mandatory.
  if [ "${SBOX_REUSE_MANAGED_CERT:-false}" = true ] && state_exists &&
     jq -e --slurpfile current "$STATE_FILE" '.domain==$current[0].domain and .certificate==$current[0].certificate' "$candidate" >/dev/null &&
     resolve_service_certificate; then return 0; fi
  return 1
}
