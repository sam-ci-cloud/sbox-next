  # The collector has a private writable bind of BASE_DIR. Stop it before
  # replacing that tree so recovery cannot leave it on a detached namespace.
  local accounting_was_active=false
  if systemctl is-active --quiet sbox-accounting.service; then
    accounting_was_active=true
    restore_attempt 'stop accounting before configuration restore' systemctl stop sbox-accounting.service
  fi
