  if [ "$accounting_was_active" = true ] && state_exists && jq -e '.accounting.enabled == true' "$STATE_FILE" >/dev/null; then
    restore_attempt 'accounting collector refresh' systemctl restart sbox-accounting.service
  fi
