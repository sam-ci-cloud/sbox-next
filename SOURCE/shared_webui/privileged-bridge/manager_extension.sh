# Additive WebUI integration. Included by the deterministic build, before main.
WEBUI_VARIANT="@VARIANT@"
WEBUI_LIB="/usr/local/lib/sbox-webui"
WEBUI_CONTROL_DIR="/var/lib/sbox-webui-control"

webui_firewall_reconcile() {
  local helper="$WEBUI_LIB/firewall.py" mode
  [ -f /etc/sbox-webui/settings.json ] || return 0
  # The helper directory must not allow another user to swap the helper (or its
  # sibling imports) after these checks.
  if [ ! -d "$WEBUI_LIB" ] || [ -L "$WEBUI_LIB" ] || [ "$(stat -c %u "$WEBUI_LIB")" != 0 ] \
    || (( (8#$(stat -c %a "$WEBUI_LIB") & 8#022) != 0 )); then
    warn 'Panel firewall helper directory missing or unsafe; previous hardening retained.'
    return 1
  fi
  # Execute only the installed root-owned helper, never a writable substitute.
  if [ ! -f "$helper" ] || [ -L "$helper" ] || [ "$(stat -c %u "$helper")" != 0 ]; then
    warn 'Panel firewall helper missing or unsafe; previous hardening retained.'
    return 1
  fi
  mode="$(stat -c %a "$helper")"
  if (( (8#$mode & 8#022) != 0 )); then
    warn 'Panel firewall helper is writable by another user; previous hardening retained.'
    return 1
  fi
  python3 -B "$helper" apply >/dev/null || {
    warn 'Panel firewall reconciliation failed; previous hardening retained. Run sbox webui doctor.'
    return 1
  }
}

# Read-only: is the panel's owned firewall rule still in place? (status/doctor; never mutates)
webui_firewall_healthy() {
  local helper="$WEBUI_LIB/firewall.py"
  [ -f /etc/sbox-webui/settings.json ] || return 0
  if [ ! -f "$helper" ] || [ -L "$helper" ] || [ "$(stat -c %u "$helper")" != 0 ] || (( (8#$(stat -c %a "$helper") & 8#022) != 0 )); then
    echo 'Panel firewall rule: helper missing or unsafe'; return 1
  fi
  local out
  if out="$(python3 -B "$helper" check 2>&1)"; then echo 'Panel firewall rule: healthy'; return 0; fi
  echo "Panel firewall rule: missing or inconsistent ($(printf '%s' "$out" | jq -r '.problems // [] | join(", ")' 2>/dev/null || echo unknown)); run: sbox firewall apply"
  return 1
}

webui_backup_snapshot() (
  [ -f /var/lib/sbox-webui/panel.db ] || exit 0
  local tmp
  tmp="$(mktemp -d "$RUNTIME_DIR/panel-backup.XXXXXXXX")"
  trap 'rm -rf -- "$tmp"' EXIT
  write_webui_assets "$tmp"
  python3 -B "$tmp/backend/panel_backup.py" snapshot "$1" >&2
)

webui_restore_data() (
  [ -f "$2/panel/panel.db" ] || exit 0
  local tmp
  tmp="$(mktemp -d "$RUNTIME_DIR/panel-restore.XXXXXXXX")"
  trap 'rm -rf -- "$tmp"' EXIT
  write_webui_assets "$tmp"
  python3 -B "$tmp/backend/panel_backup.py" "$1" "$2" >&2
)

webui_install_if_enabled() {
  accounting_stage
  if [ "${SBOX_FRESH_INSTALL:-false}" = true ] && ! jq -e '.accounting.enabled == true' "$STATE_FILE" >/dev/null; then
    if [ "$(uname -m)" = x86_64 ] && [ "$(jq -r .sing_box.version "$STATE_FILE")" = "$(jq -r .version /usr/local/lib/sbox-accounting/current/core_manifest.json)" ]; then accounting_enable
    else warn 'Accounting is unavailable on this unvalidated core version/architecture. Existing VPN and CLI remain available; quota writes are refused until a validated accounting core is installed.'; fi
  fi
  [ "${SBOX_WEBUI:-on}" != off ] || return 0
  if [ ! -f /etc/sbox-webui/settings.json ] || [ ! -f /etc/systemd/system/sbox-webui.service ]; then
    # Certificate-free REALITY and explicit self-signed Generic VPN installs
    # remain valid CLI functions. Do not silently change a public listener to
    # loopback or publish an untrusted login. Leave a concrete panel prerequisite.
    if [ "$WEBUI_VARIANT" = universal ] && [ "${SBOX_WEBUI_LISTEN:-0.0.0.0}" != 127.0.0.1 ] && [ "${SBOX_WEBUI_LISTEN:-0.0.0.0}" != ::1 ] && ! cert_trusted "$(jq -r '.certificate.source_fullchain // empty' "$STATE_FILE")" "$(jq -r .domain "$STATE_FILE")"; then
      warn 'WebUI pending: public HTTPS requires a trusted domain certificate. VPN installation is complete. Configure a certificate with sbox certificate, then run sbox webui install. Default public listener remains 0.0.0.0:9443.'
      return 0
    fi
    webui_command install
  fi
}

webui_command() (
  set -Eeuo pipefail
  local action="${1:-status}" temp
  if [ "$action" = unban ]; then
    [ "$#" -eq 2 ] || die 'Usage: sbox webui unban IP'
  else
    [ "$#" -le 1 ] || die 'Usage: sbox webui install|upgrade|start|stop|status|doctor|guard|unban IP|reset-admin|rollback|uninstall'
  fi
  need_root
  case "$action" in
    status) systemctl status sbox-webui.service sbox-webui-control.service --no-pager ;;
    guard) python3 "$WEBUI_LIB/current/backend/webui_security.py" status ;;
    unban) python3 "$WEBUI_LIB/current/backend/webui_security.py" unban "$2" ;;
    doctor)
      systemctl is-active --quiet sbox-webui-control.service sbox-webui.service
      [ -S /run/sbox-webui-control/control.sock ]
      [ "$(stat -c %a /etc/sbox-webui/bootstrap-admin.txt)" = 600 ]
      python3 "$WEBUI_LIB/current/backend/install.py" doctor "$WEBUI_VARIANT" ;;
    start|stop)
      if [ "$action" = start ]; then systemctl reset-failed sbox-webui.service sbox-webui-control.service; systemctl start sbox-webui-control.service sbox-webui.service
      else systemctl stop sbox-webui.service; fi ;;
    reset-admin)
      python3 "$WEBUI_LIB/current/backend/install.py" reset-admin "$WEBUI_VARIANT"
      echo 'Retrieve initial admin credentials locally: sudo cat /etc/sbox-webui/bootstrap-admin.txt' ;;
    install|upgrade)
      require_installed; acquire_lock; guard_no_pending_transaction
      if [ "$WEBUI_VARIANT" = zgocloud ]; then
        jq -e '.zgo_legacy_compat == true' "$STATE_FILE" >/dev/null || die 'This WebUI adapter requires the dedicated ZgoCloud state.'
      else
        jq -e '.zgo_legacy_compat != true' "$STATE_FILE" >/dev/null || die 'Use the independent ZgoCloud installer for this protected state.'
      fi
      ensure_runtime_dir
      temp="$(mktemp -d "$RUNTIME_DIR/webui-assets.XXXXXXXX")"
      trap 'rm -rf -- "$temp"' EXIT
      write_webui_assets "$temp"
      if [ "$WEBUI_VARIANT" = zgocloud ]; then
        cert_trusted "$(jq -r .certificate.source_fullchain "$STATE_FILE")" "$(jq -r .domain "$STATE_FILE")" || die 'ZgoCloud WebUI requires the existing trusted certificate; repair its ACME prerequisite first.'
      fi
      # Upgrade manager/helpers/exports through the existing policy journal;
      # adding the panel to an attached baseline must not leave stale helpers.
      client_policy_command apply >&2
      python3 "$temp/backend/install.py" "$action" "$WEBUI_VARIANT"
      echo 'WebUI credential retrieval: sudo cat /etc/sbox-webui/bootstrap-admin.txt'
      echo 'WebUI URL/settings: /etc/sbox-webui/settings.json (HTTPS; VPN ports unchanged)' ;;
    rollback|recover-db|uninstall)
      python3 "$WEBUI_LIB/current/backend/install.py" "$action" "$WEBUI_VARIANT" ;;
    *) die 'Unknown WebUI action' ;;
  esac
)

webui_policy_commit() {
  local candidate="$1" render="$2" temp="$3" source helpers_json
  source="$(readlink -f "${SBOX_MANAGER_SOURCE:-$0}")"
  install -d -m 0700 "$temp/helpers"
  write_state_helper > "$temp/helpers/sbox-state"
  write_policy_helper > "$temp/helpers/sbox-policy"
  helpers_json="$(jq -n --arg state "$temp/helpers/sbox-state" --arg policy "$temp/helpers/sbox-policy" \
    --arg state_target "$LIB_DIR/sbox-state" --arg policy_target "$LIB_DIR/sbox-policy" \
    '[{source:$state,target:$state_target},{source:$policy,target:$policy_target}]')"
  policy_transaction apply "$candidate" "$render" "$source" "$helpers_json"
}

webui_control_namespace() {
  python3 - "$WEBUI_CONTROL_DIR" <<'SBOX_WEBUI_NAMESPACE'
import os,sys
from pathlib import Path
root=Path(sys.argv[1])
for leaf in (root,root/'changes'):
    for path in (leaf,*leaf.parents):
        if path.is_symlink():raise SystemExit('Unsafe root control namespace symlink')
        if path.exists() and (path.stat().st_uid!=0 or path.stat().st_mode & 0o022):raise SystemExit('Unsafe root control namespace ownership/permissions')
    leaf.mkdir(mode=0o700,parents=True,exist_ok=True);leaf.chmod(0o700)
SBOX_WEBUI_NAMESPACE
}

webui_control_command() (
  set -Eeuo pipefail
  local action="${1:-}" tmp token change kind expected profile format user_id
  [ "$#" -eq 1 ] || die 'Exactly one WebUI control action is required'
  need_root; require_installed
  case "$action" in prepare|commit|export) ;; *) die 'Invalid control action' ;; esac
  acquire_lock; guard_no_pending_transaction; assert_safe_namespaces
  if declare -F zgo_assert_candidate_identity >/dev/null; then zgo_assert_candidate_identity "$STATE_FILE"; fi
  tmp="$(mktemp -d "$RUNTIME_DIR/webui-control.XXXXXXXX")"
  trap 'rm -rf -- "$tmp"' EXIT
  cat > "$tmp/request.json"
  [ "$(stat -c %s "$tmp/request.json")" -le 65536 ] || die 'Request too large'
  jq -e 'type=="object"' "$tmp/request.json" >/dev/null
  if [ "$action" = export ]; then
    profile="$(jq -r .profile "$tmp/request.json")"; format="$(jq -r .format "$tmp/request.json")"
    case "$profile" in global|cn|internal) ;; *) die 'Unknown export profile' ;; esac
    case "$format" in yaml|json|links|singbox) ;; *) die 'Unknown export format' ;; esac
    user_id="$(jq -r .id "$tmp/request.json")"
    [[ "$user_id" =~ ^(legacy|[a-f0-9]{32})$ ]] || die 'Invalid user'
    python3 "$WEBUI_LIB/current/privileged-bridge/controller.py" export "$STATE_FILE" "$tmp/user.json" "$WEBUI_VARIANT" < "$tmp/request.json"
    if [ "$user_id" = legacy ] && [ "$profile" = global ] &&
       declare -F zgo_write_original_yaml >/dev/null && [ "$format" != links ] && [ "$(jq -r '.endpoint // "auto"' "$tmp/request.json")" = auto ]; then
      zgo_write_original_yaml "$tmp/original.yaml"
      case "$format" in
        yaml) cat "$tmp/original.yaml" ;;
        json) python3 "$WEBUI_LIB/current/backend/export_json.py" "$tmp/original.yaml" ;;
        singbox) python3 "$WEBUI_LIB/current/backend/export_json.py" --full "$profile" "$tmp/original.yaml" ;;
      esac
      exit 0
    fi
    state_tool render "$tmp/user.json" "$tmp/export"
    case "$format" in
      yaml) cat "$tmp/export/clmi-$profile.yaml" ;;
      links) cat "$tmp/export/links.txt" ;;
      json) python3 "$WEBUI_LIB/current/backend/export_json.py" --addresses-from "$tmp/user.json" "$tmp/export/clmi-$profile.yaml" ;;
      singbox) python3 "$WEBUI_LIB/current/backend/export_json.py" --addresses-from "$tmp/user.json" --full "$profile" "$tmp/export/clmi-$profile.yaml" ;;
    esac
    exit 0
  fi
  webui_control_namespace
  # Bounded, short-lived previews; never treat an expired preview as committed.
  find "$WEBUI_CONTROL_DIR/changes" -mindepth 1 -maxdepth 1 -type d -mmin +15 -exec rm -rf -- {} +
  if [ "$action" = prepare ]; then
    python3 "$WEBUI_LIB/current/privileged-bridge/controller.py" candidate "$STATE_FILE" "$tmp/candidate.json" "$WEBUI_VARIANT" < "$tmp/request.json" > "$tmp/preview.json"
    state_tool validate "$tmp/candidate.json"
    render_bundle "$tmp/candidate.json" "$tmp/render"
    "$SBOX_BIN" check -c "$tmp/render/server.json" >/dev/null
    kind="$(jq -r .kind "$tmp/request.json")"
    if [ "$kind" = network ]; then state_tool endpoint-preflight "$tmp/candidate.json" >/dev/null || die "Network endpoint/DNS validation failed; no settings changed."; fi
    if ! [[ "$kind" =~ ^(policy|quota|quota-bulk|portal-account|accounting-policy)$ ]]; then assert_candidate_ports_free "$tmp/candidate.json"; fi
    if [ "$kind" = user-create ] && jq -e '.data.subscription==true' "$tmp/request.json" >/dev/null; then
      user_id="$(python3 - "$STATE_FILE" "$tmp/candidate.json" <<'SBOX_NEW_ONBOARD_ID'
import json,sys
old={u['id'] for u in json.load(open(sys.argv[1])).get('managed_users',[])}
new=[u['id'] for u in json.load(open(sys.argv[2])).get('managed_users',[]) if u['id'] not in old]
if len(new)!=1:raise SystemExit('Expected one new user')
print(new[0])
SBOX_NEW_ONBOARD_ID
)"
      jq -n --arg id "$user_id" '{id:$id,profile:"global",format:"yaml"}' | python3 "$WEBUI_LIB/current/privileged-bridge/controller.py" export "$tmp/candidate.json" "$tmp/client-state.json" "$WEBUI_VARIANT"
      state_tool render "$tmp/client-state.json" "$tmp/client-validated"
      validate_client_bundle "$tmp/client-validated"
    fi
    token="$(openssl rand -hex 32)"; change="$WEBUI_CONTROL_DIR/changes/$token"
    install -d -m 0700 "$change"
    jq '{kind:.kind,onboarding:(.kind=="user-create" and .data.subscription==true)}' "$tmp/request.json" > "$change/request.json" # plaintext passwords never persist in previews
    cp "$tmp/candidate.json" "$change/state.json"
    state_fingerprint "$STATE_FILE" > "$change/before.sha"
    date +%s > "$change/created"
    jq --arg token "$token" --argjson expires "$(($(date +%s)+600))" '. + {token:$token,expires_at:$expires}' "$tmp/preview.json"
    exit 0
  fi
  token="$(jq -r .token "$tmp/request.json")"
  [[ "$token" =~ ^[a-f0-9]{64}$ ]] || die 'Invalid change token'
  change="$WEBUI_CONTROL_DIR/changes/$token"
  [ -d "$change" ] && [ ! -L "$change" ] || die 'Unknown or consumed change token'
  [ "$(($(date +%s)-$(cat "$change/created")))" -le 600 ] || die 'Change preview expired'
  expected="$(cat "$change/before.sha")"
  [ "$(state_fingerprint "$STATE_FILE")" = "$expected" ] || die 'State changed since preview; prepare again'
  CURRENT_STATE_SHA="$expected"
  kind="$(jq -r .kind "$change/request.json")"
  # Consume before entering the transaction; a failed/crashed commit cannot replay.
  cp "$change/state.json" "$tmp/candidate.json"
  rm -rf -- "$change"
  if [[ "$kind" =~ ^(policy|quota|quota-bulk|portal-account|accounting-policy)$ ]]; then
    render_bundle "$tmp/candidate.json" "$tmp/render"
    webui_policy_commit "$tmp/candidate.json" "$tmp/render" "$tmp" >&2
    if declare -F zgo_assert_candidate_identity >/dev/null; then zgo_assert_candidate_identity "$STATE_FILE"; fi
  else
    if [ "$kind" = network ]; then
      state_tool endpoint-preflight "$tmp/candidate.json" >/dev/null || die "Network preflight changed; prepare again."
      local network_backup; network_backup="$(create_backup_archive network-webui)"; echo "Pre-network native backup: $network_backup" >&2
    fi
    SBOX_REUSE_MANAGED_CERT=true apply_candidate "$tmp/candidate.json" '' 'WebUI managed change' >&2
  fi
  if jq -e '.accounting.enabled == true' "$STATE_FILE" >/dev/null && [ -f /usr/local/lib/sbox-accounting/current/accounting.py ]; then
    python3 -B /usr/local/lib/sbox-accounting/current/accounting.py reconcile --inherited-lock >&2
  fi
  # Report only what the manager observed after its own validated commit.
  local active=false pid=''
  if systemctl is-active --quiet sing-box.service; then active=true; fi
  pid="$(systemctl show -p MainPID --value sing-box.service 2>/dev/null || true)"
  jq -n --arg kind "$kind" --arg fp "$(sha256sum "$STATE_FILE" | cut -c1-16)" --argjson active "$active" --arg pid "$pid" \
    --argjson restarted "$([[ "$kind" =~ ^(policy|quota|quota-bulk|portal-account|accounting-policy)$ ]] && echo false || echo true)" --argjson at "$(date +%s)" \
    '{committed:true, kind:$kind, committed_at:$at, state_fingerprint:$fp, service_active:$active, core_pid:$pid, restarted:$restarted}'
)

webui_require_variant() {
  if [ "$WEBUI_VARIANT" = zgocloud ]; then
    jq -e '.zgo_legacy_compat == true' "$STATE_FILE" >/dev/null || die 'Use the independent Generic installer for this state; no components were staged.'
  else
    jq -e '.zgo_legacy_compat != true' "$STATE_FILE" >/dev/null || die 'Use the independent ZgoCloud installer for this protected state; no components were staged.'
  fi
}
accounting_stage() (
  need_root; require_installed; acquire_lock; guard_no_pending_transaction
  webui_require_variant
  local temp
  temp="$(mktemp -d "$RUNTIME_DIR/accounting-assets.XXXXXXXX")"
  trap 'rm -rf -- "$temp"' EXIT
  write_webui_assets "$temp"
  python3 -B "$temp/backend/accounting_install.py" stage
)
accounting_preflight() (
  need_root; require_installed; acquire_lock; guard_no_pending_transaction
  webui_require_variant
  local temp
  temp="$(mktemp -d "$RUNTIME_DIR/accounting-preflight.XXXXXXXX")"
  trap 'rm -rf -- "$temp"' EXIT
  write_webui_assets "$temp"
  python3 -B "$temp/backend/accounting_install.py" preflight
)
accounting_start_ready() {
  local attempt result
  systemctl enable sbox-accounting.service || return 1
  # enable --now leaves an active process on its previous code and mount
  # namespace. Load the staged runtime and its current writable paths.
  systemctl restart sbox-accounting.service || return 1
  for attempt in 1 2 3 4 5; do
    result="$(python3 -B /usr/local/lib/sbox-accounting/current/accounting.py reconcile --inherited-lock)" || return 1
    if jq -e '.status == "ready"' >/dev/null <<< "$result"; then return 0; fi
    sleep 1
  done
  die 'Accounting reconciliation is not ready; inspect sbox accounting doctor.'
}
accounting_enable() (
  need_root; require_installed; acquire_lock; guard_no_pending_transaction
  local temp
  local installed staged=/usr/local/lib/sbox-accounting/core-candidate
  installed="$(sha256sum "$SBOX_BIN" | cut -d' ' -f1)"
  # Already active on the installed core: nothing to do unless this package
  # staged a different verified core (a product upgrade carrying a newer engine).
  if jq -e '.accounting.enabled == true' "$STATE_FILE" >/dev/null && [ "$(jq -r .accounting.core_sha256 "$STATE_FILE")" = "$installed" ] \
    && { [ ! -f "$staged" ] || [ "$(sha256sum "$staged" | cut -d' ' -f1)" = "$installed" ]; }; then
    accounting_start_ready
    return 0
  fi
  temp="$(mktemp -d "$RUNTIME_DIR/accounting-enable.XXXXXXXX")";trap 'rm -rf -- "$temp"' EXIT
  python3 -B /usr/local/lib/sbox-accounting/current/accounting_install.py candidate "$temp/state.json"
  apply_candidate "$temp/state.json" /usr/local/lib/sbox-accounting/core-candidate 'Activate source-pinned authenticated accounting (core restart)'
  accounting_start_ready
)
accounting_command() (
  need_root; require_installed
  local action="${1:-doctor}"
  shift || true
  case "$action" in
    doctor) [ "$#" -eq 0 ] || die 'Usage: sbox accounting doctor'; python3 -B /usr/local/lib/sbox-accounting/current/accounting.py doctor ;;
    enable) [ "${1:-}" = --confirm-core-restart ] && [ "$#" -eq 1 ] || die 'Activation switches to the verified core and restarts sing-box once. Run: sbox accounting enable --confirm-core-restart'; accounting_stage; accounting_enable ;;
    reconcile|backup) [ "$#" -eq 0 ] || die 'Unexpected arguments'; python3 -B /usr/local/lib/sbox-accounting/current/accounting.py "$action" ;;
    recover) acquire_lock; [ "${1:-}" = --confirm ] && [ "$#" -eq 1 ] || die 'Recovery restores last-good lower-bound accounting with an explicit uncertainty gap. Run: sbox accounting recover --confirm'; systemctl stop sbox-accounting.service; python3 -B /usr/local/lib/sbox-accounting/current/accounting.py recover; systemctl start sbox-accounting.service ;;
    *) die 'Usage: sbox accounting doctor|enable --confirm-core-restart|reconcile|backup|recover --confirm' ;;
  esac
)
quota_command() {
  need_root; require_installed
  python3 -B "$WEBUI_LIB/current/backend/quota_cli.py" "$@"
}
feature_upgrade_recover() (
  need_root; require_installed; acquire_lock
  local dir="$BACKUP_DIR/features.pending" name old tmp
  local TXN_SNAPSHOT_DIR="$dir"
  if transaction_in_progress || policy_journal_pending; then die "Recover the interrupted native/policy transaction first with sbox recover; feature snapshot retained."; fi
  [ -d "$dir" ] && [ ! -L "$dir" ] || die 'No safe feature recovery snapshot.'
  validate_runtime_snapshot "$dir/runtime" || die 'Invalid feature recovery snapshot; retained for inspection.'
  # Component staging never writes the manager, native config or running core.
  # In this phase restore only its independent pointer/unit and newly-created
  # authorization files. A failed preparation must not restart an existing VPN.
  if [ "$(cat "$dir/phase" 2>/dev/null || echo core)" = staging ]; then
    for name in stats-auth.key quota-runtime.json; do
      if [ ! -e "$dir/runtime/base/$name" ]; then rm -f -- "$BASE_DIR/$name" || die "Preparation file cleanup failed; snapshot retained."; fi
    done
    old="$(cat "$dir/accounting.previous")"
    if [ "$old" = absent ]; then rm -f /usr/local/lib/sbox-accounting/current || die "Accounting pointer cleanup failed."
    else
      [[ "$old" =~ ^release-[a-f0-9]+$ ]] || die 'Invalid accounting recovery pointer.'
      tmp=/usr/local/lib/sbox-accounting/.features-recover
      rm -f -- "$tmp" && ln -s "$old" "$tmp" && mv -Tf "$tmp" /usr/local/lib/sbox-accounting/current || die "Accounting pointer restore failed; snapshot retained."
    fi
    if [ -e "$dir/accounting.service" ]; then
      cp -a "$dir/accounting.service" /etc/systemd/system/sbox-accounting.service || die "Accounting unit restore failed; snapshot retained."
    else rm -f /etc/systemd/system/sbox-accounting.service || die "Accounting unit cleanup failed."; fi
    systemctl daemon-reload || die "Unit reload failed; snapshot retained."
    verify_restored_runtime "$dir/runtime" prepare live-quota || die 'Preparation recovery could not be verified; snapshot retained.'
    rm -rf -- "$dir" || die "Verified recovery journal cleanup failed."
    ok 'Accounting preparation rolled back without restarting VPN or panel; databases preserved.'
    return 0
  fi
  # Databases remain live and are never overwritten with stale snapshots.
  for name in sbox-accounting sbox-webui sbox-webui-control; do
    if systemctl is-active --quiet "$name.service"; then systemctl stop "$name.service" || die "Component stop failed; snapshot retained."; fi
  done
  restore_runtime "$dir/runtime" || die 'Feature runtime recovery failed; snapshot retained.'
  for name in webui accounting; do
    old="$(cat "$dir/$name.previous")"
    if [ "$old" = absent ]; then rm -f "/usr/local/lib/sbox-$name/current" || die "Component pointer cleanup failed."; continue; fi
    [[ "$old" =~ ^release-[a-f0-9]+$ ]] || die 'Invalid feature recovery release pointer.'
    tmp="/usr/local/lib/sbox-$name/.features-recover"
    rm -f -- "$tmp" && ln -s "$old" "$tmp" && mv -Tf "$tmp" "/usr/local/lib/sbox-$name/current" || die "Component pointer recovery failed; snapshot retained."
  done
  systemctl daemon-reload || die "Unit reload failed; snapshot retained."
  if [ -L /usr/local/lib/sbox-webui/current ]; then systemctl restart sbox-webui-control.service sbox-webui.service || die "Panel recovery restart failed; snapshot retained."; fi
  if [ -L /usr/local/lib/sbox-accounting/current ]; then systemctl restart sbox-accounting.service || die "Accounting recovery restart failed; snapshot retained."; else systemctl disable --now sbox-accounting.service || die "Accounting recovery stop failed."; fi
  systemctl is-active --quiet sing-box.service || die 'Feature recovery health check failed; snapshot retained.'
  rm -rf -- "$dir" || die "Verified recovery journal cleanup failed."
  ok 'Feature upgrade rolled back; user, portal and accounting databases preserved.'
)
upgrade_features_command() (
  [ "$#" -eq 1 ] && [ "$1" = --confirm-core-restart ] || die 'One-time accounting activation restarts sing-box. Run the full installer with: upgrade-features --confirm-core-restart'
  need_root; require_installed; acquire_lock; guard_no_pending_transaction
  # Validate ALL embedded assets and the selected core before updating the panel.
  accounting_preflight
  local pending="$BACKUP_DIR/features.pending" prepared
  prepared="$(mktemp -d "$BACKUP_DIR/features.prepare.XXXXXXXX")"
  trap 'rm -rf -- "$prepared"' EXIT
  install -d -m 0700 "$prepared/runtime"
  snapshot_runtime "$prepared/runtime"
  # Both pointers must be present before an in-place feature upgrade.
  { readlink /usr/local/lib/sbox-webui/current || echo absent; } > "$prepared/webui.previous"
  { readlink /usr/local/lib/sbox-accounting/current || echo absent; } > "$prepared/accounting.previous"
  if [ -f /etc/systemd/system/sbox-accounting.service ]; then cp -a /etc/systemd/system/sbox-accounting.service "$prepared/accounting.service"; fi
  printf 'staging\n' > "$prepared/phase"
  durable_paths "$prepared/webui.previous" "$prepared/accounting.previous" "$prepared/phase" "$prepared"
  if [ -e "$prepared/accounting.service" ]; then durable_paths "$prepared/accounting.service"; fi
  mv -T "$prepared" "$pending"
  durable_paths "$pending" "$BACKUP_DIR"
  SBOX_FEATURE_HELD=true
  feature_upgrade_finish() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if [ "$rc" -ne 0 ]; then
      warn 'Feature upgrade failed; restoring the prior runtime and component releases.'
      feature_upgrade_recover || warn 'Automatic recovery needs attention; run sbox recover. Snapshot retained.'
    fi
    exit "$rc"
  }
  trap feature_upgrade_finish EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  accounting_stage
  printf 'panel\n' > "$pending/phase"
  durable_paths "$pending/phase" "$pending"
  webui_command upgrade
  # Universal only: bring the self-hosted Personal Cloud tree and unit to this
  # release inside the same recoverable feature transaction.
  if declare -F fallback_web_upgrade >/dev/null; then
    printf 'website\n' > "$pending/phase"
    durable_paths "$pending/phase" "$pending"
    fallback_web_upgrade
  fi
  printf 'core\n' > "$pending/phase"
  durable_paths "$pending/phase" "$pending"
  accounting_enable
  rm -rf -- "$pending"
  trap - EXIT INT TERM HUP
  # 1.2.1: installs from before the resilient server DNS cache get it once, in
  # its own verified transaction (REALITY stays usable through resolver outages).
  if ! jq -e 'has("server_dns")' "$STATE_FILE" >/dev/null; then
    local dns_tmp; dns_tmp="$(mktemp -d "$RUNTIME_DIR/upgrade-dns.XXXXXX")"
    normalized_current_state "$dns_tmp/current.json"
    jq '.server_dns={optimistic:true}|.updated_at=(now|todateiso8601)' "$dns_tmp/current.json" > "$dns_tmp/state.json"
    apply_candidate "$dns_tmp/state.json" '' 'resilient server DNS cache (upgrade default)'
    rm -rf -- "$dns_tmp"
  fi
)


# Network-only hooks run inside the existing manager snapshot/rollback boundary.
snapshot_runtime() {
  write_network_helper | python3 - snapshot "$STATE_FILE" "$1"
  snapshot_runtime_base "$@"
}
restore_runtime() {
  restore_runtime_base "$@" || return
  write_network_helper | python3 - restore "$STATE_FILE" "$1"
}
webui_network_apply() { write_network_helper | python3 - panel-apply "$1"; }
