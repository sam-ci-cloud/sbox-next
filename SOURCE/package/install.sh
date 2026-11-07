#!/usr/bin/env bash
# SING-BOX standalone package entrypoint.
#
#   cd /root && tar -xzf SING-BOX.tar.gz && cd /root/SING-BOX && bash install.sh
#
# Verifies the whole package (SHA256SUMS), runs a read-only preflight of this
# host, then hands over to the verified all-in-one installer in bin/. Nothing is
# changed on the host before both checks pass. The package never contacts
# GitHub; normal OS package repositories (apt), Let's Encrypt/ACME, DNS and NTP
# are used as documented in docs/INSTALLATION-GUIDE.md.
set -Eeuo pipefail
umask 077
# The public bootstrap execs this entrypoint so sudo observes terminal stops.
# Only its private, owned, narrowly named staging directory may be removed.
cleanup_bootstrap_stage() {
  local stage="${SBOX_BOOTSTRAP_STAGE:-}"
  [ -n "$stage" ] || return 0
  case "$stage" in /*/singbox-bootstrap.????????) ;; *) return 0 ;; esac
  [ ! -L "$stage" ] && [ -d "$stage" ] || return 0
  [ "$(stat -c '%u %a' -- "$stage")" = "$(id -u) 700" ] || return 0
  rm -rf -- "$stage"
}
trap cleanup_bootstrap_stage EXIT
PKG="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALLER="$PKG/bin/sbox-installer.sh"
STATE=/etc/sbox-manager/state.json
POINTER=/var/backups/sbox-manager/PRE-UPGRADE-BACKUP
MIN_FREE_ROOT_MB="${SBOX_MIN_FREE_MB:-1024}"
MIN_FREE_TMP_MB=300
FAILS=0; WARNS=0

say() { printf '[SING-BOX] %s\n' "$*" >&2; }
fail() { printf '[SING-BOX] ERROR: %s\n' "$*" >&2; exit 1; }
check_ok() { printf '  [PASS] %s\n' "$*" >&2; }
check_warn() { printf '  [WARN] %s\n' "$*" >&2; WARNS=$((WARNS+1)); }
check_fail() { printf '  [FAIL] %s\n' "$*" >&2; FAILS=$((FAILS+1)); }
version() { sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$PKG/manifest.json" | head -n1; }

usage() {
  cat <<HELP
SING-BOX $(version) standalone package

Usage: bash install.sh [COMMAND] [VARIANT] [OPTIONS]

  (no command)                   Interactive menu (needs a terminal)
  install generic|zgocloud [..]  Fresh install (guided; or unattended with --yes and options)
  upgrade [generic|zgocloud]     Back up, then upgrade in place (variant auto-detected)
  recover [generic|zgocloud]     Recover an interrupted upgrade/transaction
  rollback [BACKUP.tar.gz] [--force]  Restore the automatic pre-upgrade backup (or a given one)
  verify [generic|zgocloud]      Read-only: package checksums + embedded payload integrity
  preflight [VARIANT] [OPTIONS]  Read-only host checks (dry run); changes nothing
  uninstall [--force]            Remove the SBOX runtime; keeps backups and LE lineages
  help                           This help

Same commands as separate scripts: verify.sh, upgrade.sh, rollback.sh, recover.sh,
uninstall.sh. ZgoCloud needs the owner's unlock: entered without echo, or
SBOX_ZGO_UNLOCK_FILE=/root/private/ZgoCloud-UNLOCK.txt (root-owned, chmod 600).
Installer options (install): see docs/INSTALLATION-GUIDE.md or 'bash bin/sbox-installer.sh help'.
HELP
}

# -- package integrity ------------------------------------------------------
verify_package() {
  [ -f "$PKG/SHA256SUMS" ] && [ -f "$PKG/manifest.json" ] && [ -f "$INSTALLER" ] || fail 'Package is incomplete (SHA256SUMS, manifest.json or bin/sbox-installer.sh missing). Re-extract SING-BOX.tar.gz.'
  command -v sha256sum >/dev/null || fail 'sha256sum is missing (apt-get install coreutils).'
  local links listed present unexpected
  links="$(cd "$PKG" && find . -type l -printf '%P\n' | head -n5)"
  [ -z "$links" ] || fail "Package contains symbolic links (refused): $links"
  (cd "$PKG" && sha256sum --check --strict --quiet SHA256SUMS) || fail 'Package checksum verification failed: a file is missing, truncated or modified. Re-extract a verified SING-BOX.tar.gz.'
  listed="$(cd "$PKG" && sed -n 's/^[0-9a-f]\{64\}  //p' SHA256SUMS | LC_ALL=C sort)"
  present="$(cd "$PKG" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort)"
  unexpected="$(LC_ALL=C comm -13 <(printf '%s\n' "$listed") <(printf '%s\n' "$present") || true)"
  if [ -n "$unexpected" ]; then
    if grep -qE '^(bin/|install\.sh$|[a-z]+\.sh$)' <<< "$unexpected"; then fail "Unexpected executable files in package: $(head -n3 <<< "$unexpected" | paste -sd' ')"; fi
    say "Note: extra files not part of the package: $(head -n3 <<< "$unexpected" | paste -sd' ')"
  fi
  say "Package $(version): $(wc -l < "$PKG/SHA256SUMS") files verified (SHA-256)."
}

# Read-only hint: an installer killed by SIGKILL or the OOM killer cannot run its
# cleanup trap and leaves its /tmp work directory (~100 MiB each). Only report
# them when no installer holds the lock; never delete anything during preflight.
stale_installer_workdirs_hint() {
  local dirs=() d tmp="${SBOX_HINT_TMP:-/tmp}" lock="${SBOX_HINT_LOCK:-/run/sbox-all-in-one.lock}"
  for d in "$tmp"/sbox-all-in-one.??????????; do
    [ -d "$d" ] && [ ! -L "$d" ] && [ "$(stat -c %u "$d")" = 0 ] && dirs+=("$d")
  done
  [ "${#dirs[@]}" -gt 0 ] || return 0
  if command -v flock >/dev/null && { exec 9>"$lock"; } 2>/dev/null && flock -n 9; then
    flock -u 9
    say "Stale work directories from an interrupted installer use $(du -smc "${dirs[@]}" 2>/dev/null | tail -n1 | cut -f1) MiB in /tmp."
    say "No installer is running, so they are safe to remove: rm -rf -- $tmp/sbox-all-in-one.?????????? (bash recover.sh removes them for you)"
  else
    say "An installer appears to be running; wait for it to finish before retrying."
  fi
}

# recover only: remove the work directories of installers that were killed (SIGKILL/OOM cannot run
# their cleanup trap). Same proof as the hint: the installer lock is free, so none is running; only
# root-owned, non-symlink directories with the exact installer name pattern are removed.
remove_stale_installer_workdirs() {
  local dirs=() d tmp="${SBOX_HINT_TMP:-/tmp}" lock="${SBOX_HINT_LOCK:-/run/sbox-all-in-one.lock}" mb
  for d in "$tmp"/sbox-all-in-one.??????????; do
    [ -d "$d" ] && [ ! -L "$d" ] && [ "$(stat -c %u "$d")" = 0 ] && dirs+=("$d")
  done
  [ "${#dirs[@]}" -gt 0 ] || return 0
  if command -v flock >/dev/null && { exec 9>"$lock"; } 2>/dev/null && flock -n 9; then
    mb="$(du -smc "${dirs[@]}" 2>/dev/null | tail -n1 | cut -f1)"
    rm -rf -- "${dirs[@]}"
    flock -u 9
    say "Removed ${#dirs[@]} stale work director$([ "${#dirs[@]}" -eq 1 ] && echo y || echo ies) of interrupted installers (${mb} MiB in /tmp)."
  else
    say "An installer appears to be running; stale work directories were left in place."
  fi
}

# -- read-only host preflight ----------------------------------------------
opt_value() { # opt_value NAME ARGS...  -> value of --NAME VALUE or --NAME=VALUE
  local name="$1"; shift
  while [ "$#" -gt 0 ]; do
    case "$1" in --"$name") printf '%s\n' "${2:-}"; return 0 ;; --"$name"=*) printf '%s\n' "${1#*=}"; return 0 ;; esac
    shift
  done
  return 1
}

# statfs via stat(1): works with GNU coreutils and with the uutils coreutils of
# Ubuntu 26.10, whose df has no -m option.
free_mb() { stat -f -c '%a %S' -- "$1" 2>/dev/null | awk '{printf "%d\n", $1 * $2 / 1048576}'; }

existing_variant() {
  [ -s "$STATE" ] || return 1
  if grep -q '"zgo_legacy_compat": *true' "$STATE"; then echo zgocloud; else echo generic; fi
}

check_certificate_inputs() {
  local mode domain cert key now
  mode="$(opt_value cert "$@" || true)"; domain="$(opt_value domain "$@" || true)"
  # The protected hostname belongs only in the authenticated encrypted manager.
  # Its authoritative certificate/SAN check runs there before any commit.
  if [ "${VARIANT:-}" = zgocloud ]; then
    domain=''
    check_ok 'Protected domain certificate validation is delegated to the authenticated ZgoCloud manager'
  fi
  case "$mode" in
    existing)
      cert="$(opt_value cert-path "$@" || true)"; key="$(opt_value key-path "$@" || true)"
      [ -n "$cert" ] && [ -n "$key" ] || { check_fail '--cert existing needs --cert-path and --key-path'; return; }
      [ -r "$cert" ] && [ -r "$key" ] || { check_fail "Certificate or key is not readable: $cert / $key"; return; }
      if ! command -v openssl >/dev/null; then check_warn 'openssl not installed yet; the installer validates the certificate pair after bootstrap'; return; fi
      openssl x509 -in "$cert" -noout >/dev/null 2>&1 || { check_fail "Not a PEM certificate: $cert"; return; }
      openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || check_fail 'Certificate is expired'
      openssl x509 -in "$cert" -noout -checkend 1209600 >/dev/null 2>&1 || check_warn 'Certificate expires within 14 days'
      now="$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null | sha256sum)"
      [ "$now" = "$(openssl pkey -in "$key" -pubout 2>/dev/null | sha256sum)" ] && check_ok 'Certificate and private key match' || check_fail 'Private key does not match the certificate'
      if [ -n "$domain" ]; then
        openssl x509 -in "$cert" -noout -checkhost "$domain" 2>/dev/null | grep -q 'does match' && check_ok "Certificate SAN covers $domain" || check_fail "Certificate does not cover $domain"
      fi
      [ "$(( 8#$(stat -c %a "$key") & 8#077 ))" -eq 0 ] && check_ok 'Private key file is not group/world accessible' || check_warn "Private key file permissions are broad ($(stat -c %a "$key")); chmod 600 recommended" ;;
    certbot-http01|'')
      [ "${VARIANT:-}" = zgocloud ] || [ "$mode" = certbot-http01 ] || return 0
      if command -v ss >/dev/null && ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -qE '(^|:)80$'; then
        check_fail 'TCP 80 is in use; ACME HTTP-01 needs it free during issuance'
      else check_ok 'TCP 80 is free for ACME HTTP-01 (also allow it in the provider firewall)'; fi
      if [ -n "$domain" ] && command -v getent >/dev/null; then
        getent ahosts "$domain" >/dev/null 2>&1 && check_ok "$domain resolves in DNS" || check_warn "$domain does not resolve yet; ACME HTTP-01 needs a public A/AAAA record"
      fi ;;
    certbot-dns-cloudflare)
      local token; token="$(opt_value cf-token-file "$@" || true)"
      if [ -n "$token" ]; then
        [ -f "$token" ] && [ "$(( 8#$(stat -c %a "$token") & 8#077 ))" -eq 0 ] && check_ok 'Cloudflare token file present and private' || check_fail "Cloudflare token file missing or not chmod 600: $token"
      elif [ -n "${SBOX_CF_TOKEN:-}" ]; then check_ok 'Cloudflare token supplied via SBOX_CF_TOKEN'
      else check_warn 'No --cf-token-file/SBOX_CF_TOKEN; the guided installer will ask for it'; fi ;;
    self-signed|reuse) check_ok "Certificate mode: $mode" ;;
    *) check_fail "Unknown --cert mode: $mode" ;;
  esac
}

preflight() { # preflight ACTION VARIANT [installer options]
  local action="$1" variant="$2"; shift 2
  local id='' ver='' existing mb lock_holder
  FAILS=0; WARNS=0
  say "Preflight for '$action $variant' (read-only; no changes are made):"
  [ "$(id -u)" -eq 0 ] && check_ok 'Running as root' || check_fail 'Root is required (sudo -i)'
  [ "$(uname -m)" = x86_64 ] && check_ok 'Architecture x86_64 (amd64)' || check_fail "Architecture $(uname -m) is not supported (amd64 only)"
  if [ -r /etc/os-release ]; then id="$(. /etc/os-release; echo "${ID:-}")"; ver="$(. /etc/os-release; echo "${VERSION_ID:-}")"; fi
  case "$variant:$id:$ver" in
    generic:ubuntu:24.04|generic:ubuntu:26.04|generic:ubuntu:26.10|generic:debian:12|zgocloud:ubuntu:24.04|zgocloud:ubuntu:26.04|zgocloud:ubuntu:26.10) check_ok "Supported OS: $id $ver" ;;
    *) check_fail "Unsupported OS for $variant: ${id:-unknown} ${ver:-} (Universal: Ubuntu 24.04/26.04/26.10, Debian 12; ZgoCloud: Ubuntu 24.04/26.04/26.10)" ;;
  esac
  [ -d /run/systemd/system ] && check_ok 'systemd is PID 1' || check_fail 'A running systemd system is required'
  mb="$(free_mb /usr/local)"; [ -n "$mb" ] && [ "$mb" -ge "$MIN_FREE_ROOT_MB" ] && check_ok "Free space for /usr/local and /var: ${mb} MiB" || check_fail "Need ${MIN_FREE_ROOT_MB} MiB free on the root filesystem (have ${mb:-unknown})"
  if [ "$(df -P /var | awk 'NR==2{print $1}')" != "$(df -P /usr/local | awk 'NR==2{print $1}')" ]; then
    mb="$(free_mb /var)"; [ -n "$mb" ] && [ "$mb" -ge 512 ] && check_ok "Free space on /var: ${mb} MiB" || check_fail "Need 512 MiB free on /var (have ${mb:-unknown})"
  fi
  mb="$(free_mb /tmp)"
  if [ -n "$mb" ] && [ "$mb" -ge "$MIN_FREE_TMP_MB" ]; then check_ok "Free space on /tmp: ${mb} MiB"
  else
    check_fail "Need ${MIN_FREE_TMP_MB} MiB free on /tmp (have ${mb:-unknown})"
    stale_installer_workdirs_hint
  fi
  mb="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
  [ "$mb" -ge 450 ] && check_ok "Memory: ${mb} MiB" || check_warn "Low memory (${mb} MiB); 512 MiB or more is recommended"
  if command -v apt-get >/dev/null; then
    check_ok 'apt-get available (packages come from the configured distribution repositories)'
    lock_holder=''
    if command -v fuser >/dev/null; then lock_holder="$(fuser /var/lib/dpkg/lock-frontend 2>/dev/null || true)"; fi
    [ -z "$lock_holder" ] && check_ok 'dpkg lock is free' || check_warn 'dpkg lock is held (e.g. unattended-upgrades); the installer waits up to 10 minutes'
    if ls /etc/apt/sources.list.d/*.sources /etc/apt/sources.list >/dev/null 2>&1 && grep -rhoE 'https?://[^ ]+' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -qiE 'github(usercontent)?\.com'; then
      check_warn 'An apt source on this host points at GitHub; SBOX does not need it'
    fi
  else
    check_fail 'apt-get is required (Debian/Ubuntu)'
  fi
  existing="$(existing_variant || true)"
  case "$action" in
    install)
      if [ -n "$existing" ]; then check_fail "SBOX ($existing) is already installed; use: bash install.sh upgrade"
      elif [ -e /usr/local/bin/sbox ] || [ -e /usr/local/lib/sbox-manager/manager ]; then check_fail 'Incomplete earlier SBOX files found; inspect or run recover first'
      else check_ok 'No existing SBOX installation'; fi
      check_certificate_inputs "$@" ;;
    upgrade|recover|rollback)
      if [ -z "$existing" ]; then check_fail 'No existing SBOX installation (/etc/sbox-manager/state.json)'
      elif [ "$existing" != "$variant" ]; then check_fail "Installed product is $existing; refusing a product switch to $variant"
      else check_ok "Installed product: $existing"; fi ;;
  esac
  if [ "$variant" = zgocloud ]; then
    if [ -n "${SBOX_ZGO_UNLOCK_FILE:-}" ]; then
      if [ -f "$SBOX_ZGO_UNLOCK_FILE" ] && [ ! -L "$SBOX_ZGO_UNLOCK_FILE" ] && [ "$(stat -c '%u %a' "$SBOX_ZGO_UNLOCK_FILE")" = "$(id -u) 600" ]; then
        check_ok 'ZgoCloud unlock file is private (owner-only 0600)'
      else check_fail 'SBOX_ZGO_UNLOCK_FILE must be a regular file owned by you with mode 600'; fi
    elif { : </dev/tty; } 2>/dev/null; then check_ok 'ZgoCloud unlock will be asked on the terminal (no echo)'
    else check_fail 'ZgoCloud needs a terminal or SBOX_ZGO_UNLOCK_FILE'; fi
  fi
  if [ "$FAILS" -eq 0 ]; then say "Preflight passed ($WARNS warning(s))."; return 0; fi
  say "Preflight found $FAILS blocking problem(s); nothing was changed."
  return 1
}

need_variant() {
  case "${1:-}" in generic|zgocloud) printf '%s\n' "$1" ;; universal) echo generic ;; '') existing_variant || fail 'Specify generic or zgocloud.' ;; *) fail "Unknown variant: $1 (use generic or zgocloud)" ;; esac
}

pre_upgrade_backup() {
  command -v sbox >/dev/null || { say 'sbox CLI not found; skipping the automatic backup.'; return 0; }
  local archive
  say 'Creating the automatic pre-upgrade backup (sbox backup)...'
  archive="$(sbox backup | tail -n1)" || fail 'Automatic pre-upgrade backup failed; the upgrade was not started.'
  [ -f "$archive" ] || fail 'Automatic pre-upgrade backup did not produce an archive; the upgrade was not started.'
  install -d -m 0700 "$(dirname "$POINTER")"
  printf '%s\n' "$archive" > "$POINTER.tmp" && chmod 0600 "$POINTER.tmp" && mv -f "$POINTER.tmp" "$POINTER"
  say "Pre-upgrade backup: $archive (restore with: bash rollback.sh)"
}

run_installer() { exec bash "$INSTALLER" "$@"; }

cmd_install() {
  VARIANT="$(need_variant "${1:-}")"; shift || true
  say 'Stage: checking package integrity...'
  verify_package
  say 'Stage: running read-only host preflight checks...'
  preflight install "$VARIANT" "$@" || exit 1
  say 'Stage: verifying embedded application/core, then guided setup (watch for prompts)...'
  run_installer install "$VARIANT" "$@"
}

cmd_upgrade() {
  VARIANT="$(need_variant "${1:-}")"; [ "$#" -le 1 ] || fail 'upgrade takes only an optional variant.'
  verify_package
  preflight upgrade "$VARIANT" || exit 1
  pre_upgrade_backup
  run_installer upgrade "$VARIANT"
}

cmd_recover() {
  VARIANT="$(need_variant "${1:-}")"; [ "$#" -le 1 ] || fail 'recover takes only an optional variant.'
  verify_package
  remove_stale_installer_workdirs
  preflight recover "$VARIANT" || exit 1
  run_installer recover "$VARIANT"
}

cmd_verify() {
  local variant="${1:-generic}"; [ "$#" -le 1 ] || fail 'verify takes only an optional variant.'
  case "$variant" in generic|zgocloud) ;; *) fail 'Variant must be generic or zgocloud.' ;; esac
  verify_package
  bash "$INSTALLER" verify "$variant"
}

cmd_preflight() {
  local variant
  case "${1:-}" in generic|zgocloud|universal) variant="$(need_variant "$1")"; shift ;; *) variant="$(existing_variant || echo generic)" ;; esac
  VARIANT="$variant"
  verify_package
  bash "$INSTALLER" verify generic >/dev/null 2>&1 && say 'Embedded Universal payload verified.' || fail 'Embedded installer payload verification failed.'
  if [ -n "$(existing_variant || true)" ]; then preflight upgrade "$variant"; else preflight install "$variant" "$@"; fi
}

cmd_rollback() {
  local archive='' arg; local -a flags=()
  for arg in "$@"; do
    case "$arg" in --yes|-y|--force) flags+=("$arg") ;; -*) fail "Unknown rollback option: $arg" ;; *) [ -z "$archive" ] || fail 'Usage: bash rollback.sh [BACKUP.tar.gz] [--force]'; archive="$arg" ;; esac
  done
  VARIANT="$(existing_variant)" || fail 'No existing SBOX installation to roll back.'
  if [ -z "$archive" ]; then
    [ -s "$POINTER" ] || fail "No automatic pre-upgrade backup is recorded ($POINTER). Pass a backup from /var/backups/sbox-manager/."
    archive="$(head -n1 "$POINTER")"
  fi
  [ -f "$archive" ] || fail "Backup not found: $archive"
  preflight rollback "$VARIANT" || exit 1
  say "Restoring $archive with 'sbox restore' (authenticated backups from this host restore configuration, users, quotas, certificates and their core)."
  exec sbox restore "$archive" "${flags[@]}"
}

cmd_uninstall() {
  local arg
  for arg in "$@"; do case "$arg" in --yes|-y|--force) ;; *) fail 'Usage: bash uninstall.sh [--force]' ;; esac; done
  command -v sbox >/dev/null || fail 'sbox CLI not found; nothing to uninstall.'
  exec sbox uninstall "$@"
}

menu() {
  { : </dev/tty; } 2>/dev/null || fail 'No interactive terminal. Use: bash install.sh help'
  local choice installed
  installed="$(existing_variant || true)"
  printf '\nSING-BOX %s\n' "$(version)" >&2
  [ -z "$installed" ] || printf 'Installed product: %s\n' "$installed" >&2
  printf '1) Install Universal SBOX (fresh VPS)\n2) Install ZgoCloud (fresh VPS)\n3) Upgrade installed product (automatic backup)\n4) Recover an interrupted change\n5) Roll back to the pre-upgrade backup\n6) Verify package (read-only)\n7) Preflight / dry run (read-only)\n0) Exit\n' >&2
  read -r -p 'Select [0-7]: ' choice </dev/tty || fail 'Input ended.'
  case "$choice" in
    1) cmd_install generic ;; 2) cmd_install zgocloud ;; 3) cmd_upgrade ;; 4) cmd_recover ;; 5) cmd_rollback ;;
    6) cmd_verify "${installed:-generic}" ;; 7) cmd_preflight ;; 0) exit 0 ;; *) fail 'Invalid selection.' ;;
  esac
}

main() {
  local command="${1:-}"
  [ "$#" -eq 0 ] || shift
  case "$command" in
    '') menu ;;
    install) cmd_install "$@" ;;
    upgrade) cmd_upgrade "$@" ;;
    recover) cmd_recover "$@" ;;
    rollback) cmd_rollback "$@" ;;
    verify) cmd_verify "$@" ;;
    preflight|dry-run|--dry-run) cmd_preflight "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    help|-h|--help) usage ;;
    *) usage >&2; fail "Unknown command: $command" ;;
  esac
}

main "$@"
