#!/usr/bin/env bash
# Managed by sbox-manager
# sbox - adaptive client policy with reboot-safe sing-box management
# Client policy: Anti-Block Auto fallback is the fresh default; Smart Auto and LOCK are optional
# Validation: isolated Ubuntu VM/core/client evidence retained; target VPS/phone paths require operator checks
# Protocols: VLESS REALITY, VMess-WS, Hysteria2, TUIC-v5, AnyTLS
# Target: Debian/Ubuntu with systemd

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
IFS=$'\n\t'
umask 077

MANAGER_VERSION="1.11.0"
MANAGER_BUILD_ID="b-f39ac9ca5c6751e9992eaae9"
STATE_SCHEMA=2
# These are functional compatibility/recovery values, not manager build names.
# Operators may override them with real x.y.z versions through the environment.
MIN_SINGBOX_VERSION="${SBOX_MIN_SINGBOX_VERSION:-1.12.0}"

BASE_DIR="/etc/sbox-manager"
STATE_FILE="$BASE_DIR/state.json"
CONFIG_FILE="$BASE_DIR/config.json"
CERT_DIR="$BASE_DIR/certs"
# The service reads the certificate PAIR through an atomically-swapped symlink
# directory ($CERT_DIR/live -> store/<generation>). Publishing a new pair is a
# single rename of that symlink, so the live fullchain+privkey can never be seen
# half-updated (AUD-01). These are the stable paths the sing-box config uses.
CERT_LIVE_DIR="$CERT_DIR/live"
CERT_STORE_DIR="$CERT_DIR/store"
SERVICE_CERT="$CERT_LIVE_DIR/fullchain.pem"
SERVICE_KEY="$CERT_LIVE_DIR/privkey.pem"
EXPORT_DIR="$BASE_DIR/exports"
CERT_SOURCE_DIR="$BASE_DIR/cert-source"
RUNTIME_DIR="/run/sbox-manager"
LOCK_FILE="$RUNTIME_DIR/manager.lock"
SESSION_LOCK_FILE="$RUNTIME_DIR/session.lock"
STATE_HELPER="$RUNTIME_DIR/sbox-state"
POLICY_HELPER="$RUNTIME_DIR/sbox-policy"
EXEC_WORK_DIR="${SBOX_EXEC_WORK_DIR:-/var/tmp/sbox-manager}"
EXEC_WORK_FALLBACK="/usr/local/lib/sbox-manager-staging"
LOCK_WAIT_SECONDS="${SBOX_LOCK_WAIT_SECONDS:-600}"
ASSUME_DEFAULTS="${SBOX_ASSUME_DEFAULTS:-false}"
ASSUME_FORCE=false
OPT_region=''; OPT_domain=''; OPT_node=''; OPT_email=''; OPT_cert=''; OPT_cf_token_file=''
OPT_propagation=''; OPT_cert_path=''; OPT_key_path=''; OPT_core=''; OPT_core_sha256=''; OPT_listen=''; OPT_family=''; OPT_scope=''; OPT_endpoint_override_file=''
OPT_ipv4=''; OPT_ipv6=''; OPT_protocols=''; OPT_ports=''; OPT_hy2_range=''
OPT_firewall=''; OPT_tuning=''; OPT_block_private=''
OPT_reality_fallback=''; OPT_reality_fallback_port=''
DOCTOR_JSON=false
DOCTOR_CHECKS=()
LIB_DIR="/usr/local/lib/sbox-manager"
SBOX_BIN="$LIB_DIR/sing-box"
MANAGER_BIN="$LIB_DIR/manager"
CLI_BIN="/usr/local/bin/sbox"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
FALLBACK_WEB_UNIT="sbox-fallback-web.service"
FALLBACK_WEB_SERVICE_FILE="/etc/systemd/system/$FALLBACK_WEB_UNIT"
FALLBACK_WEB_DIR="$LIB_DIR/fallback-web"
FALLBACK_WEB_FAILURE="/var/lib/sbox-manager/fallback-web-last-failure.json"
FALLBACK_WEB_DEFAULT_PORT=8443
FALLBACK_WEB_BUNDLE_SHA256="@@FALLBACK_WEB_SHA256@@"
CERT_TRUSTED_ONLY=false
FIREWALL_SERVICE_FILE="/etc/systemd/system/sbox-manager-firewall.service"
OLD_WATCHDOG_SERVICE="/etc/systemd/system/sbox-manager-watchdog.service"
OLD_WATCHDOG_TIMER="/etc/systemd/system/sbox-manager-watchdog.timer"
CERT_HOOK_FILE="/etc/letsencrypt/renewal-hooks/deploy/sbox-manager"
CERTBOT_CREDENTIALS_DIR="/etc/letsencrypt/credentials"
LE_LIVE_DIR="/etc/letsencrypt/live"
LE_ARCHIVE_DIR="/etc/letsencrypt/archive"
LE_RENEWAL_DIR="/etc/letsencrypt/renewal"
SYSCTL_FILE="/etc/sysctl.d/99-sbox-manager.conf"
BACKUP_DIR="/var/backups/sbox-manager"
# Pristine runtime sysctl values captured once, before sbox first applies any
# tuning, kept outside BASE_DIR/LIB_DIR so a rollback that wipes those can still
# revert the live kernel parameters. Removed only on uninstall.
SYSCTL_BASELINE_FILE="/var/lib/sbox-manager/sysctl-baseline.conf"
MANAGED_SYSCTLS=(
  net.core.default_qdisc net.ipv4.tcp_congestion_control
  net.core.rmem_max net.core.wmem_max net.core.somaxconn net.core.netdev_max_backlog
  net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min
)
OWNERSHIP_FILE="$BASE_DIR/ownership.json"
# Per-install secret used to authenticate that a backup archive was produced by
# THIS installation. It never leaves the host and is not placed in backups, so a
# backup crafted or captured elsewhere cannot forge the marker.
BACKUP_KEY_FILE="/var/lib/sbox-manager/backup-key"
# Durable record of an in-flight full transaction, kept on persistent storage
# (not tmpfs) so an interrupted commit (SIGKILL, OOM, power loss) is detected and
# recoverable after a reboot. Points at a persistent pre-commit snapshot.
TXN_JOURNAL="/var/lib/sbox-manager/transaction.json"
TXN_SNAPSHOT_DIR="$BACKUP_DIR/.transactions"
SERVICE_USER="sboxmgr"
SERVICE_GROUP="sboxmgr"

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

log()  { printf '%b[%s] %s%b\n' "$CYAN" "$(date -Is)" "$*" "$RESET" >&2; }
ok()   { printf '%b[OK] %s%b\n' "$GREEN" "$*" "$RESET" >&2; }
warn() { printf '%b[WARN] %s%b\n' "$YELLOW" "$*" "$RESET" >&2; }
die()  { printf '%b[ERROR] %s%b\n' "$RED" "$*" "$RESET" >&2; exit 1; }

usage() {
  cat <<'HELP'
sbox - adaptive sing-box manager

Usage:
  sbox [command] [arguments]

Commands:
  menu                         Interactive menu
  install [global|cn]          Fresh install or guided reinstall
  configure                    Change node/domain/listen/security settings
  ports                        Change protocol ports and Hysteria2 hop range
  protocols                    Enable or disable protocols
  rotate [all|PROTOCOL]        Rotate credentials (reality/vmess/hy2/tuic/anytls)
  reality-fallback status|check|remote|self-hosted
                               Show, verify or switch the REALITY handshake
                               target (remote website or self-hosted SBOX
                               Personal Cloud on 127.0.0.1; Universal only)
  certificate                  Replace the certificate source
  region <global|cn>           Change the default client routing profile (mihomo.yaml)
  update [latest|stable|beta|VERSION|PATH] [--sha256 HEX]
                               Resolve and test an accounting-compatible core from
                               verified official Go sources, use the bundled core,
                               or import a local binary verified by SHA-256.
  upgrade-policy               Upgrade manager, helpers and client exports only; no core/service restart
  network show|preview FILE|apply FILE  Explicit network migration preview/backup/restart
  client-policy show           Show Anti-Block Auto/Smart Auto/LOCK client policy
  client-policy apply          Rebuild client policy and helpers only; same as upgrade-policy
  client-policy primary NAME   Set enabled transport priority; no service restart
  client-policy rollback DIR   Restore a policy snapshot; refuses server/core drift
  regenerate                   Rebuild config, YAML, links, units and firewall
  repair                       Alias of regenerate
  webui install|upgrade|start|stop|status|doctor|reset-admin|rollback|uninstall
  upgrade-features --confirm-core-restart  Install verified user accounting
  accounting doctor|backup|reconcile|recover --confirm
  quota show|set|topup|reset|pause|resume|bulk|policy [options]
  portal account|disable USER_ID [--username NAME --password-stdin]
  backup retention [--keep-backups N --keep-policies N --prune]  Dry run unless --prune
  performance tfo|dns-cache|vmess-mux on|off|status  State-driven opt-in controls
  performance report [--json]  Read-only performance/counter inventory
  performance apply baseline|legacy  Reversible host tuning; no service restart
  security setup|repair|status|bans|unban IP  Owned SSH Fail2Ban + early nft guard
  client-policy probes active-only|continuous  Opt-in unused Smart Auto probe reduction
  client-policy probe-url URL [200|204|200/204]  HTTPS HEAD probe (redirects rejected)
  client-policy tolerance MS   Smart Auto switching tolerance10..300ms
  client-policy default smart|anti-block  Group the 🚀 VPN selector starts on
  client-policy health S MS N  Health-check interval30..600s, probe timeout1000..10000ms, failed connections1..5
  doctor --network [--target HTTPS] [--peer HOST:PORT]  Optional bounded timing diagnostics
  status                       Show concise runtime status
  doctor                       Validate files, listeners, certificate and service health
  restart                      Validate and restart sing-box
  recover                      Roll back an interrupted transaction (after a crash/power loss)
  firewall ports [text|json]   Show required provider/security-group ports
  firewall apply               Reapply local allow/NAT rules
  firewall status              Check manager-owned firewall rules
  firewall default-drop on|off Trial default-drop inbound gate (5-minute automatic rollback)
  firewall confirm             Keep the default-drop gate after testing a new SSH login
  links [text|qr]              Print client links or terminal QR codes
  qr                           Alias of "links qr"
  client-files                 Show GLOBAL/CN/INTERNAL file locations
  logs [LINES|follow]          Show service journal
  backup                       Create a root-only manager backup
  restore <archive.tar.gz> [--core SRC [--sha256 HEX]]
                               Restore from a backup (--core supplies a trusted local core for DR)
  renew-test                   Run certbot renewal dry-run when applicable
  uninstall                    Remove sbox runtime; keep backups and LE lineages
  version                      Print manager version
  help                         Show this help

Options (any command):
  --yes, -y, --non-interactive   Accept every prompt default; no terminal needed
  --force                        Answer Yes to confirmations (dangerous; scripted teardown)
  --json                         Machine-readable output (status, doctor)

Options (install):
  --region global|cn             Default client routing profile
  --core pinned|VERSION|PATH     sing-box source: the verified pinned core (default)
                                 or a local binary/archive (--binary is an alias)
  --core-sha256 HEX              Required SHA-256 of a local --core file when unattended
  --domain NAME --node NAME      Client domain and node name
  --email ADDR|none              ACME account email
  --cert reuse|certbot-dns-cloudflare|certbot-http01|existing|self-signed
  --cf-token-file PATH           Cloudflare API token file
  --propagation SECONDS          DNS-01 propagation wait (10-3600)
  --cert-path PATH --key-path P  External key pair for --cert existing
  --ipv4 ADDR|none --ipv6 ADDR|none --listen 0.0.0.0|::|IPv6 --family preserve|ipv4|dual|ipv6
  --scope public|internal       Explicit private/local deployment context (new installs default public)
  --endpoint-override-file PATH Root-owned0600 explanation for transitional/advanced DNS mapping
  --protocols LIST               e.g. reality,vmess,hy2,tuic,anytls
  --ports LIST                   e.g. reality=443,vmess=8443
  --hy2-range START:END|none     Hysteria2 UDP port hopping
  --firewall yes|no --tuning yes|no --block-private yes|no
  --reality-fallback remote|self-hosted
                                 REALITY handshake target: a remote website
                                 (default) or the self-hosted SBOX Personal
                                 Cloud website on 127.0.0.1 (Universal only;
                                 needs a trusted certificate for --domain)
  --reality-fallback-port PORT   Loopback port of that website (default 8443)

Environment:
  SBOX_LOCK_WAIT_SECONDS         Seconds to wait for the manager lock (default 600)
  SBOX_EXEC_WORK_DIR             Staging directory for core binaries
  SBOX_CF_TOKEN                  Cloudflare API token for unattended DNS-01
  SBOX_NO_SANDBOX=1              Write sing-box.service without the optional
                                 syscall and address-family hardening
  SBOX_MIN_SINGBOX_VERSION       Minimum accepted core version (default: 1.12.0)
  SBOX_CORE_SHA256               SHA-256 of a local core file (same as --sha256)

Examples:
  sudo bash ./install.sh install global
  sudo sbox status
  sudo sbox links qr
  sudo sbox doctor
  sudo bash ./install.sh install global --yes --domain vpn.example.com \
    --core /root/sing-box --cert self-signed --protocols reality,vmess \
    --ports reality=443,vmess=8443
HELP
}

need_root() { [ "${EUID:-$(id -u)}" -eq 0 ] || die "Please run as root."; }
need_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "systemd is required."
  [ -d /run/systemd/system ] || die "This host is not running systemd."
}
check_os() {
  [ -r /etc/os-release ] || die "/etc/os-release is missing."
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in debian|ubuntu) ;; *) die "Supported systems: Debian/Ubuntu. Detected: ${PRETTY_NAME:-unknown}" ;; esac
}

ensure_runtime_dir() {
  # /run is normally tmpfs and is empty after every reboot. Older revisions
  # assumed /run/sbox-manager still existed, which broke _firewall-apply and most CLI
  # commands after boot. Recreate the root-only runtime directory on demand.
  if [ -L "$RUNTIME_DIR" ] || { [ -e "$RUNTIME_DIR" ] && [ ! -d "$RUNTIME_DIR" ]; }; then
    die "Runtime path is not a normal directory: $RUNTIME_DIR"
  fi
  install -d -m 0700 -o root -g root "$RUNTIME_DIR"
  # Some setgid parent filesystems can propagate the setgid bit to new
  # directories despite the requested mode. Normalize it explicitly.
  chown root:root "$RUNTIME_DIR"
  chmod 0700 "$RUNTIME_DIR"
}

python_syntax_ok() {
  local file
  for file in "$@"; do
    python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], "rb").read(), filename=sys.argv[1])' "$file" 2>/dev/null || return 1
  done
}

# --- helper reconciliation -------------------------------------------------
# The state and policy programs are embedded as text and installed as real files
# so they can be syntax-checked, executed and inspected independently of this
# installer. They are reconciled on every use instead of being trusted because a
# file exists: the expected content for *this* manager build is regenerated,
# syntax-checked, hashed and compared with what is installed. Only a byte
# identical regular file is reused; a helper left behind by an older revision
# in the tmpfs runtime directory or in the persistent library, a symlink, or an
# unexpected owner is replaced atomically.
helper_sha256() {
  local file="$1"
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  sha256sum "$file" | awk '{print $1}'
}

# sync_helper <target> <writer-function> <mode>
sync_helper() {
  local target="$1" writer="$2" mode="${3:-0700}"
  local dir expected actual tmp current_mode current_owner
  dir="$(dirname "$target")"
  [ -d "$dir" ] || install -d -m 0700 -o root -g root "$dir" || return 1
  tmp="$(mktemp "$dir/.helper.XXXXXX")" || return 1
  if ! "$writer" > "$tmp"; then
    rm -f -- "$tmp"
    warn "Could not generate helper content for $target."
    return 1
  fi
  if ! python_syntax_ok "$tmp"; then
    rm -f -- "$tmp"
    warn "Generated helper failed Python syntax validation: $target"
    return 1
  fi
  chown root:root "$tmp" || { rm -f -- "$tmp"; return 1; }
  chmod "$mode" "$tmp" || { rm -f -- "$tmp"; return 1; }
  expected="$(sha256sum "$tmp" | awk '{print $1}')"
  if [ -L "$target" ]; then
    warn "Replacing the symlinked helper $target with a regular file."
  elif [ -f "$target" ]; then
    actual="$(sha256sum "$target" | awk '{print $1}')"
    current_mode="$(stat -c '%a' "$target" 2>/dev/null || true)"
    current_owner="$(stat -c '%u:%g' "$target" 2>/dev/null || true)"
    if [ "$actual" = "$expected" ] && [ "$current_mode" = "${mode#0}" ] && [ "$current_owner" = "0:0" ]; then
      rm -f -- "$tmp"
      return 0
    fi
    if [ "$actual" = "$expected" ]; then
      warn "Repairing helper metadata for $target (owner=$current_owner mode=$current_mode; expected root:root ${mode#0})."
    else
      warn "Replacing outdated helper $target (installed ${actual:0:12}, expected ${expected:0:12})."
    fi
  elif [ -e "$target" ]; then
    warn "Replacing the non-regular helper path $target."
    rm -rf -- "$target" || { rm -f -- "$tmp"; return 1; }
  fi
  # -T treats the destination as an exact path instead of following a symlink
  # that happens to point at a directory.
  mv -Tf -- "$tmp" "$target" || { rm -f -- "$tmp"; return 1; }
  return 0
}

ensure_helpers() {
  ensure_runtime_dir
  sync_helper "$STATE_HELPER" write_state_helper 0700 || die "Could not install the state helper ($STATE_HELPER)."
  sync_helper "$POLICY_HELPER" write_policy_helper 0700 || die "Could not install the policy helper ($POLICY_HELPER)."
}

sync_persistent_helpers() {
  ensure_dirs
  sync_helper "$LIB_DIR/sbox-state" write_state_helper 0755 || return 1
  sync_helper "$LIB_DIR/sbox-policy" write_policy_helper 0755 || return 1
}

# doctor predicate: every installed helper must be byte-identical to what this
# manager build embeds, both in the runtime copy and in the persistent copy.
helper_files_current() {
  local tmp expected_state expected_policy pair target expected actual
  tmp="$(mktemp -d "$RUNTIME_DIR/helper-check.XXXXXX")" || return 1
  if ! write_state_helper > "$tmp/sbox-state" || ! write_policy_helper > "$tmp/sbox-policy"; then
    rm -rf -- "$tmp"
    return 1
  fi
  expected_state="$(sha256sum "$tmp/sbox-state" | awk '{print $1}')"
  expected_policy="$(sha256sum "$tmp/sbox-policy" | awk '{print $1}')"
  rm -rf -- "$tmp"
  for pair in "$STATE_HELPER|$expected_state" "$POLICY_HELPER|$expected_policy" \
              "$LIB_DIR/sbox-state|$expected_state" "$LIB_DIR/sbox-policy|$expected_policy"; do
    target="${pair%%|*}"
    expected="${pair##*|}"
    actual="$(helper_sha256 "$target" || true)"
    [ "$actual" = "$expected" ] || return 1
  done
  return 0
}

# doctor predicate: helpers are regular root-owned files that are not writable by
# group or others, so a stale or foreign file cannot masquerade as one of ours.
helper_files_secure() {
  local pair path expected_mode owner mode
  for pair in "$STATE_HELPER|700" "$POLICY_HELPER|700" "$LIB_DIR/sbox-state|755" "$LIB_DIR/sbox-policy|755"; do
    path="${pair%%|*}"; expected_mode="${pair##*|}"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    owner="$(stat -c '%u:%g' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"
    [ "$owner" = "0:0" ] && [ "$mode" = "$expected_mode" ] || return 1
  done
  return 0
}

ensure_dirs() {
  install -d -m 0700 "$EXPORT_DIR" "$CERT_SOURCE_DIR" "$BACKUP_DIR"
  ensure_runtime_dir
  # BASE_DIR, CERT_DIR and LIB_DIR must stay group-traversable once the service
  # group exists: sing-box runs as the unprivileged service user and reads
  # config.json (0640 root:group) and the certificates through these parents.
  # Earlier this reset BASE_DIR to 0700 on every call (backup/restore/uninstall
  # all invoke ensure_dirs), so a plain `sbox backup` silently revoked the
  # service user's access and the next restart/reboot failed with "permission
  # denied". Keep the mode consistent with ensure_service_user instead.
  if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$BASE_DIR" "$CERT_DIR" "$LIB_DIR"
  else
    install -d -m 0700 "$BASE_DIR" "$CERT_DIR" "$LIB_DIR"
  fi
}

positive_integer() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

assume_or_die() {
  [ "$ASSUME_DEFAULTS" = true ] && die "$1"
  return 0
}

opt_set() {
  case "$1" in
    region|domain|node|email|cert|cf_token_file|propagation|cert_path|key_path|core|core_sha256|listen|family|scope|endpoint_override_file|ipv4|ipv6|protocols|ports|hy2_range|firewall|tuning|block_private|reality_fallback|reality_fallback_port) ;;
    *) die "Unknown option: --${1//_/-}" ;;
  esac
  printf -v "OPT_$1" '%s' "$2"
}

opt_port_for() {
  local name="$1" pair
  [ -n "$OPT_ports" ] || return 1
  local IFS=,
  for pair in $OPT_ports; do
    pair="${pair// /}"
    case "$pair" in
      "$name"=*) printf '%s\n' "${pair#*=}"; return 0 ;;
    esac
  done
  return 1
}

opt_yesno() {
  case "${1:-}" in
    yes|true|1|on) printf 'yes\n' ;;
    no|false|0|off) printf 'no\n' ;;
    '') case "$2" in true) printf 'yes\n' ;; *) printf 'no\n' ;; esac ;;
    *) die "Invalid boolean option value: $1 (use yes or no)" ;;
  esac
}

hy2_range_default() {
  case "${OPT_hy2_range:-}" in
    '') printf '%s' "$1" ;;
    none|off|disabled) printf '' ;;
    *) printf '%s' "$OPT_hy2_range" ;;
  esac
}

# Options are read from --flags so that a full install can run unattended:
#   sbox install global --yes --domain vpn.example.com --core /root/sing-box \
#     --cert self-signed --protocols reality,vmess --ports reality=443,vmess=8443
parse_install_options() {
  local key
  while [ "$#" -gt 0 ]; do
    case "$1" in
      global|cn)
        [ -z "$OPT_region" ] || die "Profile given twice."
        OPT_region="$1"
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      --*)
        [ "$#" -ge 2 ] || die "Option $1 requires a value."
        key="${1#--}"; key="${key//-/_}"
        if [ "$key" = binary ]; then key=core; fi
        opt_set "$key" "$2"
        shift
        ;;
      *) die "Unknown install argument: $1" ;;
    esac
    shift
  done
  validate_ports_option
}

exec_work_dir_usable() {
  local dir="$1" probe
  [ -n "$dir" ] || return 1
  [ ! -L "$dir" ] || return 1
  if [ -d "$dir" ] && [ "$(stat -c %u "$dir")" != 0 ]; then return 1; fi
  install -d -m 0700 -o root -g root "$dir" >/dev/null 2>&1 || return 1
  [ -d "$dir" ] && [ -w "$dir" ] || return 1
  probe="$(mktemp "$dir/.exec-test.XXXXXX")" || return 1
  printf '#!/bin/sh\nexit 0\n' > "$probe" || { rm -f -- "$probe"; return 1; }
  chmod 0700 "$probe" || { rm -f -- "$probe"; return 1; }
  if "$probe" >/dev/null 2>&1; then
    rm -f -- "$probe"
    return 0
  fi
  rm -f -- "$probe"
  return 1
}

ensure_exec_work_dir() {
  local requested="$EXEC_WORK_DIR" candidate
  for candidate in "$requested" "$EXEC_WORK_FALLBACK"; do
    [ -n "$candidate" ] || continue
    if exec_work_dir_usable "$candidate"; then
      EXEC_WORK_DIR="$candidate"
      find "$EXEC_WORK_DIR" -mindepth 1 -maxdepth 1 -type d -name 'sbox-*.????????' -mtime +2 -exec rm -rf -- {} + 2>/dev/null || true
      return 0
    fi
    warn "Executable staging directory is unavailable or mounted noexec: $candidate"
  done
  die "No executable staging directory is available. Set SBOX_EXEC_WORK_DIR to a root-owned executable filesystem."
}

exec_mktemp_dir() {
  local label="${1:-work}"
  ensure_exec_work_dir
  mktemp -d "$EXEC_WORK_DIR/sbox-${label}.XXXXXXXX"
}

acquire_lock() {
  [ "${SBOX_LOCK_HELD:-false}" = true ] && return 0
  ensure_runtime_dir
  positive_integer "$LOCK_WAIT_SECONDS" || die "SBOX_LOCK_WAIT_SECONDS must be a positive integer."
  exec 9>"$LOCK_FILE"
  if flock -n -x 9; then SBOX_LOCK_HELD=true; return 0; fi
  log "Another sbox operation holds the manager lock; waiting up to ${LOCK_WAIT_SECONDS}s."
  flock -w "$LOCK_WAIT_SECONDS" -x 9 || die "Timed out waiting for the manager lock; another sbox operation is still running."
  SBOX_LOCK_HELD=true
}

# Interactive commands hold this only for the duration of their own session, and
# fail fast instead of queueing: the manager lock above is what serializes
# state mutation, so a pending transaction (for example the certbot deploy
# hook) must never wait behind an administrator who is still answering prompts.
acquire_session() {
  ensure_runtime_dir
  exec 8>"$SESSION_LOCK_FILE"
  flock -n -x 8 || die "Another sbox session is already running on this host; finish or cancel it first."
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s\n' "$value"
}

ask() {
  local prompt="$1" default="${2:-}" value
  if [ "$ASSUME_DEFAULTS" = true ]; then
    [ -n "$default" ] || die "Non-interactive mode needs a value for: $prompt"
    printf '%s\n' "$default"
    return 0
  fi
  if [ -n "$default" ]; then
    read -r -p "$prompt [$default]: " value || die "Input ended before an answer was given."
    value="$(trim "$value")"
    printf '%s\n' "${value:-$default}"
  else
    while true; do
      read -r -p "$prompt: " value || die "Input ended before a value was provided."
      value="$(trim "$value")"
      [ -n "$value" ] && { printf '%s\n' "$value"; return 0; }
      echo "A value is required." >&2
    done
  fi
}

prompt_choice() {
  local prompt="$1" default="$2" valid="$3" value
  if [ "$ASSUME_DEFAULTS" = true ]; then
    case " $valid " in *" $default "*) printf '%s\n' "$default"; return 0 ;; esac
    die "Non-interactive mode needs a valid value for: $prompt"
  fi
  while true; do
    read -r -p "$prompt [$default]: " value || die "Input ended before an answer was given."
    value="$(trim "$value")"; value="${value:-$default}"
    case " $valid " in *" $value "*) printf '%s\n' "$value"; return 0 ;; esac
    echo "Invalid choice. Valid: ${valid// /, }." >&2
  done
}

# A declined restore changes nothing. Interactively that is the operator's choice (exit 0); with
# --yes it only means the prompt's default (No) was taken, so report failure instead of success.
restore_declined() {
  [ -z "${1:-}" ] || rm -rf -- "$1"
  [ -z "${2:-}" ] || rm -rf -- "$2"
  if [ "$ASSUME_DEFAULTS" = true ]; then
    die "Restore not performed: --yes accepts each prompt's default and 'Restore this backup?' defaults to No. Nothing was changed. Re-run interactively, or use --force to restore without prompts."
  fi
  echo "Cancelled."
}

yes_no() {
  local prompt="$1" default="${2:-yes}" value shown
  case "$default" in y|Y|yes|Yes|YES|true|1) default=yes; shown=Yes ;; *) default=no; shown=No ;; esac
  if [ "$ASSUME_FORCE" = true ]; then
    echo true
    return 0
  fi
  if [ "$ASSUME_DEFAULTS" = true ]; then
    case "$default" in yes) echo true ;; *) echo false ;; esac
    return 0
  fi
  while true; do
    read -r -p "$prompt (Yes/No) [Default: $shown]: " value || die "Input ended before an answer was given."
    value="$(trim "$value")"; value="${value:-$default}"
    case "$value" in y|Y|yes|Yes|YES|true|1) echo true; return 0 ;; n|N|no|No|NO|false|0) echo false; return 0 ;; esac
    echo "Please type Yes or No." >&2
  done
}

atomic_install() {
  local src="$1" dst="$2" mode="${3:-0600}" owner="${4:-root}" group="${5:-root}" dir tmp
  dir="$(dirname "$dst")"
  [ -d "$dir" ] || install -d -m 0755 "$dir" || return 1
  tmp="$(mktemp "$dir/.tmp.$(basename "$dst").XXXXXX")" || return 1
  # Explicit checks are required even when a caller uses if/||, where Bash
  # disables errexit throughout a function. Never fsync the old destination
  # and accidentally report success after a failed install or rename.
  if ! install -m "$mode" -o "$owner" -g "$group" "$src" "$tmp"; then
    rm -f -- "$tmp" || true
    return 1
  fi
  if ! mv -Tf -- "$tmp" "$dst"; then
    rm -f -- "$tmp" || true
    return 1
  fi
  durable_paths "$dst" "$dir" || return 1
}

private_jq() (
  set -Eeuo pipefail
  ensure_runtime_dir
  local temp index=0 name value
  local -a args=()
  temp="$(mktemp -d "$RUNTIME_DIR/jq-private.XXXXXXXX")"
  trap 'rm -rf -- "$temp"' EXIT
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --arg ]; then
      [ "$#" -ge 3 ] || return 2
      name="$2"; value="$3"; index=$((index+1))
      printf '%s' "$value" > "$temp/$index"
      args+=(--rawfile "$name" "$temp/$index")
      shift 3
    else args+=("$1"); shift; fi
  done
  command jq "${args[@]}"
)

apt_run() {
  # apt/dpkg, needrestart, conffile replacement and network waits are bounded.
  timeout --foreground -k 15 600 env DEBIAN_FRONTEND=noninteractive \
    NEEDRESTART_MODE=l APT_LISTCHANGES_FRONTEND=none UCF_FORCE_CONFFOLD=1 apt-get \
    -o DPkg::Lock::Timeout=120 -o Acquire::Retries=2 \
    -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" </dev/null
}

state_exists() { [ -s "$STATE_FILE" ] && jq -e . "$STATE_FILE" >/dev/null 2>&1; }
state_fingerprint() {
  [ -s "$1" ] && sha256sum "$1" | awk '{print $1}' || true
}

state_exists() { [ -s "$STATE_FILE" ] && jq -e . "$STATE_FILE" >/dev/null 2>&1; }
state_fingerprint() {
  [ -s "$1" ] && sha256sum "$1" | awk '{print $1}' || true
}
require_installed() {
  state_exists && [ -x "$SBOX_BIN" ] || die "sbox is not installed. Run: sbox install"
  # Every installed command may need temporary files or the manager lock.
  # Recreate /run/sbox-manager here so status/doctor/firewall/cert hooks keep
  # working after a reboot even before any interactive command has run.
  ensure_runtime_dir
}

version_ge() { dpkg --compare-versions "${1#v}" ge "${2#v}"; }
version_lt() { dpkg --compare-versions "${1#v}" lt "${2#v}"; }
valid_version() { [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; }
# The compatibility floor is always a real x.y.z version. Reject a malformed
# override instead of silently disabling the protection.
core_minimum_ok() {
  valid_version "$MIN_SINGBOX_VERSION" || die "SBOX_MIN_SINGBOX_VERSION must look like x.y.z; got: $MIN_SINGBOX_VERSION"
  version_ge "$1" "$MIN_SINGBOX_VERSION"
}
binary_version() { "$1" version 2>/dev/null | awk '/sing-box version/{print $3; exit}' || true; }
random_hex() { openssl rand -hex "${1:-16}"; }
random_uuid() { command -v uuidgen >/dev/null 2>&1 && uuidgen || cat /proc/sys/kernel/random/uuid; }

validate_domain() {
  local d="${1%.}"
  [ "${#d}" -le 253 ] && [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}
ask_domain() {
  local prompt="$1" default="${2:-}" value
  while true; do
    value="$(ask "$prompt" "$default")"; value="${value%.}"; value="${value,,}"
    validate_domain "$value" && { printf '%s\n' "$value"; return 0; }
    assume_or_die "Invalid domain for non-interactive mode: $value"
    echo "Invalid domain. Example: vpn.example.com" >&2
  done
}

validate_label() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }
ask_label() {
  local prompt="$1" default="$2" value
  while true; do
    value="$(ask "$prompt" "$default")"
    validate_label "$value" && { printf '%s\n' "$value"; return 0; }
    assume_or_die "Invalid node name for non-interactive mode: $value"
    echo "Use 1-64 characters: A-Z a-z 0-9 . _ -" >&2
  done
}

normalize_port() {
  local raw="${1:-}" value
  # A length bound prevents arithmetic overflow; force decimal, never octal.
  [[ "$raw" =~ ^[0-9]{1,16}$ ]] || return 1
  value=$((10#$raw))
  [ "$value" -ge 1 ] && [ "$value" -le 65535 ] && [ "$value" -ne 80 ] || return 1
  printf '%s\n' "$value"
}
validate_port() { normalize_port "${1:-}" >/dev/null; }

validate_ports_option() {
  [ -n "$OPT_ports" ] || return 0
  local raw="${OPT_ports//[[:space:]]/}" pair name value result='' IFS=,
  local -A seen=()
  [[ -n "$raw" && "$raw" != ,* && "$raw" != *, && "$raw" != *,,* ]] || die "Invalid --ports list. Use protocol=port pairs."
  for pair in $raw; do
    [[ "$pair" == *=* ]] || die "Invalid --ports entry: $pair"
    name="${pair%%=*}"; value="${pair#*=}"
    case "$name" in reality|vmess|hy2|tuic|anytls) ;; *) die "Unknown protocol in --ports: $name" ;; esac
    [ -z "${seen[$name]:-}" ] || die "Duplicate protocol in --ports: $name"
    seen[$name]=1
    value="$(normalize_port "$value")" || die "Invalid port for $name (1-65535, excluding reserved 80)."
    result+="${result:+,}$name=$value"
  done
  OPT_ports="$result"
}
port_in_use() {
  local port="$1" proto="$2"
  if [ "$proto" = tcp ]; then
    ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
  else
    ss -H -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
  fi
}
random_free_port() {
  local proto="$1" p blocked used tries=0
  shift
  while [ "$tries" -lt 1000 ]; do
    tries=$((tries+1)); p="$(shuf -i 10000-65535 -n 1)"
    blocked=false
    for used in "$@"; do [ -n "$used" ] && [ "$p" = "$used" ] && blocked=true; done
    [ "$blocked" = true ] && continue
    port_in_use "$p" "$proto" && continue
    printf '%s\n' "$p"; return 0
  done
  die "Could not find a free $proto port."
}
ask_port() {
  local label="$1" proto="$2" current="${3:-}" value used
  shift 3
  if [ "$ASSUME_DEFAULTS" = true ]; then
    if [ -n "$current" ]; then
      current="$(normalize_port "$current")" || die "Invalid $label port for non-interactive mode."
      printf '%s\n' "$current"; return 0
    fi
    random_free_port "$proto" "$@"; return 0
  fi
  while true; do
    if [ -n "$current" ]; then
      read -r -p "$label ${proto^^} port [Enter=keep $current, R=random]: " value || die "Input ended before a port was given."
    else
      read -r -p "$label ${proto^^} port [Enter=random]: " value || die "Input ended before a port was given."
    fi
    value="$(trim "$value")"
    case "$value" in
      '')
        if [ -n "$current" ]; then value="$current"; else random_free_port "$proto" "$@"; return 0; fi
        ;;
      r|R|random|RANDOM) random_free_port "$proto" "$@" "$current"; return 0 ;;
    esac
    value="$(normalize_port "$value")" || { echo "Port must be 1-65535; TCP 80 is reserved for HTTP-01." >&2; continue; }
    for used in "$@"; do [ -n "$used" ] && [ "$value" = "$used" ] && { echo "Port $value is already selected for another ${proto^^} protocol." >&2; continue 2; }; done
    if port_in_use "$value" "$proto"; then
      if [ -n "$current" ] && [ "$value" = "$current" ]; then echo "$value"; return 0; fi
      echo "Port $value/$proto is already in use." >&2; continue
    fi
    echo "$value"; return 0
  done
}

normalize_range() {
  local raw="${1//-/:}" a b
  raw="${raw//[[:space:]]/}"
  [[ "$raw" =~ ^([0-9]{1,5}):([0-9]{1,5})$ ]] || return 1
  a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]}))
  [ "$a" -ge 1 ] && [ "$a" -lt "$b" ] && [ "$b" -le 65535 ] || return 1
  [ $((b-a+1)) -ge 10 ] && [ $((b-a+1)) -le 10000 ] || return 1
  printf '%s:%s\n' "$a" "$b"
}
range_contains() { local a="${1%%:*}" b="${1##*:}" p="$2"; [ "$p" -ge "$a" ] && [ "$p" -le "$b" ]; }
udp_range_conflict() {
  local range="$1" start="${1%%:*}" end="${1##*:}" row endpoint port own_pid="${2:-}"
  while IFS= read -r row; do
    # An already-running verified core may have kernel-assigned outbound UDP
    # sockets in the hopping range. A metadata/core update does not claim them.
    if [[ "$own_pid" =~ ^[1-9][0-9]*$ ]] && [[ "$row" == *"pid=$own_pid,"* ]]; then continue; fi
    endpoint="$(awk '{print $4}' <<< "$row")";port="${endpoint##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    [ "$port" -ge "$start" ] && [ "$port" -le "$end" ] && { echo "$port"; return 0; }
  done < <(ss -H -lnup 2>/dev/null)
  return 1
}

random_udp_range() {
  local main="$1" other="$2" size="${3:-1000}" start end range tries=0
  while [ "$tries" -lt 500 ]; do
    tries=$((tries+1)); start="$(shuf -i 10000-$((65535-size+1)) -n 1)"; end=$((start+size-1)); range="$start:$end"
    range_contains "$range" "$main" && continue
    range_contains "$range" "$other" && continue
    udp_range_conflict "$range" >/dev/null && continue
    printf '%s\n' "$range"; return 0
  done
  die "Could not find a free Hysteria2 UDP range."
}
ask_hy2_range() {
  local main="$1" other="$2" current="${3:-}" choice value range conflict
  # An explicit flag is a request, not a suggestion for a prompt default.
  # Never silently disable an explicitly requested range after a conflict.
  case "${OPT_hy2_range:-}" in
    none|off|disabled) printf ''; return 0 ;;
    '') ;;
    *)
      range="$(normalize_range "$OPT_hy2_range")" || die "Invalid --hy2-range; use start:end (10-10000 ports) or none."
      if range_contains "$range" "$main" || range_contains "$range" "$other"; then
        die "Explicit --hy2-range overlaps a selected UDP main port."
      fi
      conflict="$(udp_range_conflict "$range" || true)"
      [ -z "$conflict" ] || die "Explicit --hy2-range conflicts with UDP listener $conflict."
      printf '%s\n' "$range"; return 0 ;;
  esac
  if [ -n "$current" ]; then
    conflict="$(udp_range_conflict "$current" || true)"
    if range_contains "$current" "$main" || range_contains "$current" "$other" || [ -n "$conflict" ]; then
      warn "Current Hysteria2 range conflicts with a selected main port or a local UDP listener and cannot be kept."
      current=''
    fi
  fi
  echo >&2
  echo "Hysteria2 UDP port hopping:" >&2
  echo "  1) Disabled (recommended unless you specifically need hopping)" >&2
  echo "  2) Random 1000-port range" >&2
  echo "  3) Custom range, e.g. 30000:30999" >&2
  [ -n "$current" ] && echo "  4) Keep current: $current" >&2
  choice="$(prompt_choice 'Select option' "$([ -n "$current" ] && echo 4 || echo 1)" "$([ -n "$current" ] && echo '1 2 3 4' || echo '1 2 3')")"
  case "$choice" in
    1) echo '' ;;
    2) random_udp_range "$main" "$other" 1000 ;;
    3)
      while true; do
        value="$(ask 'UDP range (start:end)' '30000:30999')"
        range="$(normalize_range "$value" 2>/dev/null || true)"
        [ -n "$range" ] || { assume_or_die "Invalid UDP range for non-interactive mode: $value"; echo "Invalid range; it must contain 10-10000 ports." >&2; continue; }
        range_contains "$range" "$main" && { assume_or_die "UDP range includes the Hysteria2 main port."; echo "Range includes the Hysteria2 main port." >&2; continue; }
        range_contains "$range" "$other" && { assume_or_die "UDP range includes the TUIC main port."; echo "Range includes the TUIC main port." >&2; continue; }
        conflict="$(udp_range_conflict "$range" || true)"
        [ -z "$conflict" ] || { assume_or_die "UDP range conflicts with a local UDP listener: $conflict"; echo "UDP port $conflict inside the range is already in use." >&2; continue; }
        echo "$range"; return 0
      done ;;
    4) echo "$current" ;;
  esac
}

BASE_PACKAGES=(
  bash ca-certificates curl jq openssl tar gzip
  iproute2 iptables nftables fail2ban rsyslog python3-systemd python3 python3-yaml python3-h2 qrencode dnsutils
  util-linux procps psmisc coreutils findutils grep sed mawk
  libc-bin dpkg passwd kmod
)
BASE_COMMANDS=(
  bash curl jq openssl python3 awk grep sed find xargs sha256sum
  ss ip iptables ip6tables iptables-restore ip6tables-restore nft fail2ban-client flock tar gzip qrencode dig shuf
  systemctl journalctl dpkg sysctl modprobe getent install readlink mktemp rsyslogd logger timeout
)

base_dependencies_ready() {
  local cmd
  for cmd in "${BASE_COMMANDS[@]}"; do command -v "$cmd" >/dev/null 2>&1 || return 1; done
  python3 -c 'import yaml; import systemd.journal; import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1 || return 1
  [ -s /etc/ssl/certs/ca-certificates.crt ]
}

wait_for_apt() {
  command -v fuser >/dev/null 2>&1 || return 0
  local attempts=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    attempts=$((attempts+1))
    [ "$attempts" -le 200 ] || die "The apt/dpkg lock is still held after 10 minutes; check for a stuck package manager and retry."
    log "Waiting for apt/dpkg lock (attempt $attempts/200)..."; sleep 3
  done
}

retry() {
  local attempt=1 max=4
  until "$@"; do
    [ "$attempt" -ge "$max" ] && return 1
    warn "Command failed; retry $attempt/$max in 4 seconds: $*"
    attempt=$((attempt+1)); sleep 4
  done
}

install_dependencies() {
  base_dependencies_ready && return 0
  command -v apt-get >/dev/null 2>&1 || die "apt-get is required to install dependencies."
  log "Installing required packages (including qrencode)..."
  wait_for_apt
  retry apt_run update
  retry apt_run install -y "${BASE_PACKAGES[@]}"
  base_dependencies_ready || die "Required dependencies are still missing after apt installation."
  if [ ! -e /var/log/auth.log ]; then
    logger -p authpriv.notice -t sbox-manager 'Authentication logging initialized for distribution Fail2Ban defaults.'
    local attempt
    for attempt in {1..10}; do [ -e /var/log/auth.log ] && break; sleep 0.2; done
  fi
}

ensure_certbot() {
  local mode="${1:-http}"
  if command -v certbot >/dev/null 2>&1 && { [ "$mode" != dns ] || certbot plugins 2>/dev/null | grep -q dns-cloudflare; }; then
    return 0
  fi
  wait_for_apt
  retry apt_run update
  if [ "$mode" = dns ]; then
    retry apt_run install -y certbot python3-certbot-dns-cloudflare
  else
    retry apt_run install -y certbot
  fi
  command -v certbot >/dev/null 2>&1 || die "certbot installation failed."
  [ "$mode" != dns ] || certbot plugins 2>/dev/null | grep -q dns-cloudflare || die "Certbot Cloudflare DNS plugin is unavailable."
}

detect_arch() {
  case "$(uname -m)" in
    x86_64) echo amd64 ;; aarch64|arm64) echo arm64 ;; armv7l) echo armv7 ;; i386|i686) echo 386 ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
}

@@CORE_SOURCE@@

# The state and policy programs are materialized as real files so they can be
# syntax-checked, run and inspected independently of this installer.
@@HELPER_STATE@@

state_tool() {
  local action="$1" state="$2" extra="${3:-}"
  ensure_helpers
  python3 "$STATE_HELPER" "$action" "$state" "$extra" "$CERT_DIR" "$MANAGER_VERSION" "$STATE_SCHEMA" "$MIN_SINGBOX_VERSION" "$CONFIG_FILE"
}

# Read-only variant for status/doctor/firewall-ports: runs the state program
# from a throwaway copy under the private runtime dir instead of reconciling
# (and thereby rewriting) the installed runtime/persistent helpers. Diagnostic
# commands must not mutate the managed helper files, otherwise doctor would
# silently repair helper drift before it could report it, and a "read-only"
# status would leave side effects behind.
state_tool_ro() {
  local action="$1" state="$2" extra="${3:-}" tmp rc=0
  ensure_runtime_dir
  tmp="$(mktemp -d "$RUNTIME_DIR/ro.XXXXXX")" || return 1
  if ! write_state_helper > "$tmp/sbox-state"; then rm -rf -- "$tmp"; return 1; fi
  python3 "$tmp/sbox-state" "$action" "$state" "$extra" "$CERT_DIR" "$MANAGER_VERSION" "$STATE_SCHEMA" "$MIN_SINGBOX_VERSION" "$CONFIG_FILE"
  rc=$?
  rm -rf -- "$tmp"
  return "$rc"
}

# Migrate+validate a state into a scratch file for a read-only command, without
# touching the installed helpers.
normalize_state_ro() {
  local source="$1" output="$2"
  state_tool_ro migrate "$source" "$output"
  state_tool_ro validate "$output"
}

normalize_state_to() {
  local source="$1" output="$2"
  state_tool migrate "$source" "$output"
  state_tool validate "$output"
}

# Keep the stored fallback preference pointing at an enabled transport. The
# preference is only ever used to order enabled nodes, so a value left pointing
# at a protocol the operator has since disabled is stale: reconcile it to the
# effective primary (the first enabled protocol in canonical order) so status,
# doctor and the stored state agree. Runs on every mutation via apply_candidate.
reconcile_client_policy() {
  local state="$1" stored effective tmp
  stored="$(jq -r '.client_policy.primary // "tuic"' "$state")"
  effective="$(state_tool effective-primary "$state")"
  [ -n "$effective" ] || return 0
  [ "$stored" = "$effective" ] && return 0
  warn "Fallback priority '$stored' is disabled; reconciling client policy to '$effective'."
  tmp="$(mktemp "$RUNTIME_DIR/reconcile.XXXXXX")"
  jq --arg p "$effective" '.client_policy.primary=$p' "$state" > "$tmp"
  mv -f "$tmp" "$state"
  chmod 0600 "$state"
}

state_needs_certificate() {
  # The self-hosted REALITY website presents this installation's own trusted
  # certificate, so it needs one even when every other TLS protocol is off.
  jq -e '(.protocols.vmess.enabled and .protocols.vmess.tls) or .protocols.hy2.enabled or .protocols.tuic.enabled or .protocols.anytls.enabled or (.protocols.reality.enabled and ((.protocols.reality.fallback.mode // "remote") == "self_hosted"))' "$1" >/dev/null
}

# Firewall rules, listener checks, provider port lists and doctor all derive the
# enabled-protocol table from this one mapping, so the protocol-to-transport
# rule and the enabled filter exist in exactly one place.
enabled_transport_rows() {
  jq -r '.protocols|to_entries[]|select(.value.enabled)|[.key,(if (.key=="hy2" or .key=="tuic") then "udp" else "tcp" end),(.value.port|tostring)]|@tsv' "$1"
}

validate_client_bundle() {
  local dir="$1"
  python3 - \
    "$dir/mihomo.yaml" "$dir/clmi.yaml" \
    "$dir/mihomo-global.yaml" "$dir/mihomo-cn.yaml" "$dir/mihomo-internal.yaml" \
    "$dir/clmi-global.yaml" "$dir/clmi-cn.yaml" "$dir/clmi-internal.yaml" \
    "$dir/internal.yaml" <<'PY'
import sys, yaml
profiles = {}
for path in sys.argv[1:]:
    data = yaml.safe_load(open(path, encoding='utf-8'))
    assert isinstance(data, dict)
    assert isinstance(data.get('proxies'), list) and data['proxies']
    groups = {group['name']: group for group in data.get('proxy-groups', [])}
    assert len(data['proxy-groups']) == len(groups) == 4
    assert set(groups) == {'🚀 VPN', '🛡 Anti-Block Auto', '🧠 Smart Auto', '🔒 LOCK'}
    assert groups['🧠 Smart Auto']['type'] == 'url-test'
    assert type(groups['🧠 Smart Auto']['interval']) is int and 30 <= groups['🧠 Smart Auto']['interval'] <= 600
    assert type(groups['🧠 Smart Auto']['timeout']) is int and 1000 <= groups['🧠 Smart Auto']['timeout'] < groups['🧠 Smart Auto']['interval'] * 1000
    assert type(groups['🧠 Smart Auto']['tolerance']) is int and 10 <= groups['🧠 Smart Auto']['tolerance'] <= 300
    assert type(groups['🧠 Smart Auto']['max-failed-times']) is int and 1 <= groups['🧠 Smart Auto']['max-failed-times'] <= 5
    assert isinstance(groups['🧠 Smart Auto']['lazy'], bool)
    assert str(groups['🧠 Smart Auto']['expected-status']) in {'200','204','200/204'}
    assert groups['🛡 Anti-Block Auto']['type'] == 'fallback'
    for key in ('interval', 'timeout', 'max-failed-times'):
        assert groups['🛡 Anti-Block Auto'][key] == groups['🧠 Smart Auto'][key]
    assert groups['🛡 Anti-Block Auto']['lazy'] is False
    assert groups['🔒 LOCK']['type'] == 'select'
    vpn = groups['🚀 VPN']
    assert vpn['type'] == 'select'
    assert vpn['default-selected'] in ('🛡 Anti-Block Auto', '🧠 Smart Auto')
    assert vpn['proxies'] == ['🛡 Anti-Block Auto', '🧠 Smart Auto', '🔒 LOCK']
    assert groups['🛡 Anti-Block Auto']['expected-status'] == groups['🧠 Smart Auto']['expected-status']
    nodes = {p['name'] for p in data['proxies']}
    ordered = groups['🧠 Smart Auto']['proxies']
    assert len(ordered) == len(nodes) and set(ordered) == nodes
    assert groups['🛡 Anti-Block Auto']['proxies'] == ordered
    assert groups['🔒 LOCK']['proxies'] == ordered
    assert groups['🔒 LOCK']['default-selected'] == ordered[0]
    assert set(groups['🔒 LOCK']) == {'name', 'type', 'default-selected', 'proxies'}
    for group in groups.values():
        assert group['proxies'] and 'DIRECT' not in group['proxies']
        assert all(name in nodes or name in groups for name in group['proxies'])
        assert group.get('disable-udp', False) is False
    assert data['rules'][-1] == 'MATCH,🚀 VPN'
    profiles[path] = data
global_profile = profiles[sys.argv[3]]
cn_profile = profiles[sys.argv[4]]
internal_profile = profiles[sys.argv[5]]
assert 'GEOSITE,CN,DIRECT' not in global_profile['rules']
assert 'GEOIP,CN,DIRECT,no-resolve' not in global_profile['rules']
assert 'GEOSITE,CN,DIRECT' in cn_profile['rules']
assert 'GEOIP,CN,DIRECT,no-resolve' in cn_profile['rules']
assert internal_profile['rules'] == ['MATCH,🚀 VPN']
assert internal_profile == profiles[sys.argv[8]] == profiles[sys.argv[9]]
PY
}

# render_bundle validates the staging directory and doctor validates the live
# export directory; both must apply exactly the same rules, so the checks live
# only in the validate_client_bundle() function above.
render_bundle() {
  local state="$1" out="$2"
  rm -rf -- "$out"
  install -d -m 0700 "$out"
  state_tool validate "$state"
  state_tool render "$state" "$out"
  jq -e . "$out/server.json" >/dev/null
  validate_client_bundle "$out"
}

# Resolve what sing-box actually serves, never infer from a newer pair merely
# existing beside an older configured pair. Refuse mixed/unowned TLS paths.
resolve_service_certificate() {
  local pair
  pair="$(python3 - "$CONFIG_FILE" "$CERT_DIR" <<'PYCERTPATH'
import json, sys
from pathlib import Path
config, root = map(Path, sys.argv[1:])
obj = json.loads(config.read_text())
pairs = {(i.get('tls', {}).get('certificate_path'), i.get('tls', {}).get('key_path'))
         for i in obj.get('inbounds', [])
         if 'certificate_path' in i.get('tls', {}) or 'key_path' in i.get('tls', {})}
allowed = {(str(root/'fullchain.pem'), str(root/'privkey.pem')),
           (str(root/'live/fullchain.pem'), str(root/'live/privkey.pem'))}
if len(pairs) != 1 or not pairs <= allowed:
    raise SystemExit('effective TLS pair is missing, mixed, or outside managed paths')
print('\t'.join(next(iter(pairs))))
PYCERTPATH
  )" || return 1
  IFS=$'\t' read -r EFFECTIVE_CERT EFFECTIVE_KEY <<< "$pair"
  certificate_pair_ok "$EFFECTIVE_CERT" "$EFFECTIVE_KEY"
}

certificate_pair_ok() {
  local cert="$1" key="$2" cert_pub key_pub
  [ -s "$cert" ] && [ -s "$key" ] || return 1
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || return 1
  openssl pkey -in "$key" -passin pass: -noout >/dev/null 2>&1 || return 1
  cert_pub="$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  key_pub="$(openssl pkey -in "$key" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ]
}
cert_matches_domain() {
  local output
  output="$(LC_ALL=C openssl x509 -in "$1" -noout -checkhost "$2" 2>/dev/null)" || return 1
  [[ "$output" == *" does match certificate" ]]
}
cert_valid_now() {
  python3 - "$1" <<'PYCERTTIME'
import ssl,subprocess,sys,time
p=subprocess.run(['openssl','x509','-in',sys.argv[1],'-noout','-startdate','-enddate'],capture_output=True,text=True)
try:
    dates=dict(line.split('=',1) for line in p.stdout.splitlines())
    valid=p.returncode==0 and ssl.cert_time_to_seconds(dates['notBefore']) <= time.time() < ssl.cert_time_to_seconds(dates['notAfter'])
except (KeyError,ValueError):valid=False
raise SystemExit(0 if valid else 1)
PYCERTTIME
}
cert_trusted() {
  local cert="$1" domain="$2"
  cert_valid_now "$cert" && cert_matches_domain "$cert" "$domain" || return 1
  openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
    -purpose sslserver -verify_hostname "$domain" -untrusted "$cert" "$cert" >/dev/null 2>&1
}
cert_valid_week() { openssl x509 -in "$1" -noout -checkend 604800 >/dev/null 2>&1; }
files_same_sha256() {
  local first="$1" second="$2" a b
  [ -s "$first" ] && [ -s "$second" ] || return 1
  a="$(sha256sum "$first" | awk '{print $1}')"
  b="$(sha256sum "$second" | awk '{print $1}')"
  [ -n "$a" ] && [ "$a" = "$b" ]
}

# Publish the cert+key as one crash-consistent PAIR. Both halves are written
# into a fresh generation directory under $CERT_DIR/store, verified together,
# then made live by a SINGLE atomic rename of the $CERT_DIR/live symlink. There
# is no window in which fullchain.pem and privkey.pem on the served paths
# ($CERT_DIR/live/*) belong to different generations: either the old generation
# is live, or the new one is. A failure before the swap leaves the old pair
# fully intact; a crash/SIGKILL/reboot at any point leaves exactly one complete
# generation live. (AUD-01: replaces the previous two-independent-rename scheme.)
copy_service_certificate() {
  local cert="$1" key="$2" gen stamp tmplink prev
  certificate_pair_ok "$cert" "$key" || die "Certificate and private key do not match."
  install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CERT_DIR"
  install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CERT_STORE_DIR"
  stamp="$(date +%Y%m%d-%H%M%S)-$$.$RANDOM"
  gen="$CERT_STORE_DIR/$stamp"
  install -d -m 0750 -o root -g "$SERVICE_GROUP" "$gen"
  if ! install -m 0644 -o root -g "$SERVICE_GROUP" "$cert" "$gen/fullchain.pem" \
     || ! install -m 0640 -o root -g "$SERVICE_GROUP" "$key" "$gen/privkey.pem"; then
    rm -rf -- "$gen"
    die "Could not stage the certificate/key pair; the live certificate was left unchanged."
  fi
  if ! certificate_pair_ok "$gen/fullchain.pem" "$gen/privkey.pem"; then
    rm -rf -- "$gen"
    die "Staged certificate/key pair is inconsistent; the live certificate was left unchanged."
  fi
  durable_paths "$gen/fullchain.pem" "$gen/privkey.pem" "$gen" "$CERT_STORE_DIR"
  prev="$(readlink "$CERT_LIVE_DIR" 2>/dev/null || true)"
  # One atomic rename swaps BOTH halves at once. The target is a relative link so
  # it survives a move of $CERT_DIR.
  tmplink="$CERT_DIR/.live.$$.$RANDOM"
  rm -f -- "$tmplink"
  ln -s "store/$stamp" "$tmplink"
  mv -Tf -- "$tmplink" "$CERT_LIVE_DIR"
  durable_paths "$CERT_DIR"
  certificate_pair_ok "$SERVICE_CERT" "$SERVICE_KEY" || die "Installed certificate/key pair is inconsistent."
  # Retain the immediately previous generation for forensic/rollback value; prune older ones.
  local keep g
  keep="store/$stamp"; [ -n "$prev" ] && keep="$keep
$prev"
  if [ -d "$CERT_STORE_DIR" ]; then
    for g in "$CERT_STORE_DIR"/*; do
      [ -e "$g" ] || continue
      case "$keep" in *"store/$(basename "$g")"*) ;; *) rm -rf -- "$g" ;; esac
    done
  fi
}

# Remove the served certificate pair (no enabled protocol needs TLS). Leaves the
# store/ generations and only drops the live symlink.
clear_service_certificate() {
  rm -f -- "$CERT_LIVE_DIR"
  rm -rf -- "$CERT_STORE_DIR"
  # Legacy layout (pre-AUD-01 installs served regular files directly).
  rm -f -- "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem"
}

acme_email_valid() {
  local value="${1:-}"
  [ "${value,,}" = none ] || [[ "$value" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}
ask_acme_email() {
  local value
  while true; do
    value="$(ask 'ACME email (or none)' "${OPT_email:-none}")"
    acme_email_valid "$value" && { echo "$value"; return 0; }
    assume_or_die "Invalid ACME email for non-interactive mode: $value"
    echo "Invalid email, or type none." >&2
  done
}

default_zone() {
  local domain candidate
  domain="${1%.}"
  candidate="$domain"
  if command -v dig >/dev/null 2>&1; then
    while [[ "$candidate" == *.* ]]; do
      [ -n "$(dig +time=2 +tries=1 +short SOA "$candidate" 2>/dev/null || true)" ] && { echo "$candidate"; return 0; }
      candidate="${candidate#*.}"
    done
  fi
  python3 - "$domain" <<'PY'
import sys
labels=sys.argv[1].split('.')
print('.'.join(labels[1:]) if len(labels)>=3 else sys.argv[1])
PY
}

collect_certificate_plan() {
  local domain="$1" needed="$2" existing_state="${3:-}" output="$4"
  local choice cert key target zone token email propagation credentials current_cert current_key
  if [ "$needed" != true ]; then
    jq -n '{method:"none",certificate:{mode:"none",source_mode:"none",source_fullchain:"",source_key:"",insecure:false}}' > "$output"
    chmod 0600 "$output"
    return 0
  fi

  if [ -n "$OPT_cert" ]; then
    case "$OPT_cert" in
      reuse) choice=0 ;;
      certbot-dns-cloudflare) choice=1 ;;
      certbot-http01) choice=2 ;;
      existing) choice=3 ;;
      self-signed)
        [ "$CERT_TRUSTED_ONLY" != true ] || die "The self-hosted REALITY website needs a publicly trusted certificate for $domain. Use --cert certbot-dns-cloudflare, certbot-http01 or existing, or --reality-fallback remote."
        choice=4 ;;
      none) die "The enabled protocols require a certificate, so --cert none cannot be used." ;;
      *) die "Unknown certificate method: $OPT_cert" ;;
    esac
    if [ "$choice" = 0 ]; then
      [ -s "$existing_state" ] || die "--cert reuse requires an installed state that has a certificate."
      current_cert="$(jq -r '.certificate.source_fullchain // empty' "$existing_state")"
      current_key="$(jq -r '.certificate.source_key // empty' "$existing_state")"
      certificate_pair_ok "$current_cert" "$current_key" && cert_valid_now "$current_cert" && cert_matches_domain "$current_cert" "$domain" || die "The current certificate cannot be reused for $domain."
      if [ "$CERT_TRUSTED_ONLY" = true ]; then
        [ "$(jq -r '.certificate.insecure' "$existing_state")" = false ] && cert_trusted "$current_cert" "$domain" || die "The current certificate is not publicly trusted for $domain, so the self-hosted REALITY website cannot use it."
      fi
      jq -n --argjson cert "$(jq -c '.certificate' "$existing_state")" '{method:"reuse",certificate:$cert}' > "$output"
      chmod 0600 "$output"
      return 0
    fi
  elif [ -s "$existing_state" ]; then
    current_cert="$(jq -r '.certificate.source_fullchain // empty' "$existing_state")"
    current_key="$(jq -r '.certificate.source_key // empty' "$existing_state")"
    if certificate_pair_ok "$current_cert" "$current_key" && cert_valid_now "$current_cert" && cert_matches_domain "$current_cert" "$domain" \
       && { [ "$CERT_TRUSTED_ONLY" != true ] || { [ "$(jq -r '.certificate.insecure' "$existing_state")" = false ] && cert_trusted "$current_cert" "$domain"; }; }; then
      echo >&2
      echo "Certificate:" >&2
      echo "  1) Reuse this installation's own current valid certificate (recommended)" >&2
      echo "  2) Let's Encrypt via Cloudflare DNS-01" >&2
      echo "  3) Let's Encrypt via HTTP-01" >&2
      echo "  4) Existing certificate/key paths" >&2
      if [ "$CERT_TRUSTED_ONLY" = true ]; then
        echo "  0) Go back: use the remote website handshake target instead" >&2
        choice="$(prompt_choice 'Select certificate method' '1' '0 1 2 3 4')"
      else
        echo "  5) Self-signed test certificate" >&2
        choice="$(prompt_choice 'Select certificate method' '1' '1 2 3 4 5')"
      fi
      if [ "$choice" = 0 ]; then
        jq -n '{method:"cancel-self-hosted"}' > "$output"; chmod 0600 "$output"; return 0
      fi
      if [ "$choice" = 1 ]; then
        jq -n --argjson cert "$(jq -c '.certificate' "$existing_state")" '{method:"reuse",certificate:$cert}' > "$output"
        chmod 0600 "$output"
        return 0
      fi
      choice=$((choice-1))
    else
      warn "Current certificate cannot be reused for $domain."
      choice=""
    fi
  fi

  if [ -z "${choice:-}" ]; then
    echo >&2
    echo "Certificate:" >&2
    echo "  1) Let's Encrypt via Cloudflare DNS-01 (recommended; no TCP 80)" >&2
    echo "  2) Let's Encrypt via HTTP-01" >&2
    echo "  3) Existing certificate/key paths" >&2
    if [ "$CERT_TRUSTED_ONLY" = true ]; then
      echo "  0) Go back: use the remote website handshake target instead" >&2
      echo "  (Self-signed certificates are not offered: the self-hosted website must be publicly trusted.)" >&2
      choice="$(prompt_choice 'Select certificate method' '1' '0 1 2 3')"
    else
      echo "  4) Self-signed test certificate" >&2
      choice="$(prompt_choice 'Select certificate method' '1' '1 2 3 4')"
    fi
  fi
  if [ "$choice" = 0 ]; then
    jq -n '{method:"cancel-self-hosted"}' > "$output"; chmod 0600 "$output"; return 0
  fi

  case "$choice" in
    1)
      zone="$(ask_domain 'Cloudflare root zone' "$(default_zone "$domain")")"
      [[ "$domain" = "$zone" || "$domain" = *."$zone" ]] || die "$zone is not a DNS suffix of $domain."
      if [ -n "$OPT_cf_token_file" ]; then
        [ -r "$OPT_cf_token_file" ] || die "Cloudflare token file is not readable: $OPT_cf_token_file"
        token="$(trim "$(head -n 1 "$OPT_cf_token_file")")"
      elif [ -n "${SBOX_CF_TOKEN:-}" ]; then
        token="$(trim "$SBOX_CF_TOKEN")"
      else
        read -r -s -p "Cloudflare API token: " token || die "Input ended before the Cloudflare API token was given."
        echo >&2
        token="$(trim "$token")"
      fi
      [ -n "$token" ] || die "Cloudflare API token is required."
      credentials="${output}.cloudflare.ini"
      printf 'dns_cloudflare_api_token = %s\n' "$token" > "$credentials"
      chmod 0600 "$credentials"
      propagation="$(ask 'DNS propagation wait seconds' "${OPT_propagation:-120}")"
      [[ "$propagation" =~ ^[0-9]+$ ]] && [ "$propagation" -ge 10 ] && [ "$propagation" -le 3600 ] || die "Propagation wait must be 10-3600 seconds."
      email="$(ask_acme_email)"
      jq -n --arg domain "$domain" --arg zone "$zone" --arg credentials "$credentials" --arg email "$email" --argjson propagation "$propagation" \
        --arg cert "$LE_LIVE_DIR/$domain/fullchain.pem" --arg key "$LE_LIVE_DIR/$domain/privkey.pem" \
        '{method:"certbot-dns-cloudflare",domain:$domain,zone:$zone,credentials:$credentials,email:$email,propagation:$propagation,certificate:{mode:"certbot-dns-cloudflare",source_mode:"letsencrypt",source_fullchain:$cert,source_key:$key,insecure:false}}' > "$output"
      ;;
    2)
      email="$(ask_acme_email)"
      jq -n --arg domain "$domain" --arg email "$email" --arg cert "$LE_LIVE_DIR/$domain/fullchain.pem" --arg key "$LE_LIVE_DIR/$domain/privkey.pem" \
        '{method:"certbot-http01",domain:$domain,email:$email,certificate:{mode:"certbot-http01",source_mode:"letsencrypt",source_fullchain:$cert,source_key:$key,insecure:false}}' > "$output"
      ;;
    3)
      while true; do
        cert="$(ask 'Fullchain/certificate path' "${OPT_cert_path:-}")"; key="$(ask 'Private key path' "${OPT_key_path:-}")"
        case "$cert:$key" in /*:/*) ;; *) assume_or_die "Certificate and key paths must be absolute."; echo "Both paths must be absolute." >&2; continue ;; esac
        certificate_pair_ok "$cert" "$key" || { assume_or_die "Certificate/key pair is invalid or mismatched."; echo "Certificate/key pair is invalid or mismatched." >&2; continue; }
        cert_valid_now "$cert" || { assume_or_die "Certificate is expired."; echo "Certificate is expired." >&2; continue; }
        cert_matches_domain "$cert" "$domain" || { assume_or_die "Certificate does not cover $domain."; echo "Certificate does not cover $domain." >&2; continue; }
        if [ "$CERT_TRUSTED_ONLY" = true ] && ! cert_trusted "$cert" "$domain"; then
          assume_or_die "The self-hosted REALITY website needs a publicly trusted certificate chain for $domain."
          echo "This certificate is not publicly trusted for $domain (chain/EKU). The self-hosted website needs a trusted certificate." >&2; continue
        fi
        break
      done
      jq -n --arg cert "$cert" --arg key "$key" '{method:"existing",certificate:{mode:"existing",source_mode:"external",source_fullchain:$cert,source_key:$key,insecure:false}}' > "$output"
      ;;
    4)
      [ "$CERT_TRUSTED_ONLY" != true ] || die "Self-signed certificates cannot be used for the self-hosted REALITY website."
      target="$CERT_SOURCE_DIR/self-signed/$domain/$(date +%Y%m%d-%H%M%S)-$$"
      jq -n --arg domain "$domain" --arg target "$target" --arg cert "$target/fullchain.pem" --arg key "$target/privkey.pem" \
        '{method:"self-signed",domain:$domain,target:$target,certificate:{mode:"self-signed",source_mode:"self",source_fullchain:$cert,source_key:$key,insecure:true}}' > "$output"
      warn "Self-signed mode makes clients skip certificate verification. Use only for testing."
      ;;
    *) die "Invalid certificate selection." ;;
  esac
  chmod 0600 "$output"
}

# procfs reports st_size=0 even when IPv6 addresses are present.
ipv6_available() { [ -r /proc/net/if_inet6 ] && IFS= read -r _ < /proc/net/if_inet6; }

open_http01_rule() {
  SBOX_HTTP01_ADDED4=false; SBOX_HTTP01_ADDED6=false
  if ! iptables -w -C INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT 2>/dev/null; then
    iptables -w -I INPUT 1 -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT || return 1
    SBOX_HTTP01_ADDED4=true
  fi
  if ipv6_available && ! ip6tables -w -C INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT 2>/dev/null; then
    if ! ip6tables -w -I INPUT 1 -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT; then
      close_http01_rule; return 1
    fi
    SBOX_HTTP01_ADDED6=true
  fi
  return 0
}

close_http01_rule() {
  local tool flag failed=0
  for tool in iptables ip6tables; do
    if [ "$tool" = iptables ]; then flag="${SBOX_HTTP01_ADDED4:-false}"; else flag="${SBOX_HTTP01_ADDED6:-false}"; fi
    if [ "$flag" = true ] || [ "${1:-}" = force ]; then
      if "$tool" -w -C INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT 2>/dev/null; then
        "$tool" -w -D INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT || failed=1
      fi
    fi
  done
  return "$failed"
}


certbot_lineage_complete() {
  local domain="$1" cert="$2" key="$3"
  [ -f "$LE_RENEWAL_DIR/$domain.conf" ] || return 1
  [ -d "$LE_ARCHIVE_DIR/$domain" ] || return 1
  [ -e "$LE_LIVE_DIR/$domain/fullchain.pem" ] || return 1
  [ -e "$LE_LIVE_DIR/$domain/privkey.pem" ] || return 1
  certificate_pair_ok "$cert" "$key" || return 1
  cert_matches_domain "$cert" "$domain"
}

certbot_lineage_reusable() {
  local domain="$1" cert="$2" key="$3"
  certbot_lineage_complete "$domain" "$cert" "$key" || return 1
  cert_valid_week "$cert"
}

# Same-host rollback/restore: a saved certbot certificate whose renewable
# lineage is still complete and valid on this host keeps its source, so
# automatic renewal is not silently disconnected. Disaster recovery on another
# host (no lineage) keeps using the static copy from the backup.
restore_keeps_certbot_lineage() {
  local candidate="$1" mode domain cert key
  mode="$(jq -r '.certificate.mode // ""' "$candidate")"
  case "$mode" in certbot-http01|certbot-dns-cloudflare) ;; *) return 1 ;; esac
  [ "$(jq -r '.certificate.source_mode // ""' "$candidate")" = letsencrypt ] || return 1
  domain="$(jq -r '.domain // ""' "$candidate")"
  cert="$(jq -r '.certificate.source_fullchain // ""' "$candidate")"; key="$(jq -r '.certificate.source_key // ""' "$candidate")"
  [ -n "$domain" ] && [ -n "$cert" ] && [ -n "$key" ] || return 1
  certbot_lineage_reusable "$domain" "$cert" "$key" && cert_matches_domain "$cert" "$domain"
}

certbot_lineage_partial() {
  local domain="$1" cert="$2" key="$3"
  if [ -e "$LE_RENEWAL_DIR/$domain.conf" ] || [ -e "$LE_LIVE_DIR/$domain" ] || [ -e "$LE_ARCHIVE_DIR/$domain" ]; then
    certbot_lineage_complete "$domain" "$cert" "$key" || return 0
  fi
  return 1
}

patch_cloudflare_renewal() {
  local domain="$1" credentials="$2" renewal="$LE_RENEWAL_DIR/$1.conf" tmp
  [ -f "$renewal" ] || return 1
  tmp="$(mktemp "$RUNTIME_DIR/renewal.XXXXXX")"
  python3 - "$renewal" "$credentials" "$tmp" <<'PYRENEW'
from pathlib import Path
import re
import sys
source, credentials, output = map(Path, sys.argv[1:4])
text = source.read_text(encoding='utf-8')
line = f'dns_cloudflare_credentials = {credentials}'
pattern = r'(?m)^dns_cloudflare_credentials\s*=.*$'
if re.search(pattern, text):
    text = re.sub(pattern, line, text)
elif re.search(r'(?m)^\[renewalparams\]\s*$', text):
    text = re.sub(r'(?m)^(\[renewalparams\]\s*)$', r'\1\n' + line, text, count=1)
else:
    raise SystemExit('renewalparams section is missing')
output.write_text(text if text.endswith('\n') else text + '\n', encoding='utf-8')
PYRENEW
  atomic_install "$tmp" "$renewal" 0600 root root
  rm -f "$tmp"
}

materialize_certificate_plan() {
  local plan="$1" method domain cert key email propagation credentials stable rc=0
  acquire_lock
  if [ -z "${SBOX_PREPARED_SNAPSHOT:-}" ]; then guard_no_pending_transaction; fi
  if [ -n "${SBOX_PREPARED_SNAPSHOT:-}" ]; then
    local parent_hook
    parent_hook="$(mktemp "$RUNTIME_DIR/parent-hook.XXXXXX")"
    write_cert_hook_content > "$parent_hook"
    install -d -m 0755 "$(dirname "$CERT_HOOK_FILE")"
    atomic_install "$parent_hook" "$CERT_HOOK_FILE" 0755 root root
    rm -f "$parent_hook"
  fi
  method="$(jq -r '.method' "$plan")"
  cert="$(jq -r '.certificate.source_fullchain // empty' "$plan")"
  key="$(jq -r '.certificate.source_key // empty' "$plan")"
  case "$method" in
    none) return 0 ;;
    reuse|existing)
      certificate_pair_ok "$cert" "$key" || die "Selected certificate source is no longer valid."
      cert_valid_now "$cert" || die "Selected certificate is expired."
      ;;
    self-signed)
      domain="$(jq -r '.domain' "$plan")"
      install -d -m 0700 "$(jq -r '.target' "$plan")"
      openssl req -x509 -newkey rsa:3072 -sha256 -days 397 -nodes \
        -keyout "$key" -out "$cert" -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" >/dev/null 2>&1 || die "Self-signed certificate generation failed."
      chmod 0600 "$key"; chmod 0644 "$cert"
      ;;
    certbot-dns-cloudflare)
      ensure_certbot dns
      domain="$(jq -r '.domain' "$plan")"; email="$(jq -r '.email' "$plan")"; propagation="$(jq -r '.propagation' "$plan")"
      credentials="$(jq -r '.credentials' "$plan")"; [ -s "$credentials" ] || die "Temporary Cloudflare credential is missing."
      install -d -m 0700 "$CERTBOT_CREDENTIALS_DIR"
      stable="$CERTBOT_CREDENTIALS_DIR/sbox-manager-${domain}.ini"
      if certbot_lineage_reusable "$domain" "$cert" "$key"; then
        log "Reusing valid Let's Encrypt lineage for $domain."
        # No issuance happens on reuse, so the supplied token is NEVER verified
        # here. Replacing a stored, known-good renewal token with an unverified
        # one would silently break the next unattended renewal (AUD-02). Adopt
        # the supplied credential only when there is no stored one to protect;
        # otherwise keep the existing credential untouched. Token rotation is
        # done through the verified issuance path below (expiring/absent lineage
        # or an explicit renewal), where a real certonly proves the new token
        # before it is promoted.
        if [ ! -s "$stable" ]; then
          atomic_install "$credentials" "$stable" 0600 root root
        elif ! cmp -s "$credentials" "$stable"; then
          warn "A different Cloudflare token was supplied while the certificate is still valid; the new token is unverified, so the existing known-good renewal credential is kept unchanged. To rotate the token, re-run certificate setup when the certificate is near renewal (the new token is then verified by a real issuance before it is stored)."
        fi
      else
        certbot_lineage_partial "$domain" "$cert" "$key" && die "Incomplete Certbot lineage found for $domain. Repair or remove its renewal/live/archive files before retrying."
        # Attempt issuance with the TEMPORARY credential and only promote it to
        # the stable path after success. A failed attempt (e.g. a rejected API
        # token) must never overwrite the credential a previous working lineage
        # still renews with.
        local -a args=(certonly --cert-name "$domain" --dns-cloudflare --dns-cloudflare-credentials "$credentials" --dns-cloudflare-propagation-seconds "$propagation" -d "$domain" --agree-tos --non-interactive)
        [ "$email" = none ] && args+=(--register-unsafely-without-email) || args+=(--email "$email")
        SBOX_CERTBOT_PARENT_TRANSACTION="${SBOX_PREPARED_SNAPSHOT:-}" certbot "${args[@]}" || die "Let's Encrypt Cloudflare DNS-01 issuance failed."
        atomic_install "$credentials" "$stable" 0600 root root
      fi
      patch_cloudflare_renewal "$domain" "$stable" || die "Could not persist the Cloudflare renewal credential path."
      ;;
    certbot-http01)
      ensure_certbot http
      domain="$(jq -r '.domain' "$plan")"; email="$(jq -r '.email' "$plan")"
      if certbot_lineage_reusable "$domain" "$cert" "$key"; then
        log "Reusing valid Let's Encrypt lineage for $domain."
      else
        certbot_lineage_partial "$domain" "$cert" "$key" && die "Incomplete Certbot lineage found for $domain. Repair or remove its renewal/live/archive files before retrying."
        [ -z "$(ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -E '(^|:)80$' || true)" ] || die "TCP 80 is in use; HTTP-01 cannot start."
        open_http01_rule || die "Could not open TCP 80 in the local firewall for HTTP-01."
        local -a args=(certonly --cert-name "$domain" --standalone --preferred-challenges http --http-01-port 80 -d "$domain" --agree-tos --non-interactive)
        [ "$email" = none ] && args+=(--register-unsafely-without-email) || args+=(--email "$email")
        # The temporary TCP/80 accept rule must never outlive certbot, including
        # when the operator (or a supervising process) interrupts issuance. A
        # signal would otherwise kill the manager before the unconditional
        # close below runs, leaving port 80 open in the firewall.
        trap 'close_http01_rule; trap - INT TERM HUP; exit 143' INT TERM HUP
        set +e; SBOX_CERTBOT_PARENT_TRANSACTION="${SBOX_PREPARED_SNAPSHOT:-}" certbot "${args[@]}"; rc=$?; set -e
        trap - INT TERM HUP
        close_http01_rule
        [ "$rc" -eq 0 ] || die "Let's Encrypt HTTP-01 issuance failed."
      fi
      ;;
    *) die "Unknown certificate plan: $method" ;;
  esac
  certificate_pair_ok "$cert" "$key" || die "Materialized certificate/key pair is invalid."
  domain="$(jq -r '.domain // empty' "$plan")"
  [ -z "$domain" ] || cert_matches_domain "$cert" "$domain" || die "Certificate does not cover $domain."
}

merge_plan_certificate() {
  local state="$1" plan="$2" output="$3"
  jq --argjson cert "$(jq -c '.certificate' "$plan")" '.certificate=$cert | .updated_at=(now|todateiso8601)' "$state" > "$output"
  chmod 0600 "$output"
  state_tool validate "$output"
}

detect_public_ipv4() {
  local url value
  for url in https://api.ipify.org https://checkip.amazonaws.com https://4.ipw.cn; do
    value="$(curl -4fsSL --connect-timeout 5 --max-time 10 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    python3 - "$value" <<'PY' >/dev/null 2>&1 && { echo "$value"; return 0; }
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]); assert ip.version==4 and ip.is_global
PY
  done
  return 1
}
detect_public_ipv6() {
  local url value
  for url in https://api64.ipify.org https://ipv6.icanhazip.com https://6.ipw.cn; do
    value="$(curl -6fsSL --connect-timeout 5 --max-time 10 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    python3 - "$value" <<'PY' >/dev/null 2>&1 && { echo "$value"; return 0; }
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]); assert ip.version==6 and ip.is_global
PY
  done
  return 1
}

ask_optional_ip() {
  local label="$1" family="$2" default="${3:-}" value
  while true; do
    value="$(ask "$label address (type none to clear)" "${default:-none}")"
    [ "${value,,}" = none ] && { echo ''; return 0; }
    python3 - "$value" "$family" <<'PY' >/dev/null 2>&1 && { echo "$value"; return 0; }
import ipaddress,sys
assert ipaddress.ip_address(sys.argv[1]).version==int(sys.argv[2])
PY
    assume_or_die "Invalid IPv$family address for non-interactive mode: $value"
    echo "Invalid IPv$family address." >&2
  done
}

choose_region() {
  local current="${1:-global}" default=1 choice
  [ "$current" = cn ] && default=2
  echo >&2
  echo "Default client routing profile:" >&2
  echo "  1) GLOBAL - international routing and DNS (mihomo.yaml = GLOBAL)" >&2
  echo "  2) CN     - mainland-China direct routing and DNS (mihomo.yaml = CN)" >&2
  choice="$(prompt_choice 'Select profile' "$default" '1 2')"
  [ "$choice" = 2 ] && echo cn || echo global
}

choose_listen() {
  # $4 = true when $2 equals the address detect_public_ipv6() found with a
  # successful outbound IPv6 request (1.8.0 D3); a typed address is not proof.
  local current="${1:-0.0.0.0}" ipv6="${2:-}" existing="${3:-false}" probed="${4:-false}" default=1 choice options="1 2 3"
  [ "$current" = '::' ] && default=2
  [[ "$current" = *:* && "$current" != '::' ]] && default=3
  if [ "$existing" != true ] && [ -n "$ipv6" ] && [ "$probed" = true ] && [ "$current" = 0.0.0.0 ]; then default=2; fi
  echo >&2
  echo "Listen mode:" >&2
  echo "  1) IPv4 only (IPv4 listeners, outbound DNS and client dialing)" >&2
  echo "  2) Dual stack (::; automatic address-family fallback)" >&2
  echo "  3) IPv6 only (bind assigned IPv6; IPv4 destinations unavailable without translation)" >&2
  if [ "$existing" = true ]; then
    default=4; options='1 2 3 4'
    echo "  4) Keep current network policy (preserve existing DNS and outbound behavior)" >&2
  fi
  [ -z "$ipv6" ] && echo "  No public IPv6 was detected/saved; IPv4-only is recommended." >&2
  if [ -n "$ipv6" ] && [ "$probed" = true ] && [ "$existing" != true ] && [ "$default" = 2 ]; then
    echo "  Working public IPv6 detected ($ipv6): dual stack is recommended so IPv4 and IPv6 clients can connect." >&2
  fi
  if [ "$existing" = true ] && [ -n "$ipv6" ] && [ "$probed" = true ] && [ "$current" = 0.0.0.0 ]; then
    echo "  Note: listeners are IPv4-only, so IPv6 clients cannot connect. Choose 2 to add IPv6 (current policy is kept unless you choose)." >&2
  fi
  choice="$(prompt_choice 'Select listen mode' "$default" "$options")"
  case "$choice" in
    1) echo '0.0.0.0' ;;
    2) echo '::' ;;
    3) [ -n "$ipv6" ] || die 'IPv6-only mode requires an assigned IPv6 host address.'; echo "$ipv6" ;;
    4) [ "$existing" = true ] || die 'No existing network policy.'; echo preserve ;;
  esac
}

check_domain_dns() {
  local domain="$1" ipv4="$2" ipv6="$3" mode="${4:-preserve}" scope="${5:-public}" override="${6:-}" interface="${7:-}" tmp rc=0
  tmp="$(mktemp -d "$RUNTIME_DIR/endpoint-preflight.XXXXXXXX")"
  jq -n --arg domain "$domain" --arg v4 "$ipv4" --arg v6 "$ipv6" --arg mode "$mode" --arg scope "$scope" --arg override "$override" --arg interface "$interface" \
    '{schema:2,domain:$domain,server:{ipv4:$v4,ipv6:$v6,mode:$mode,scope:$scope,endpoint_override:$override,interface:$interface}}' > "$tmp/input.json"
  echo "Checking required endpoint DNS and local address assignment..." >&2
  state_tool endpoint-preflight "$tmp/input.json" > "$tmp/report.json" || rc=$?
  if [ -s "$tmp/report.json" ]; then
    jq -r '(.errors[]? | "Endpoint ERROR: "+.),(.warnings[]? | "Endpoint warning: "+.),("Reachability: "+.firewall)' "$tmp/report.json" >&2
  fi
  rm -rf -- "$tmp"
  [ "$rc" -eq 0 ] || die 'Endpoint preflight failed. Correct saved addresses/DNS/assignment, or configure an explicit documented advanced override.'
}

select_protocols() {
  local existing="${1:-}" result='{}' name label default enabled count=0
  if [ -n "$OPT_protocols" ]; then
    local item IFS=,
    for item in $OPT_protocols; do
      case "${item// /}" in
        reality|vmess|hy2|tuic|anytls) ;;
        *) die "Unknown protocol in --protocols: $item" ;;
      esac
    done
    for name in reality vmess hy2 tuic anytls; do
      case ",${OPT_protocols// /}," in
        *",$name,"*) enabled=true; count=$((count+1)) ;;
        *) enabled=false ;;
      esac
      result="$(jq --arg n "$name" --argjson value "$enabled" '. + {($n):$value}' <<< "$result")"
    done
    [ "$count" -gt 0 ] || die "--protocols must enable at least one protocol."
    echo "$result"
    return 0
  fi
  echo >&2
  echo "Protocols (press Enter to keep the shown default):" >&2
  for name in reality vmess hy2 tuic anytls; do
    case "$name" in reality) label='VLESS REALITY' ;; vmess) label='VMess-WS' ;; hy2) label='Hysteria2' ;; tuic) label='TUIC-v5' ;; anytls) label='AnyTLS' ;; esac
    default=yes
    [ -s "$existing" ] && [ "$(jq -r --arg n "$name" '.protocols[$n].enabled' "$existing")" != true ] && default=no
    enabled="$(yes_no "Enable $label?" "$default")"
    result="$(jq --arg n "$name" --argjson value "$enabled" '. + {($n):$value}' <<< "$result")"
    [ "$enabled" = true ] && count=$((count+1))
  done
  [ "$count" -gt 0 ] || die "At least one protocol must be enabled."
  echo "$result"
}

generate_reality_keypair() {
  local binary="$1" output private public
  output="$("$binary" generate reality-keypair)"
  private="$(printf '%s\n' "$output" | awk -F': *' '/PrivateKey/{print $2; exit}')"
  public="$(printf '%s\n' "$output" | awk -F': *' '/PublicKey/{print $2; exit}')"
  [ -n "$private" ] && [ -n "$public" ] || die "Could not parse sing-box REALITY keypair output."
  printf '%s\t%s\n' "$private" "$public"
}

choose_reality_sni() {
  local current="${1:-www.cloudflare.com}" choice default=1
  case "$current" in www.cloudflare.com) default=1 ;; www.microsoft.com) default=2 ;; www.apple.com) default=3 ;; *) default=4 ;; esac
  echo >&2
  echo "Remote website used as the REALITY handshake target (SNI):" >&2
  echo "  1) www.cloudflare.com" >&2
  echo "  2) www.microsoft.com" >&2
  echo "  3) www.apple.com" >&2
  echo "  4) Custom" >&2
  choice="$(prompt_choice 'Select SNI' "$default" '1 2 3 4')"
  case "$choice" in 1) echo www.cloudflare.com ;; 2) echo www.microsoft.com ;; 3) echo www.apple.com ;; 4) ask_domain 'Custom REALITY SNI' "$current" ;; esac
}

# ---------------------------------------------------------------------------
# REALITY handshake target (Universal only)
#
# remote      : the original behaviour. Non-REALITY TLS is relayed to a remote
#               website (handshake.server = SNI, port dest_port). SBOX never
#               obtains, copies or stores that website's certificate or key.
# self_hosted : non-REALITY TLS is relayed to the local SBOX Personal Cloud
#               website on a loopback-only listener, which presents this
#               installation's own trusted certificate for the SBOX domain.
# An absent .protocols.reality.fallback object means "remote", so existing
# states, configs and client profiles are unchanged.
# ---------------------------------------------------------------------------
reality_fallback_active() {
  jq -e '.protocols.reality.enabled == true and ((.protocols.reality.fallback.mode // "remote") == "self_hosted")' "$1" >/dev/null 2>&1
}

reality_fallback_explain() {
  cat >&2 <<'EXPLAIN'

REALITY handshake target (what an ordinary browser or probe sees on the REALITY port):
  1) Remote website handshake target (default, current behaviour)
     Ordinary TLS is relayed to a well-known remote website you choose.
     SBOX does not obtain, copy or store that website's certificate or key.
  2) Self-hosted SBOX Personal Cloud website on this VPS
     Ordinary TLS is relayed to a small read-only Personal Cloud website that
     runs on 127.0.0.1 only and presents YOUR trusted certificate for YOUR
     domain. Requires DNS for the domain to point here and a publicly trusted
     certificate (Let's Encrypt DNS-01/HTTP-01 or your own certificate/key).
     No new public port is opened; the SBOX admin panel is not exposed.
EXPLAIN
}

# The running Personal Cloud service may already own its port (reconfigure).
fallback_web_port_owned() {
  local port="$1" pid line
  pid="$(systemctl show -p MainPID --value "$FALLBACK_WEB_UNIT" 2>/dev/null || echo 0)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  line="$(ss -H -lntp 2>/dev/null | awk -v p="$port" '$4 ~ ("(^|:)" p "$")')"
  [ -n "$line" ] && printf '%s\n' "$line" | grep -q "pid=${pid},"
}

# Prints a reason and returns 1 when the local website port cannot be used.
validate_fallback_port() {
  local port="$1" used
  shift
  if ! [[ "$port" =~ ^[0-9]{1,5}$ ]] || [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ] || [ "$port" -eq 9443 ]; then
    echo "Use a local port from 1024 to 65535 (9443 is reserved for the SBOX WebUI)."; return 1
  fi
  for used in "$@"; do
    [ -n "$used" ] && [ "$port" = "$used" ] && { echo "Port $port is already selected for an enabled VPN protocol."; return 1; }
  done
  if port_in_use "$port" tcp && ! fallback_web_port_owned "$port"; then
    echo "Port $port/tcp is already in use by another program."; return 1
  fi
  return 0
}

ask_fallback_port() {
  local current="$1" value reason
  shift
  while true; do
    if [ "$ASSUME_DEFAULTS" = true ]; then
      value="$current"
    else
      read -r -p "Local Personal Cloud HTTPS port on 127.0.0.1 [Enter=keep $current]: " value || die "Input ended before a port was given."
      value="$(trim "$value")"; value="${value:-$current}"
    fi
    if reason="$(validate_fallback_port "$value" "$@")"; then printf '%s\n' "$value"; return 0; fi
    assume_or_die "Self-hosted REALITY website: $reason"
    echo "$reason" >&2
  done
}

# choose_reality_fallback CURRENT_FALLBACK_JSON DOMAIN REMOTE_SNI [TAKEN_TCP_PORT...]
# Prints the new fallback object as compact JSON.
choose_reality_fallback() {
  local current="${1:-}" domain="$2" remote_sni="$3" mode choice default port
  shift 3
  [ -n "$current" ] || current='{}'
  mode="$(jq -r '.mode // "remote"' <<< "$current")"
  case "${OPT_reality_fallback:-}" in
    '') ;;
    remote) mode=remote ;;
    self-hosted|self_hosted|selfhosted) mode=self_hosted ;;
    *) die "--reality-fallback must be remote or self-hosted." ;;
  esac
  default=1; [ "$mode" = self_hosted ] && default=2
  reality_fallback_explain
  choice="$(prompt_choice 'Select REALITY handshake target' "$default" '1 2')"
  if [ "$choice" = 1 ]; then jq -nc '{mode:"remote"}'; return 0; fi
  port="${OPT_reality_fallback_port:-$(jq -r '.port // empty' <<< "$current")}"
  port="$(ask_fallback_port "${port:-$FALLBACK_WEB_DEFAULT_PORT}" "$@")"
  echo "  The Personal Cloud website will answer as https://$domain (port 443 of REALITY if REALITY uses 443)." >&2
  jq -nc --arg host "$domain" --argjson port "$port" --arg remote "$remote_sni" \
    '{mode:"self_hosted",hostname:$host,listen:"127.0.0.1",port:$port,remote_sni:$remote}'
}

# Collect the certificate plan for a candidate state. When the candidate uses
# the self-hosted website the plan must be publicly trusted; the operator may
# instead go back to the remote target, which rewrites the candidate.
collect_state_certificate_plan() {
  local candidate="$1" domain="$2" existing="${3:-}" plan="$4" needed tmp
  while true; do
    needed=false; state_needs_certificate "$candidate" && needed=true
    CERT_TRUSTED_ONLY=false; reality_fallback_active "$candidate" && CERT_TRUSTED_ONLY=true
    collect_certificate_plan "$domain" "$needed" "$existing" "$plan"
    [ "$(jq -r '.method' "$plan")" = cancel-self-hosted ] || { CERT_TRUSTED_ONLY=false; return 0; }
    tmp="$candidate.remote"
    jq '.protocols.reality.sni=.protocols.reality.fallback.remote_sni | del(.protocols.reality.fallback)' "$candidate" > "$tmp"
    mv -f "$tmp" "$candidate"; chmod 0600 "$candidate"
    warn "Self-hosted website cancelled. REALITY keeps the remote website handshake target $(jq -r '.protocols.reality.sni' "$candidate")."
  done
}

# The site and server are embedded in this manager (see tools/build.py).
fallback_web_bundle() {
  cat <<'SBOX_FALLBACK_WEB_BUNDLE'
@@FALLBACK_WEB_BUNDLE@@
SBOX_FALLBACK_WEB_BUNDLE
}

FALLBACK_WEB_REQUIRED=(server.py site/index.html site/files/index.html site/media/index.html site/about/index.html)

# fallback_web_tree_check DIR -- prints one problem per line and returns 1 when
# the installed tree is not exactly what the unprivileged sandboxed service can
# read: root-owned, no symlinks, directories 0755, files 0644, every required
# page present and non-empty. Modes are checked directly (not by trying to read
# as "nobody"): the service sees DIR through its own bind mount, so the 0750
# $LIB_DIR above it is intentionally not traversable by other users.
fallback_web_tree_check() {
  python3 -I -B - "$1" "${FALLBACK_WEB_REQUIRED[@]}" <<'PYFALLBACKTREE'
import os,stat,sys
root,required=sys.argv[1],sys.argv[2:]
problems=[]
def mode(st):return '%04o'%stat.S_IMODE(st.st_mode)
try:
    top=os.lstat(root)
except OSError as e:
    print('%s: %s'%(root,e.strerror));sys.exit(1)
if not stat.S_ISDIR(top.st_mode):problems.append(root+': not a directory')
for base,dirs,files in os.walk(root,followlinks=False):
    for name in [base]+[os.path.join(base,x) for x in dirs+files]:
        st=os.lstat(name);rel=os.path.relpath(name,root)
        if stat.S_ISLNK(st.st_mode):problems.append(rel+': symlink is not allowed');continue
        if st.st_uid!=0 or st.st_gid!=0:problems.append(rel+': owner %d:%d, expected root:root'%(st.st_uid,st.st_gid))
        want='0755' if stat.S_ISDIR(st.st_mode) else '0644'
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):problems.append(rel+': not a regular file or directory')
        elif mode(st)!=want:problems.append(rel+': mode %s, expected %s (the sandboxed service cannot read it)'%(mode(st),want))
for rel in required:
    path=os.path.join(root,rel)
    if not os.path.isfile(path) or os.path.getsize(path)==0:problems.append(rel+': required file is missing or empty')
print('\n'.join(problems)) if problems else None
sys.exit(1 if problems else 0)
PYFALLBACKTREE
}

# Installs the read-only site and server below $LIB_DIR (part of every
# transaction snapshot). Never touches a host web server configuration.
install_fallback_web_files() {
  local stage problems
  # ZgoCloud intentionally carries no website. Never silently accept that
  # build when the requested candidate requires the self-hosted REALITY site.
  if [ "$FALLBACK_WEB_BUNDLE_SHA256" = disabled ]; then
    if [ -s "$STATE_FILE" ] && reality_fallback_active "$STATE_FILE"; then
      warn "Self-hosted Personal Cloud is unavailable in this manager build: embedded website bundle is disabled."
      return 1
    fi
    return 0
  fi
  install -d -m 0750 "$LIB_DIR"
  # Stage on the DESTINATION filesystem so every later mv is a rename(2).
  # A cross-filesystem mv (tmpfs /run -> disk) is a recursive copy, and the
  # uutils coreutils mv shipped by Ubuntu 26.10 recreates directories with the
  # process umask (077): site/ became 0700 and the unprivileged service failed
  # with "site root has no index.html". Modes are also normalized explicitly.
  rm -rf -- "$LIB_DIR"/.fallback-web.stage.*
  stage="$(mktemp -d "$LIB_DIR/.fallback-web.stage.XXXXXX")" || return 1
  fallback_web_bundle | base64 -d > "$stage/bundle.tgz" || { rm -rf "$stage"; return 1; }
  [ "$(sha256sum "$stage/bundle.tgz" | awk '{print $1}')" = "$FALLBACK_WEB_BUNDLE_SHA256" ] || { rm -rf "$stage"; warn "Embedded Personal Cloud bundle digest mismatch."; return 1; }
  install -d -m 0755 "$stage/tree"
  python3 -I -B - "$stage/bundle.tgz" "$stage/tree" "${FALLBACK_WEB_REQUIRED[@]}" <<'PYFALLBACKUNPACK' || { rm -rf "$stage"; return 1; }
import hashlib,json,os,sys,tarfile
from pathlib import Path,PurePosixPath
archive,target,required=sys.argv[1],Path(sys.argv[2]),sys.argv[3:]
with tarfile.open(archive,'r:gz') as tf:
    members=tf.getmembers();files={}
    for m in members:
        p=PurePosixPath(m.name)
        if not m.isfile() or p.is_absolute() or '..' in p.parts or any(x.startswith('.') for x in p.parts) or m.name in files:raise SystemExit('unsafe Personal Cloud bundle entry')
        files[m.name]=tf.extractfile(m).read()
if 'MANIFEST.json' not in files:raise SystemExit('Personal Cloud bundle has no manifest')
manifest=json.loads(files.pop('MANIFEST.json'))
if manifest!={n:hashlib.sha256(b).hexdigest() for n,b in files.items()}:raise SystemExit('Personal Cloud bundle manifest mismatch')
missing=[r for r in required if not files.get(r)]
if missing:raise SystemExit('Personal Cloud bundle is missing: '+', '.join(missing))
os.umask(0o022)
for name,data in sorted(files.items()):
    out=target/name
    for parent in reversed(out.relative_to(target).parents[:-1]):
        d=target/parent
        if not d.is_dir():d.mkdir(mode=0o755)
        os.chmod(d,0o755)
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as fh:fh.write(data)
    os.chmod(out,0o644)
PYFALLBACKUNPACK
  find "$stage/tree" -type d -exec chmod 0755 {} + && find "$stage/tree" -type f -exec chmod 0644 {} + && chown -R root:root "$stage/tree" || { rm -rf "$stage"; return 1; }
  rm -rf -- "$FALLBACK_WEB_DIR.new"
  mv -T "$stage/tree" "$FALLBACK_WEB_DIR.new" || { rm -rf "$stage"; return 1; }
  rm -rf -- "$FALLBACK_WEB_DIR"
  mv -T "$FALLBACK_WEB_DIR.new" "$FALLBACK_WEB_DIR" || { rm -rf "$stage"; return 1; }
  rm -rf "$stage"
  find "$FALLBACK_WEB_DIR" -type d -exec chmod 0755 {} + && find "$FALLBACK_WEB_DIR" -type f -exec chmod 0644 {} + || return 1
  # Do not let an incomplete or unreadable site reach systemd. The transaction
  # must stop here, while the previous runtime is still recoverable.
  if ! problems="$(fallback_web_tree_check "$FALLBACK_WEB_DIR")"; then
    warn "Personal Cloud website files are not deployable: ${problems//$'\n'/; }"
    rm -rf -- "$FALLBACK_WEB_DIR"
    return 1
  fi
}

# Unit text is a pure function of the state, so tests can verify it offline.
fallback_web_unit_content() {
  local state="$1" host listen port
  host="$(jq -r '.protocols.reality.fallback.hostname' "$state")"
  listen="$(jq -r '.protocols.reality.fallback.listen' "$state")"
  port="$(jq -r '.protocols.reality.fallback.port' "$state")"
  cat <<EOF
# Managed by sbox-manager
# SBOX Personal Cloud: self-hosted REALITY fallback website. Loopback only.
[Unit]
Description=SBOX Personal Cloud website (self-hosted REALITY fallback, loopback only)
After=network.target local-fs.target
Before=sing-box.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=exec
DynamicUser=yes
# Fail closed, as the sandboxed service user, if any page is missing or
# unreadable; the journal names the exact path and error.
ExecStartPre=/usr/bin/python3 -I -B /srv/sbox-fallback-web/server.py --preflight --root /srv/sbox-fallback-web/site
ExecStart=/usr/bin/python3 -I -B /srv/sbox-fallback-web/server.py --listen $listen --port $port --hostname $host --root /srv/sbox-fallback-web/site --quiet
LoadCredential=tls.crt:$SERVICE_CERT
LoadCredential=tls.key:$SERVICE_KEY
# Bind the complete verified website tree once into the private /srv tmpfs.
# A single root bind exposes server.py and every site page without a nested
# mount that could mask the site directory on another systemd version.
TemporaryFileSystem=/srv:ro
BindReadOnlyPaths=$FALLBACK_WEB_DIR:/srv/sbox-fallback-web
InaccessiblePaths=-$BASE_DIR -/var/lib/sbox-manager -$BACKUP_DIR -/etc/letsencrypt -/var/lib/sbox-accounting -/usr/local/lib/sbox-accounting -/usr/local/lib/sbox-webui -/etc/sbox-webui -/var/lib/sbox-webui -/run/sbox-webui-control -/etc/fail2ban -/var/log
Restart=on-failure
RestartSec=2s
TimeoutStartSec=20s
TimeoutStopSec=10s
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=localhost
SocketBindDeny=any
SocketBindAllow=tcp:$port
MemoryMax=96M
TasksMax=256
CPUQuota=50%
LimitNOFILE=1024
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=50

[Install]
WantedBy=multi-user.target sing-box.service
EOF
}

fallback_web_unit_owned() { [ ! -e "$FALLBACK_WEB_SERVICE_FILE" ] || manager_owned_file "$FALLBACK_WEB_SERVICE_FILE"; }

# Inside the apply transaction: write or remove ONLY the SBOX-owned unit.
fallback_web_sync() {
  local state="$1" tmp
  fallback_web_unit_owned || { warn "$FALLBACK_WEB_SERVICE_FILE exists and is not managed by SBOX; refusing to touch it."; return 1; }
  if reality_fallback_active "$state"; then
    tmp="$(mktemp "$RUNTIME_DIR/fallback-unit.XXXXXX")"
    fallback_web_unit_content "$state" > "$tmp"
    atomic_install "$tmp" "$FALLBACK_WEB_SERVICE_FILE" 0644 root root
    rm -f "$tmp"
  elif [ -e "$FALLBACK_WEB_SERVICE_FILE" ]; then
    systemctl disable --now "$FALLBACK_WEB_UNIT" >/dev/null 2>&1 || true
    rm -f -- "$FALLBACK_WEB_SERVICE_FILE"
  fi
}

# fallback_web_check STATE [via]  -- verified HTTPS against the system trust
# store with SNI = the website hostname. "via" connects to the public REALITY
# port on loopback instead, proving REALITY relays ordinary TLS to the site.
fallback_web_check() {
  local state="$1" via="${2:-}" host listen port
  local -a connect=()
  host="$(jq -r '.protocols.reality.fallback.hostname' "$state")"
  listen="$(jq -r '.protocols.reality.fallback.listen' "$state")"
  port="$(jq -r '.protocols.reality.fallback.port' "$state")"
  if [ "$via" = via ]; then
    connect=(--connect-port "$(jq -r '.protocols.reality.port' "$state")")
    # The website stays on its own loopback family. Probe the actual VPN
    # listener, which may independently bind an assigned IPv6-only address.
    local inbound
    inbound="$(jq -r '.server.listen // "0.0.0.0"' "$state")"
    case "$inbound" in 0.0.0.0|::) connect+=(--connect-host 127.0.0.1) ;; *) connect+=(--connect-host "$inbound") ;; esac
  fi
  python3 -I -B "$FALLBACK_WEB_DIR/server.py" --check --compact --listen "$listen" --port "$port" --hostname "$host" "${connect[@]}"
}

fallback_web_wait_healthy() {
  local state="$1" tries="${2:-15}" i
  for ((i=1;i<=tries;i++)); do
    fallback_web_check "$state" >/dev/null 2>&1 && return 0
    systemctl is-failed --quiet "$FALLBACK_WEB_UNIT" 2>/dev/null && break
    sleep 1
  done
  fallback_web_check "$state" >&2 || true
  systemctl status --no-pager "$FALLBACK_WEB_UNIT" >&2 || true
  journalctl --no-pager -u "$FALLBACK_WEB_UNIT" -n 60 >&2 || true
  return 1
}

fallback_web_record_failure() {
  install -d -m 0700 "$(dirname "$FALLBACK_WEB_FAILURE")" || return 0
  jq -n --arg reason "$1" '{time:(now|todateiso8601),reason:$reason}' > "$FALLBACK_WEB_FAILURE" 2>/dev/null || true
  chmod 0600 "$FALLBACK_WEB_FAILURE" 2>/dev/null || true
}

# Inside the apply transaction, after sing-box.service is restarted.
fallback_web_activate() {
  local state="$1" problems
  reality_fallback_active "$state" || return 0
  # Check the host tree before asking systemd to create a mount namespace.
  # This distinguishes an incomplete or unreadable install tree from a
  # service sandbox issue, and names the exact file.
  if ! problems="$(fallback_web_tree_check "$FALLBACK_WEB_DIR")"; then
    fallback_web_record_failure "website files not deployable: ${problems//$'\n'/; }"
    warn "Personal Cloud website deployment is incomplete: ${problems//$'\n'/; }"
    return 1
  fi
  systemctl enable "$FALLBACK_WEB_UNIT" >/dev/null || return 1
  systemctl reset-failed "$FALLBACK_WEB_UNIT" >/dev/null 2>&1 || true
  # Restart (not reload): systemd re-reads the credentials, so a renewed
  # certificate is always picked up.
  systemctl restart "$FALLBACK_WEB_UNIT" || {
    fallback_web_record_failure 'service did not start'
    systemctl status --no-pager "$FALLBACK_WEB_UNIT" >&2 || true
    journalctl --no-pager -u "$FALLBACK_WEB_UNIT" -n 60 >&2 || true
    return 1
  }
  fallback_web_wait_healthy "$state" 15 || { fallback_web_record_failure 'local HTTPS health check failed'; return 1; }
}

# Disposable-lab fault injection for rollback/recovery acceptance. Inert unless
# the host carries the lab marker; never set on a production server.
lab_fault() {
  [ -n "${SBOX_LAB_FAULT:-}" ] && [ -f /opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS ] || return 0
  case "$SBOX_LAB_FAULT" in
    "$1") warn "LAB FAULT INJECTED at $1"; return 1 ;;
    "$1-hang") warn "LAB FAULT: hanging at $1 (kill this process to simulate a crash)"; sleep 3600; return 1 ;;
  esac
  return 0
}

# Matching upgrade (feature transaction): reinstall the verified website tree
# and unit from this release, restart and verify loopback HTTPS and the REALITY
# relay. Any failure returns non-zero so the caller restores its snapshot.
fallback_web_upgrade() {
  [ -s "$STATE_FILE" ] && reality_fallback_active "$STATE_FILE" || return 0
  log "Updating the self-hosted Personal Cloud website to this release..."
  install_fallback_web_files || return 1
  fallback_web_sync "$STATE_FILE" || return 1
  lab_fault website-upgrade || return 1
  systemctl daemon-reload || return 1
  fallback_web_activate "$STATE_FILE" || return 1
  fallback_web_verify_relay "$STATE_FILE" || return 1
}

# The sandbox masks later-created private paths (WebUI/accounting state) only
# when the namespace is built. A fresh install creates them after the website
# started, so rebuild the namespace once and re-verify; failure is reported,
# not hidden, and leaves the VPN untouched.
fallback_web_refresh_sandbox() {
  [ -s "$STATE_FILE" ] && reality_fallback_active "$STATE_FILE" || return 0
  systemctl is-active --quiet "$FALLBACK_WEB_UNIT" 2>/dev/null || return 0
  systemctl restart "$FALLBACK_WEB_UNIT" && fallback_web_wait_healthy "$STATE_FILE" 15 && fallback_web_verify_relay "$STATE_FILE" && return 0
  warn "Personal Cloud website did not become healthy after its sandbox refresh; run: sbox reality-fallback check"
  return 0
}

fallback_web_verify_relay() {
  local state="$1" i
  reality_fallback_active "$state" || return 0
  for ((i=1;i<=10;i++)); do
    fallback_web_check "$state" via >/dev/null 2>&1 && { rm -f -- "$FALLBACK_WEB_FAILURE"; return 0; }
    sleep 1
  done
  fallback_web_check "$state" via >&2 || true
  fallback_web_record_failure 'REALITY did not relay ordinary HTTPS to the Personal Cloud website'
  return 1
}

# No firewall rule may ever expose the loopback website port.
fallback_web_no_public_rule() {
  local port="$1"
  ! firewall_owned_dump 2>/dev/null | grep -Eq -- "--dport ${port}( |$)"
}

reality_fallback_doctor() {
  local state="$1" host port listen
  jq -e '.protocols.reality.enabled == true' "$state" >/dev/null || return 0
  if ! reality_fallback_active "$state"; then
    doctor_record info "REALITY handshake target: remote website $(jq -r '.protocols.reality.sni' "$state"):$(jq -r '.protocols.reality.dest_port' "$state") (SBOX does not copy that site's certificate)"
    doctor_check "no leftover Personal Cloud website service" test ! -e "$FALLBACK_WEB_SERVICE_FILE" || failures=$((failures+1))
    return 0
  fi
  host="$(jq -r '.protocols.reality.fallback.hostname' "$state")"; port="$(jq -r '.protocols.reality.fallback.port' "$state")"; listen="$(jq -r '.protocols.reality.fallback.listen' "$state")"
  doctor_record info "REALITY handshake target: self-hosted SBOX Personal Cloud for $host on $listen:$port"
  doctor_check "Personal Cloud website files installed and readable by the sandboxed service" fallback_web_tree_check "$FALLBACK_WEB_DIR" || failures=$((failures+1))
  fallback_web_unit_content "$state" > "$state.unit"
  doctor_check "Personal Cloud website unit is SBOX-owned and matches the state" cmp -s "$state.unit" "$FALLBACK_WEB_SERVICE_FILE" || failures=$((failures+1))
  rm -f -- "$state.unit"
  doctor_check "Personal Cloud website service active" systemctl is-active --quiet "$FALLBACK_WEB_UNIT" || failures=$((failures+1))
  doctor_check "Personal Cloud website service enabled for reboot" systemctl is-enabled --quiet "$FALLBACK_WEB_UNIT" || failures=$((failures+1))
  doctor_check "Personal Cloud website: loopback-only listener, trusted certificate for $host and all pages served" fallback_web_check "$state" || failures=$((failures+1))
  doctor_check "REALITY relays ordinary HTTPS on port $(jq -r '.protocols.reality.port' "$state") to the Personal Cloud website" fallback_web_check "$state" via || failures=$((failures+1))
  doctor_check "no public firewall rule for the local website port $port" fallback_web_no_public_rule "$port" || failures=$((failures+1))
  if [ -s "$FALLBACK_WEB_FAILURE" ]; then
    doctor_record warn "last Personal Cloud website activation failed: $(jq -r '"\(.time) \(.reason)"' "$FALLBACK_WEB_FAILURE" 2>/dev/null || echo unknown)"
    warnings=$((warnings+1))
  fi
}

reality_fallback_command() {
  local action="${1:-status}" temp current candidate plan remote host port listen
  [ "$#" -gt 0 ] && shift || true
  case "$action" in
    status|check)
      need_root; require_installed
      temp="$(mktemp "$RUNTIME_DIR/fallback-status.XXXXXX.json")"; normalize_state_ro "$STATE_FILE" "$temp"
      if ! jq -e '.protocols.reality.enabled == true' "$temp" >/dev/null; then echo "REALITY is disabled."; rm -f "$temp"; return 0; fi
      if reality_fallback_active "$temp"; then
        printf 'REALITY handshake target : self-hosted SBOX Personal Cloud\nWebsite                  : https://%s (relayed by REALITY on TCP %s)\nLocal listener           : %s:%s (loopback only)\nService                  : %s\n' \
          "$(jq -r '.protocols.reality.fallback.hostname' "$temp")" "$(jq -r '.protocols.reality.port' "$temp")" "$(jq -r '.protocols.reality.fallback.listen' "$temp")" "$(jq -r '.protocols.reality.fallback.port' "$temp")" "$(systemctl is-active "$FALLBACK_WEB_UNIT" 2>/dev/null || echo inactive)"
        if [ "$action" = check ]; then fallback_web_check "$temp" && fallback_web_check "$temp" via; local rc=$?; rm -f "$temp"; return "$rc"; fi
      else
        printf 'REALITY handshake target : remote website %s:%s\nNote                     : SBOX does not obtain or copy that website'"'"'s certificate.\n' "$(jq -r '.protocols.reality.sni' "$temp")" "$(jq -r '.protocols.reality.dest_port' "$temp")"
      fi
      rm -f "$temp"; return 0 ;;
    remote|self-hosted|self_hosted) ;;
    *) die "Usage: sbox reality-fallback status|check|remote [--sni HOST]|self-hosted [--port N] [--cert ...]" ;;
  esac
  local sni_opt=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --sni) [ "$#" -ge 2 ] || die "--sni requires a hostname."; sni_opt="$2"; shift 2 ;;
      --port) [ "$#" -ge 2 ] || die "--port requires a value."; OPT_reality_fallback_port="$2"; shift 2 ;;
      *) parse_install_options "$@"; break ;;
    esac
  done
  need_root; require_installed; acquire_session
  temp="$(mktemp -d "$RUNTIME_DIR/reality-fallback.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"; plan="$temp/cert-plan.json"
  normalized_current_state "$current"
  jq -e '.protocols.reality.enabled == true' "$current" >/dev/null || { rm -rf "$temp"; die "Enable VLESS REALITY first (sbox protocols)."; }
  jq -e '.zgo_legacy_compat != true' "$current" >/dev/null || { rm -rf "$temp"; die "The self-hosted REALITY website is available for Universal installations only."; }
  if reality_fallback_active "$current"; then remote="$(jq -r '.protocols.reality.fallback.remote_sni' "$current")"; else remote="$(jq -r '.protocols.reality.sni' "$current")"; fi
  if [ "$action" = remote ]; then
    [ -z "$sni_opt" ] || { validate_domain "$sni_opt" || die "Invalid --sni hostname."; remote="$sni_opt"; }
    jq --arg sni "$remote" --arg manager "$MANAGER_VERSION" '.protocols.reality.sni=$sni | del(.protocols.reality.fallback) | .manager_version=$manager | .updated_at=(now|todateiso8601)' "$current" > "$candidate"
  else
    host="$(jq -r '.domain' "$current")"
    port="$(ask_fallback_port "${OPT_reality_fallback_port:-$(jq -r '.protocols.reality.fallback.port // empty' "$current")}" $(jq -r '.protocols|to_entries[]|select(.value.enabled and (.key!="hy2") and (.key!="tuic"))|.value.port' "$current"))"
    [ -n "$port" ] || port="$FALLBACK_WEB_DEFAULT_PORT"
    listen=127.0.0.1
    jq --arg host "$host" --argjson port "$port" --arg listen "$listen" --arg remote "$remote" --arg manager "$MANAGER_VERSION" \
      '.protocols.reality.sni=$host | .protocols.reality.fallback={mode:"self_hosted",hostname:$host,listen:$listen,port:$port,remote_sni:$remote} | .manager_version=$manager | .updated_at=(now|todateiso8601)' "$current" > "$candidate"
  fi
  chmod 0600 "$candidate"
  collect_state_certificate_plan "$candidate" "$(jq -r '.domain' "$candidate")" "$current" "$plan"
  merge_plan_certificate "$candidate" "$plan" "$temp/merged.json"; mv -f "$temp/merged.json" "$candidate"
  echo >&2; print_plan_summary "$candidate" "$plan" >&2
  SBOX_ANSWER="$(yes_no 'Apply this REALITY handshake target?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_planned_candidate "$candidate" '' "REALITY handshake target change" "$plan"
  rm -rf "$temp"
  echo "Client profiles were regenerated. Re-import them if the REALITY SNI changed."
}

choose_fingerprint() {
  local current="${1:-chrome}" choice default=1
  case "$current" in chrome) default=1 ;; firefox) default=2 ;; edge) default=3 ;; safari) default=4 ;; ios) default=5 ;; android) default=6 ;; random) default=7 ;; randomized) default=8 ;; esac
  echo >&2
  echo "REALITY uTLS fingerprint: 1 chrome, 2 firefox, 3 edge, 4 safari, 5 ios, 6 android, 7 random, 8 randomized" >&2
  choice="$(prompt_choice 'Select fingerprint' "$default" '1 2 3 4 5 6 7 8')"
  case "$choice" in 1) echo chrome ;; 2) echo firefox ;; 3) echo edge ;; 4) echo safari ;; 5) echo ios ;; 6) echo android ;; 7) echo random ;; 8) echo randomized ;; esac
}

ask_vmess_path() {
  local default="$1" value
  while true; do
    value="$(ask 'VMess WebSocket path (without leading slash)' "${default#/}")"; value="${value#/}"
    [[ "$value" =~ ^[A-Za-z0-9._~-]{1,128}$ ]] && { echo "$value"; return 0; }
    assume_or_die "Invalid VMess path for non-interactive mode: $value"
    echo "Invalid VMess path." >&2
  done
}

choose_protocol_port() {
  local label="$1" proto="$2" enabled="$3" old_enabled="$4" current="${5:-}" used
  shift 5
  if [ "$enabled" = true ]; then
    [ "$old_enabled" = true ] || current=''
    ask_port "$label" "$proto" "$current" "$@"
    return 0
  fi
  current="$(normalize_port "$current")" || current=''
  for used in "$@"; do [ -n "$used" ] && [ "$current" = "$used" ] && current=''; done
  if [ -n "$current" ] && [ "$old_enabled" != true ] && port_in_use "$current" "$proto"; then current=''; fi
  [ -n "$current" ] && echo "$current" || random_free_port "$proto" "$@"
}

build_guided_state() {
  local output="$1" existing="$2" region="$3" binary="$4" version="$5" channel="$6" cert_plan="$7"
  local keep_network=false endpoint_scope=public endpoint_override='' old_server='{}'
  local has_old=false old_node=SBOX old_domain='' old_ipv4='' old_ipv6='' old_listen='0.0.0.0'
  [ -s "$existing" ] && has_old=true
  if [ "$has_old" = true ]; then
    old_node="$(jq -r '.node_name' "$existing")"; old_domain="$(jq -r '.domain' "$existing")"
    old_ipv4="$(jq -r '.server.ipv4 // empty' "$existing")"; old_ipv6="$(jq -r '.server.ipv6 // empty' "$existing")"
    old_listen="$(jq -r '.server.listen' "$existing")"
  fi

  local detected4 detected6 ipv4 ipv6 node domain listen enabled
  if [ "$ASSUME_DEFAULTS" = true ]; then
    # Unattended runs must not depend on outbound reachability of an IP echo
    # service: explicit flags win, otherwise the saved values are kept.
    detected4=''; detected6=''
  else
    detected4="$(detect_public_ipv4 || true)"; detected6="$(detect_public_ipv6 || true)"
  fi
  ipv4="$(ask_optional_ip 'Public IPv4' 4 "${OPT_ipv4:-${detected4:-$old_ipv4}}")"
  ipv6="$(ask_optional_ip 'Public IPv6' 6 "${OPT_ipv6:-${detected6:-$old_ipv6}}")"
  node="$(ask_label 'Node name' "${OPT_node:-$old_node}")"
  domain="$(ask_domain 'Client domain' "${OPT_domain:-$old_domain}")"
  local family="${OPT_family:-}"
  if [ "$has_old" = true ] && { [ "$family" = preserve ] || { [ -z "$family" ] && [ "$ASSUME_DEFAULTS" = true ]; }; }; then
    keep_network=true
    family="$(jq -r '.server.mode // "preserve"' "$existing")"
    listen="${OPT_listen:-$old_listen}"
  else
    case "$family" in
      ipv4) listen="${OPT_listen:-0.0.0.0}" ;; dual) listen='::' ;;
      ipv6) [ -n "$ipv6" ] || die 'IPv6 mode requires --ipv6 with a host address.'; listen="$ipv6" ;;
      preserve|'') listen="$(choose_listen "${OPT_listen:-$old_listen}" "$ipv6" "$has_old" "$([ -n "$detected6" ] && [ "$ipv6" = "$detected6" ] && echo true || echo false)")" ;;
      *) die 'Unknown family; use preserve, ipv4, dual or ipv6.' ;;
    esac
    if [ "$listen" = preserve ]; then
      keep_network=true
      family="$(jq -r '.server.mode // "preserve"' "$existing")"; listen="$old_listen"
    fi
    if [ -z "$family" ]; then
      case "$listen" in 0.0.0.0) family=ipv4 ;; ::) family=dual ;; *) family=ipv6 ;; esac
    fi
  fi
  if [ "$keep_network" = true ]; then
    old_server="$(jq -c '.server' "$existing")"
    endpoint_scope="$(jq -r '.server.scope // (if (.server.mode // "preserve")=="preserve" then "legacy" else "public" end)' "$existing")"
    endpoint_override="$(jq -r '.server.endpoint_override // empty' "$existing")"
  fi
  endpoint_scope="${OPT_scope:-$endpoint_scope}"
  case "$endpoint_scope" in public|internal|legacy) ;; *) die 'Scope must be public or internal.' ;; esac
  if [ -n "$OPT_endpoint_override_file" ]; then
    [ -f "$OPT_endpoint_override_file" ] && [ ! -L "$OPT_endpoint_override_file" ] && [ "$(stat -c '%u %a' "$OPT_endpoint_override_file")" = '0 600' ] || die 'Endpoint override file must be a root-owned0600 regular file.'
    endpoint_override="$(cat "$OPT_endpoint_override_file")"
  fi
  check_domain_dns "$domain" "$ipv4" "$ipv6" "$(jq -nr --arg mode "$family" --argjson old "$old_server" '$old.policies.inbound // $mode')" "$endpoint_scope" "$endpoint_override" "$(jq -r '.interface // empty' <<< "$old_server")"
  enabled="$(select_protocols "$existing")"

  local reality_enabled vmess_enabled hy2_enabled tuic_enabled anytls_enabled
  reality_enabled="$(jq -r '.reality' <<< "$enabled")"; vmess_enabled="$(jq -r '.vmess' <<< "$enabled")"
  hy2_enabled="$(jq -r '.hy2' <<< "$enabled")"; tuic_enabled="$(jq -r '.tuic' <<< "$enabled")"; anytls_enabled="$(jq -r '.anytls' <<< "$enabled")"

  local old_reality_port='' old_vmess_port='' old_anytls_port='' old_hy2_port='' old_tuic_port=''
  local old_reality_enabled=false old_vmess_enabled=false old_anytls_enabled=false old_hy2_enabled=false old_tuic_enabled=false
  local old_range=''
  if [ "$has_old" = true ]; then
    old_reality_port="$(jq -r '.protocols.reality.port' "$existing")"; old_reality_enabled="$(jq -r '.protocols.reality.enabled' "$existing")"
    old_vmess_port="$(jq -r '.protocols.vmess.port' "$existing")"; old_vmess_enabled="$(jq -r '.protocols.vmess.enabled' "$existing")"
    old_anytls_port="$(jq -r '.protocols.anytls.port' "$existing")"; old_anytls_enabled="$(jq -r '.protocols.anytls.enabled' "$existing")"
    old_hy2_port="$(jq -r '.protocols.hy2.port' "$existing")"; old_hy2_enabled="$(jq -r '.protocols.hy2.enabled' "$existing")"
    old_tuic_port="$(jq -r '.protocols.tuic.port' "$existing")"; old_tuic_enabled="$(jq -r '.protocols.tuic.enabled' "$existing")"
    old_range="$(jq -r '.protocols.hy2.udp_range // empty' "$existing")"
  fi

  local reality_port vmess_port anytls_port hy2_port tuic_port hy2_range other_for_range=0
  local flag_port keep_reality="$old_reality_enabled" keep_vmess="$old_vmess_enabled" keep_anytls="$old_anytls_enabled"
  local keep_hy2="$old_hy2_enabled" keep_tuic="$old_tuic_enabled"
  # An explicit --ports value must win even when the protocol is enabled for the
  # first time, so it also marks the port as "keep" for choose_protocol_port.
  if flag_port="$(opt_port_for reality)"; then keep_reality=true; else flag_port="$old_reality_port"; fi
  reality_port="$(choose_protocol_port 'REALITY' tcp "$reality_enabled" "$keep_reality" "$flag_port")"
  if flag_port="$(opt_port_for vmess)"; then keep_vmess=true; else flag_port="$old_vmess_port"; fi
  vmess_port="$(choose_protocol_port 'VMess-WS' tcp "$vmess_enabled" "$keep_vmess" "$flag_port" "$reality_port")"
  if flag_port="$(opt_port_for anytls)"; then keep_anytls=true; else flag_port="$old_anytls_port"; fi
  anytls_port="$(choose_protocol_port 'AnyTLS' tcp "$anytls_enabled" "$keep_anytls" "$flag_port" "$reality_port" "$vmess_port")"
  if flag_port="$(opt_port_for hy2)"; then keep_hy2=true; else flag_port="$old_hy2_port"; fi
  hy2_port="$(choose_protocol_port 'Hysteria2' udp "$hy2_enabled" "$keep_hy2" "$flag_port")"
  if flag_port="$(opt_port_for tuic)"; then keep_tuic=true; else flag_port="$old_tuic_port"; fi
  tuic_port="$(choose_protocol_port 'TUIC-v5' udp "$tuic_enabled" "$keep_tuic" "$flag_port" "$hy2_port")"
  [ "$tuic_enabled" = true ] && other_for_range="$tuic_port"
  if [ "$hy2_enabled" = true ]; then
    hy2_range="$(ask_hy2_range "$hy2_port" "$other_for_range" "$(hy2_range_default "$old_range")")"
  else
    hy2_range=''
  fi

  local reality_uuid private_key public_key short_id vmess_uuid hy2_pass tuic_uuid tuic_pass anytls_pass
  if [ "$has_old" = true ]; then
    reality_uuid="$(jq -r '.protocols.reality.uuid' "$existing")"; private_key="$(jq -r '.protocols.reality.private_key' "$existing")"
    public_key="$(jq -r '.protocols.reality.public_key' "$existing")"; short_id="$(jq -r '.protocols.reality.short_id' "$existing")"
    vmess_uuid="$(jq -r '.protocols.vmess.uuid' "$existing")"; hy2_pass="$(jq -r '.protocols.hy2.password' "$existing")"
    tuic_uuid="$(jq -r '.protocols.tuic.uuid' "$existing")"; tuic_pass="$(jq -r '.protocols.tuic.password' "$existing")"
    anytls_pass="$(jq -r '.protocols.anytls.password' "$existing")"
  else
    reality_uuid="$(random_uuid)"; IFS=$'\t' read -r private_key public_key < <(generate_reality_keypair "$binary")
    short_id="$(random_hex 8)"; vmess_uuid="$(random_uuid)"; hy2_pass="$(random_hex 24)"
    tuic_uuid="$(random_uuid)"; tuic_pass="$(random_hex 24)"; anytls_pass="$(random_hex 24)"
  fi

  local reality_sni=www.cloudflare.com fingerprint=chrome vmess_path vmess_tls=true tuning firewall block_private old_cert='{}' old_client_policy='{"primary":"tuic","rule_precedence":"lan_first"}'
  vmess_path="$(random_hex 12)-vm"
  if [ "$has_old" = true ]; then
    reality_sni="$(jq -r '.protocols.reality.sni' "$existing")"; fingerprint="$(jq -r '.protocols.reality.fingerprint' "$existing")"
    vmess_path="$(jq -r '.protocols.vmess.path' "$existing")"; vmess_tls="$(jq -r '.protocols.vmess.tls' "$existing")"
    old_cert="$(jq -c '.certificate' "$existing")"
    old_client_policy="$(jq -c '.client_policy // {primary:"tuic"}' "$existing")"
  fi
  local old_fallback='{}' fallback='{"mode":"remote"}' remote_sni
  if [ "$has_old" = true ]; then old_fallback="$(jq -c '.protocols.reality.fallback // {}' "$existing")"; fi
  # A self-hosted state stores the remote target it replaced, so switching back
  # restores the previous remote SNI instead of the website hostname.
  remote_sni="$(jq -r --arg sni "$reality_sni" 'if .mode == "self_hosted" then .remote_sni else $sni end' <<< "$old_fallback")"
  if [ "$reality_enabled" = true ]; then
    # Only the Universal product offers the self-hosted website.
    if [ "$has_old" = true ] && jq -e '.zgo_legacy_compat == true' "$existing" >/dev/null; then
      reality_sni="$(choose_reality_sni "$reality_sni")"
    else
      fallback="$(choose_reality_fallback "$old_fallback" "$domain" "$remote_sni" \
        "$([ "$vmess_enabled" = true ] && echo "$vmess_port")" "$([ "$anytls_enabled" = true ] && echo "$anytls_port")" "$reality_port")"
      if [ "$(jq -r '.mode' <<< "$fallback")" = self_hosted ]; then
        reality_sni="$domain"
      else
        reality_sni="$(choose_reality_sni "$remote_sni")"
      fi
    fi
    fingerprint="$(choose_fingerprint "$fingerprint")"
  elif [ "$(jq -r '.mode // "remote"' <<< "$old_fallback")" = self_hosted ]; then
    # REALITY is off: keep the remote target as the dormant default.
    reality_sni="$remote_sni"
  fi
  if [ "$vmess_enabled" = true ]; then
    vmess_path="$(ask_vmess_path "$vmess_path")"
    vmess_tls="$(yes_no 'Enable TLS on VMess-WS?' "$([ "$vmess_tls" = true ] && echo yes || echo no)")"
  fi
  local old_firewall=true old_tuning=false old_block_private=true
  if [ "$has_old" = true ]; then
    old_firewall="$(jq -r '.firewall.enabled' "$existing")"
    old_tuning="$(jq -r '.tuning.enabled' "$existing")"
    old_block_private="$(jq -r '.security.block_private' "$existing")"
  fi
  firewall="$(yes_no 'Install/reconcile local firewall allow rules?' "$(opt_yesno "${OPT_firewall:-}" "$old_firewall")")"
  tuning="$(yes_no 'Apply legacy BBR/fq socket tuning (measure before opting in)?' "$(opt_yesno "${OPT_tuning:-}" "$old_tuning")")"
  block_private="$(yes_no 'Block proxied access to private/link-local VPS destinations?' "$(opt_yesno "${OPT_block_private:-}" "$old_block_private")")"

  private_jq -n \
    --arg created_at "$([ "$has_old" = true ] && jq -r ' .created_at // (now|todateiso8601)' "$existing" || date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson schema "$STATE_SCHEMA" --arg manager "$MANAGER_VERSION" --arg region "$region" --arg node "$node" --arg domain "$domain" \
    --arg scope "$endpoint_scope" --arg override "$endpoint_override" --argjson old_server "$old_server" \
    --arg family "$family" --arg ipv4 "$ipv4" --arg ipv6 "$ipv6" --arg listen "$listen" --arg version "$version" --arg channel "$channel" \
    --argjson enabled "$enabled" --argjson firewall "$firewall" --argjson tuning "$tuning" --argjson block_private "$block_private" \
    --argjson dest_port "$([ "$has_old" = true ] && jq -r .protocols.reality.dest_port "$existing" || echo 443)" \
    --arg reality_uuid "$reality_uuid" --arg private "$private_key" --arg public "$public_key" --arg short "$short_id" --arg reality_sni "$reality_sni" --arg fp "$fingerprint" --argjson reality_port "$reality_port" \
    --argjson reality_tfo "$([ "$has_old" = true ] && jq '.protocols.reality.tcp_fast_open // false' "$existing" || echo true)" \
    --argjson server_dns "$([ "$has_old" = true ] && jq -c '.server_dns // {optimistic:false}' "$existing" || echo '{"optimistic":true}')" \
    --argjson vmess_mux "$([ "$has_old" = true ] && jq '.protocols.vmess.multiplex // false' "$existing" || echo true)" \
    --arg vmess_uuid "$vmess_uuid" --arg vmess_path "$vmess_path" --argjson vmess_tls "$vmess_tls" --argjson vmess_port "$vmess_port" \
    --arg hy2_pass "$hy2_pass" --argjson hy2_port "$hy2_port" --arg hy2_range "$hy2_range" \
    --arg tuic_uuid "$tuic_uuid" --arg tuic_pass "$tuic_pass" --argjson tuic_port "$tuic_port" \
    --arg anytls_pass "$anytls_pass" --argjson anytls_port "$anytls_port" --argjson old_cert "$old_cert" --argjson client_policy "$old_client_policy" \
    '{
      schema:$schema,manager_version:$manager,
      created_at:$created_at,updated_at:(now|todateiso8601),
      region:$region,node_name:$node,domain:$domain,
      server:($old_server+{ipv4:$ipv4,ipv6:$ipv6,listen:$listen,mode:$family,scope:$scope,endpoint_override:$override}),
      sing_box:{version:$version,channel:$channel},
      certificate:$old_cert,client_policy:$client_policy,
      firewall:{enabled:$firewall},tuning:{enabled:$tuning},security:{block_private:$block_private},server_dns:$server_dns,
      protocols:{
        reality:{enabled:$enabled.reality,port:$reality_port,uuid:$reality_uuid,sni:$reality_sni,dest_port:$dest_port,fingerprint:$fp,private_key:$private,public_key:$public,short_id:$short,tcp_fast_open:$reality_tfo},
        vmess:{enabled:$enabled.vmess,port:$vmess_port,uuid:$vmess_uuid,path:$vmess_path,tls:$vmess_tls,sni:$domain,multiplex:$vmess_mux},
        hy2:{enabled:$enabled.hy2,port:$hy2_port,password:$hy2_pass,udp_range:$hy2_range},
        tuic:{enabled:$enabled.tuic,port:$tuic_port,uuid:$tuic_uuid,password:$tuic_pass},
        anytls:{enabled:$enabled.anytls,port:$anytls_port,password:$anytls_pass}
      }
    }' > "$output"
  if [ "$has_old" = false ] && [ "$family" != preserve ]; then
    jq --arg mode "$family" '.server.panel_family=$mode' "$output" > "$output.network" && mv "$output.network" "$output"
  fi
  chmod 0600 "$output"
  if [ "$(jq -r '.mode' <<< "$fallback")" = self_hosted ]; then
    jq --argjson fallback "$fallback" '.protocols.reality.fallback=$fallback' "$output" > "$output.fallback" && mv -f "$output.fallback" "$output"
    chmod 0600 "$output"
  fi

  local merged="${output}.merged"
  collect_state_certificate_plan "$output" "$domain" "$existing" "$cert_plan"
  if [ "$has_old" = true ] && jq -e 'has("managed_users")' "$existing" >/dev/null; then
    jq --slurpfile old "$existing" '.managed_users=$old[0].managed_users | if $old[0].accounting then .accounting=$old[0].accounting else . end' "$output" > "$output.users"
    mv -f "$output.users" "$output"
  fi
  merge_plan_certificate "$output" "$cert_plan" "$merged"
  mv -f "$merged" "$output"
}

print_plan_summary() {
  local state="$1" plan="${2:-}"
  jq -r '
    "Profile      : \(.region|ascii_upcase)",
    "Node         : \(.node_name)",
    "Domain       : \(.domain)",
    "Listen       : \(.server.listen)",
    "Network policy: \(.server.mode // "preserve")",
    "sing-box     : \(.sing_box.version) (\(.sing_box.channel))",
    "Protocols    : \([.protocols|to_entries[]|select(.value.enabled)|.key]|join(", "))",
    "REALITY target: \(if (.protocols.reality.enabled|not) then "n/a" elif (.protocols.reality.fallback.mode // "remote") == "self_hosted" then "self-hosted SBOX Personal Cloud (https://\(.protocols.reality.fallback.hostname), loopback \(.protocols.reality.fallback.listen):\(.protocols.reality.fallback.port))" else "remote website \(.protocols.reality.sni):\(.protocols.reality.dest_port)" end)",
    "Certificate  : \(.certificate.mode)",
    "Firewall     : \(.firewall.enabled)",
    "BBR/fq tuning: \(.tuning.enabled)",
    "Block private: \(.security.block_private)"
  ' "$state"
  if [ -n "$plan" ]; then
    printf 'Certificate action: %s\n' "$(jq -r '.method' "$plan")"
  fi
}

ensure_service_user() {
  local created_group=false created_user=false tmp
  if [ -s "$OWNERSHIP_FILE" ]; then
    created_group="$(jq -r '.created_group // false' "$OWNERSHIP_FILE" 2>/dev/null || echo false)"
    created_user="$(jq -r '.created_user // false' "$OWNERSHIP_FILE" 2>/dev/null || echo false)"
  fi
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then groupadd --system "$SERVICE_GROUP"; created_group=true; fi
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then useradd --system --gid "$SERVICE_GROUP" --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"; created_user=true; fi
  ensure_dirs
  chown root:"$SERVICE_GROUP" "$BASE_DIR" "$CERT_DIR" "$LIB_DIR"
  chmod 0750 "$BASE_DIR" "$CERT_DIR" "$LIB_DIR"
  chmod 0700 "$EXPORT_DIR" "$CERT_SOURCE_DIR" "$RUNTIME_DIR" "$BACKUP_DIR"
  tmp="$(mktemp "$RUNTIME_DIR/ownership.XXXXXX")"
  jq -n --argjson group "$created_group" --argjson user "$created_user" '{created_group:$group,created_user:$user}' > "$tmp"
  atomic_install "$tmp" "$OWNERSHIP_FILE" 0600 root root
  rm -f "$tmp"
}

manager_owned_file() {
  local path="$1"
  [ -f "$path" ] && sed -n '1,12p' "$path" 2>/dev/null | grep -Fq 'Managed by sbox-manager'
}

assert_safe_namespaces() {
  local reserved parent
  for reserved in /usr/local/lib/sbox-manager-security "$BASE_DIR" "$LIB_DIR" "$CERT_DIR" "$EXPORT_DIR" "$CERT_SOURCE_DIR" "$BACKUP_DIR" "$(dirname "$TXN_JOURNAL")"; do
    parent="$reserved"
    while [ "$parent" != / ]; do
      [ ! -L "$parent" ] || die "Reserved directory has a symlink ancestor: $parent"
      parent="$(dirname "$parent")"
    done
    [ ! -e "$reserved" ] || [ -d "$reserved" ] || die "Reserved path is not a directory: $reserved"
  done
  for reserved in "$STATE_FILE" "$CONFIG_FILE" "$BACKUP_KEY_FILE"; do
    [ ! -L "$reserved" ] || die "Reserved file is a symlink: $reserved"
  done
  for reserved in "$FIREWALL_SERVICE_FILE" "$SYSCTL_FILE" "$CERT_HOOK_FILE" "$OLD_WATCHDOG_SERVICE" "$OLD_WATCHDOG_TIMER"; do
    if [ -e "$reserved" ] || [ -L "$reserved" ]; then
      [ ! -L "$reserved" ] && { grep -Fq 'sbox-manager' "$reserved" || grep -Fq "$MANAGER_BIN" "$reserved"; } || die "Reserved file belongs to another application: $reserved"
    fi
  done
  local unit fragment
  for unit in sing-box.service sbox-manager-firewall.service; do
    fragment="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null || true)"
    if [ -n "$fragment" ] && [ -f "$fragment" ]; then
      grep -Fq 'sbox-manager' "$fragment" || die "An unrelated service owns $unit ($fragment)."
    fi
  done
  if [ -e "$SERVICE_FILE" ] || [ -L "$SERVICE_FILE" ]; then
    grep -Fq 'managed by sbox-manager' "$SERVICE_FILE" 2>/dev/null || die "An unmanaged sing-box.service already exists at $SERVICE_FILE."
  fi
  if [ -e "$CLI_BIN" ] || [ -L "$CLI_BIN" ]; then
    case "$(readlink -f "$CLI_BIN" 2>/dev/null || true)" in "$MANAGER_BIN"|"/usr/local/sbin/sbox-manager") ;; *) manager_owned_file "$CLI_BIN" || die "$CLI_BIN exists and is not managed by sbox." ;; esac
  fi
  if [ -L "$BASE_DIR" ] || { [ -e "$BASE_DIR" ] && [ ! -d "$BASE_DIR" ]; }; then
    die "$BASE_DIR is not a normal directory."
  fi
  if [ -d "$BASE_DIR" ] && ! state_exists; then
    find "$BASE_DIR" -mindepth 1 -not -type d -print -quit 2>/dev/null | grep -q . && die "$BASE_DIR contains files but no valid state.json. Inspect or move it first."
  fi
  if [ -L "$LIB_DIR" ] || { [ -e "$LIB_DIR" ] && [ ! -d "$LIB_DIR" ]; }; then
    die "$LIB_DIR is not a normal directory."
  fi
  if [ -d "$LIB_DIR" ]; then
    local path name
    for path in "$LIB_DIR"/*; do
      [ -e "$path" ] || [ -L "$path" ] || continue
      name="$(basename "$path")"
      case "$name" in
        manager)
          [ -f "$path" ] && [ ! -L "$path" ] && manager_owned_file "$path" || die "$path is not an sbox-managed manager file."
          ;;
        sing-box)
          [ -f "$path" ] && [ ! -L "$path" ] || die "$path is not a regular sing-box binary."
          ;;
        sbox-state|sbox-policy)
          [ -f "$path" ] && [ ! -L "$path" ] || die "$path is not a regular helper file."
          ;;
        fallback-web)
          # The Universal Personal Cloud website tree (self-hosted REALITY
          # fallback). It is recreated from the verified embedded bundle by
          # every apply; only its shape is checked here.
          [ -d "$path" ] && [ ! -L "$path" ] || die "$path is not an sbox-managed Personal Cloud directory."
          [ -f "$path/server.py" ] && [ ! -L "$path/server.py" ] && grep -Fqx '# Managed by sbox-manager' <(head -n 3 "$path/server.py") || die "$path is not an sbox-managed Personal Cloud directory."
          ;;
        *) die "Unknown file in reserved runtime directory: $path" ;;
      esac
    done
    if ! state_exists && [ -e "$SBOX_BIN" ] && ! manager_owned_file "$MANAGER_BIN"; then
      die "$SBOX_BIN exists without a recognized sbox manager or state. Inspect or move $LIB_DIR first."
    fi
  fi
}

install_manager_self() {
  local source resolved candidate installed_version installed_build_id cli_tmp
  ensure_runtime_dir
  source="${SBOX_MANAGER_SOURCE:-$0}"
  [ -f "$source" ] && [ -r "$source" ] || die "Manager source is not a readable regular file: $source"
  resolved="$(readlink -f "$source" 2>/dev/null || echo "$source")"
  candidate="$(mktemp "$RUNTIME_DIR/manager.XXXXXX")"
  python3 - "$resolved" "$candidate" <<'PY'
from pathlib import Path
import sys
source, output = map(Path, sys.argv[1:3])
data=source.read_bytes()
if data.startswith(b'\xef\xbb\xbf'): data=data[3:]
if b'\0' in data: raise SystemExit('NUL byte in manager source')
data=data.replace(b'\r\n',b'\n').replace(b'\r',b'\n')
text=data.decode('utf-8')
if '# Managed by sbox-manager' not in text.splitlines()[:12]: raise SystemExit('manager marker missing')
output.write_text(text if text.endswith('\n') else text+'\n',encoding='utf-8')
PY
  chmod 0755 "$candidate"
  bash -n "$candidate" || die "Manager source failed Bash syntax validation."
  atomic_install "$candidate" "$MANAGER_BIN" 0755 root root
  rm -f "$candidate"
  installed_version="$("$MANAGER_BIN" version 2>/dev/null || true)"
  installed_build_id="$("$MANAGER_BIN" _build-id 2>/dev/null || true)"
  [ "$installed_version" = "$MANAGER_VERSION" ] || die "Installed manager display-version self-check failed: expected $MANAGER_VERSION, got ${installed_version:-empty}."
  [ "$installed_build_id" = "$MANAGER_BUILD_ID" ] || die "Installed manager build-identity self-check failed."

  # Replace the public CLI link atomically so repair/update cannot leave a
  # missing /usr/local/bin/sbox if interrupted between rm and ln.
  cli_tmp="${CLI_BIN}.tmp.$$.$RANDOM"
  rm -f -- "$cli_tmp"
  ln -s "$MANAGER_BIN" "$cli_tmp"
  mv -Tf -- "$cli_tmp" "$CLI_BIN"
  [ "$(readlink -f "$CLI_BIN" 2>/dev/null || true)" = "$(readlink -f "$MANAGER_BIN" 2>/dev/null || true)" ] || die "sbox CLI link self-check failed."
}

write_cert_hook_content() {
  cat <<EOF
#!/usr/bin/env bash
# Managed by sbox-manager
set -euo pipefail
[ -n "\${RENEWED_LINEAGE:-}" ] || exit 0
if [ -n "\${SBOX_CERTBOT_PARENT_TRANSACTION:-}" ] && [ -s "$TXN_JOURNAL" ] && [ "\$SBOX_CERTBOT_PARENT_TRANSACTION" = "\$(jq -r '.snapshot // empty' "$TXN_JOURNAL")" ]; then
  exit 0
fi
exec "$MANAGER_BIN" _cert-deploy "\$RENEWED_LINEAGE"
EOF
}

write_systemd_units() {
  local dir service firewall hook hardening=''
  dir="$(mktemp -d "$RUNTIME_DIR/units.XXXXXX")"
  service="$dir/sing-box.service"; firewall="$dir/sbox-manager-firewall.service"; hook="$dir/cert-hook"
  # sing-box opens a netlink socket at startup (interface/route discovery), so
  # AF_NETLINK is required. Hosts where the core still cannot live with the
  # syscall filter can fall back to the previous proven unit with
  # SBOX_NO_SANDBOX=1.
  if [ "${SBOX_NO_SANDBOX:-0}" = 1 ]; then
    warn "SBOX_NO_SANDBOX=1: writing sing-box.service without the optional syscall/address-family hardening."
  else
    hardening="$(cat <<'HARDENING'
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
MemoryDenyWriteExecute=true
RemoveIPC=true
KeyringMode=private
HARDENING
)"
  fi
  cat > "$service" <<EOF
[Unit]
Description=sing-box managed by sbox-manager
Documentation=https://sing-box.sagernet.org/
After=network-online.target sbox-manager-firewall.service
Wants=network-online.target sbox-manager-firewall.service
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=exec
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStartPre=$SBOX_BIN check -c $CONFIG_FILE
# Allow TCP Fast Open on listeners that request it (server bit 0x2); never lowers the admin value.
ExecStartPre=+/bin/sh -c 'v=\$\$(/usr/sbin/sysctl -n net.ipv4.tcp_fastopen 2>/dev/null) && /usr/sbin/sysctl -qw net.ipv4.tcp_fastopen=\$\$((v | 2)) || true'
ExecStart=$SBOX_BIN run -c $CONFIG_FILE
Restart=always
RestartSec=2s
TimeoutStartSec=30s
TimeoutStopSec=15s
LimitNOFILE=1048576
TasksMax=infinity
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
$hardening
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200

[Install]
WantedBy=multi-user.target
EOF
  cat > "$firewall" <<EOF
[Unit]
Description=sbox-manager firewall allow and Hysteria2 port-hop rules
Before=sing-box.service
After=local-fs.target network-pre.target ufw.service netfilter-persistent.service nftables.service fail2ban.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=oneshot
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$MANAGER_BIN _firewall-apply
RemainAfterExit=yes
TimeoutStartSec=60s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
  write_cert_hook_content > "$hook"
  chmod 0755 "$hook"
  if command -v systemd-analyze >/dev/null 2>&1; then
    if ! systemd-analyze verify "$service" "$firewall" > "$dir/verify.log" 2>&1; then
      cat "$dir/verify.log" >&2
      die "Generated systemd units failed validation."
    fi
  fi
  atomic_install "$service" "$SERVICE_FILE" 0644 root root
  atomic_install "$firewall" "$FIREWALL_SERVICE_FILE" 0644 root root
  install -d -m 0755 "$(dirname "$CERT_HOOK_FILE")"
  atomic_install "$hook" "$CERT_HOOK_FILE" 0755 root root
  rm -rf "$dir"
}

# Snapshot the live values of the keys we may change, once, before the first
# change. The file is the ground truth for reverting runtime tuning.
capture_sysctl_baseline() {
  [ -s "$SYSCTL_BASELINE_FILE" ] && return 0
  install -d -m 0755 "$(dirname "$SYSCTL_BASELINE_FILE")"
  local key val tmp
  tmp="$(mktemp "$(dirname "$SYSCTL_BASELINE_FILE")/.baseline.XXXXXX")"
  {
    echo '# sbox-manager - pre-tuning runtime sysctl baseline (do not edit)'
    for key in "${MANAGED_SYSCTLS[@]}"; do
      val="$(sysctl -n "$key" 2>/dev/null)" || continue
      [ -n "$val" ] && printf '%s = %s\n' "$key" "$val"
    done
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$SYSCTL_BASELINE_FILE"
  durable_paths "$SYSCTL_BASELINE_FILE" "$(dirname "$SYSCTL_BASELINE_FILE")"
}

# Revert the managed keys to their captured pristine values.
restore_sysctl_baseline() {
  local mode="${1:-explicit}" line key val current managed failed=0
  [ -s "$SYSCTL_BASELINE_FILE" ] || { warn "No captured sysctl baseline; no kernel values changed."; return 0; }
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%% = *}"; val="${line#* = }"
    [ -n "$key" ] && [ "$key" != "$line" ] || { failed=1; continue; }
    current="$(sysctl -n "$key" 2>/dev/null)" || { warn "Cannot read baseline key: $key"; failed=1; continue; }
    if [ "$mode" = managed ]; then
      managed="$(awk -F ' = ' -v key="$key" '$1==key {print $2}' "$SYSCTL_FILE")"
      # Only undo values still attributable to our managed profile. A later
      # administrator override belongs to its administrator, even on uninstall.
      [ -n "$managed" ] && [ "$current" = "$managed" ] || continue
    fi
    [ "$current" = "$val" ] && continue
    if ! sysctl -w "$key=$val" >/dev/null 2>&1; then warn "Could not restore captured sysctl: $key"; failed=1; fi
  done < "$SYSCTL_BASELINE_FILE"
  return "$failed"
}


# 1.8.0 D5: net.core.default_qdisc only applies to qdiscs created *after* it is
# set. Physical/virtio NICs are created at boot before sysctl runs, so the root
# qdisc stayed pfifo_fast (single queue) or mq+pfifo_fast (multi-queue) on live
# hosts although tuning requested fq. Attach the requested qdisc explicitly.
# Best effort: never fails a transaction; reports what it did. Only physical
# devices (with a /device link) are touched; lo/veth/tun/wg/bridges are not.
apply_egress_qdisc() {
  local want dev n i sysnet="${SBOX_SYS_NET:-/sys/class/net}" devices kind
  want="${SBOX_QDISC_WANT:-$(sysctl -n net.core.default_qdisc 2>/dev/null || true)}"
  case "$want" in fq|fq_codel|cake) ;; *) return 0 ;; esac
  command -v tc >/dev/null 2>&1 || { warn "tc is unavailable; ${want} qdisc not attached."; return 0; }
  if [ -n "${SBOX_QDISC_DEVICES:-}" ]; then devices="$SBOX_QDISC_DEVICES"
  else
    devices=''
    for dev in "$sysnet"/*; do
      [ -e "$dev/device" ] || continue
      devices="$devices ${dev##*/}"
    done
  fi
  for dev in $devices; do
    case "$dev" in ''|*[!A-Za-z0-9_.:@-]*) continue ;; esac
    n="$(find "$sysnet/$dev/queues" -maxdepth 1 -name 'tx-*' 2>/dev/null | wc -l)"
    kind="$(tc qdisc show dev "$dev" root 2>/dev/null | awk 'NR==1{print $2}')"
    if [ "${n:-0}" -le 1 ]; then
      [ "$kind" = "$want" ] && continue
      tc qdisc replace dev "$dev" root "$want" 2>/dev/null || { warn "Could not attach $want on $dev."; continue; }
    else
      tc qdisc replace dev "$dev" root handle 1: mq 2>/dev/null || { warn "Could not attach mq on $dev."; continue; }
      for i in $(seq 1 "$n"); do
        tc qdisc replace dev "$dev" parent "1:$(printf '%x' "$i")" "$want" 2>/dev/null || warn "Could not attach $want on $dev tx-$((i-1))."
      done
    fi
    echo "qdisc: $dev -> $want ($n tx queue(s))" >&2
  done
  return 0
}

apply_tuning() {
  local state="$1" enabled bbr=false tmp line key val current failed=0 explicit="${SBOX_TUNING_EXPLICIT:-false}"
  enabled="$(jq -r '.tuning.enabled' "$state")"
  if [ "$enabled" != true ]; then
    if [ -f "$SYSCTL_FILE" ]; then
      manager_owned_file "$SYSCTL_FILE" || { warn "Refusing to alter foreign sysctl file: $SYSCTL_FILE"; return 1; }
      if [ "$explicit" = true ]; then restore_sysctl_baseline explicit || failed=1
      else restore_sysctl_baseline managed || failed=1; fi
      # Failed keys must remain identifiable for a later repair/retry.
      if [ "$failed" -eq 0 ]; then rm -f "$SYSCTL_FILE" || return 1; durable_paths "$(dirname "$SYSCTL_FILE")" || return 1; fi
    elif [ "$explicit" = true ]; then restore_sysctl_baseline explicit || failed=1
    fi
    if [ "$failed" -ne 0 ]; then
      warn "Some tuning keys could not be restored; VPN configuration can proceed. Retry explicit performance apply baseline after correcting host restrictions."
      [ "$explicit" != true ] || return 1
    fi
    return 0
  fi
  # Ordinary full operations preserve both persistent and administrator-adjusted
  # live values. An explicit performance apply legacy deliberately reapplies.
  if [ -f "$SYSCTL_FILE" ] && [ "$explicit" != true ]; then apply_egress_qdisc; return 0; fi
  capture_sysctl_baseline || return 1
  modprobe tcp_bbr 2>/dev/null || true
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr ' ' '
' | grep -qx bbr; then
    bbr=true
  else
    warn "TCP BBR is unavailable on this kernel; applying only safe socket/queue tuning."
  fi
  tmp="$(mktemp "$RUNTIME_DIR/sysctl.XXXXXX")"
  {
    echo '# Managed by sbox-manager - legacy opt-in tuning (not a measured universal optimum)'
    [ "$bbr" = true ] && {
      echo 'net.core.default_qdisc = fq'
      echo 'net.ipv4.tcp_congestion_control = bbr'
    }
    cat <<'EOF'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF
  } > "$tmp"
  atomic_install "$tmp" "$SYSCTL_FILE" 0644 root root
  rm -f -- "$tmp"
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%% = *}"; val="${line#* = }"
    current="$(sysctl -n "$key" 2>/dev/null)" || { warn "Unsupported tuning key: $key"; failed=1; continue; }
    [ "$current" = "$val" ] && continue
    sysctl -w "$key=$val" >/dev/null 2>&1 || { warn "Cannot apply tuning key: $key"; failed=1; }
  done < "$SYSCTL_FILE"
  apply_egress_qdisc
  if [ "$failed" -ne 0 ]; then warn "Some requested tuning keys are unavailable; inspect performance report."; [ "$explicit" != true ] || return 1; fi
  return 0
}

firewall_assert_owned_family() {
  local tool="$1" rules line
  command -v "$tool" >/dev/null 2>&1 || return 0
  rules="$("$tool" -w -S SBOX_INPUT 2>/dev/null)" || rules=''
  if [ -n "$rules" ]; then
    state_exists || [ "${SBOX_FIREWALL_RECOVERY:-false}" = true ] || die "Reserved firewall chain exists without installed state: SBOX_INPUT"
    while IFS= read -r line; do
      case "$line" in '-N SBOX_INPUT'|'-A SBOX_INPUT -j RETURN') ;;
        '-A SBOX_INPUT '*--comment*sbox:*' -j ACCEPT') ;;
        *) die "Foreign rule in SBOX_INPUT; refusing to flush it." ;;
      esac
    done <<< "$rules"
  fi
  rules="$("$tool" -w -t nat -S SBOX_NAT 2>/dev/null)" || rules=''
  if [ -n "$rules" ]; then
    state_exists || [ "${SBOX_FIREWALL_RECOVERY:-false}" = true ] || die "Reserved NAT chain exists without installed state: SBOX_NAT"
    while IFS= read -r line; do
      case "$line" in '-N SBOX_NAT') ;;
        '-A SBOX_NAT -p udp '*--dport*' -j REDIRECT --to-ports '*) ;;
        *) die "Foreign rule in SBOX_NAT; refusing to flush it." ;;
      esac
    done <<< "$rules"
  fi
}

firewall_remove_family() {
  local tool="$1"
  firewall_assert_owned_family "$tool"
  command -v "$tool" >/dev/null 2>&1 || return 0
  while "$tool" -w -C INPUT -j SBOX_INPUT 2>/dev/null; do "$tool" -w -D INPUT -j SBOX_INPUT 2>/dev/null || break; done
  "$tool" -w -F SBOX_INPUT 2>/dev/null || true
  "$tool" -w -X SBOX_INPUT 2>/dev/null || true
  while "$tool" -w -t nat -C PREROUTING -j SBOX_NAT 2>/dev/null; do "$tool" -w -t nat -D PREROUTING -j SBOX_NAT 2>/dev/null || break; done
  "$tool" -w -t nat -F SBOX_NAT 2>/dev/null || true
  "$tool" -w -t nat -X SBOX_NAT 2>/dev/null || true
}

firewall_remove_all() {
  firewall_remove_family iptables
  firewall_remove_family ip6tables
}

firewall_apply_family() {
  local tool="$1" state="$2" name proto port range start end main cert_mode tmp restore
  firewall_assert_owned_family "$tool"
  restore="${tool}-restore"
  command -v "$restore" >/dev/null || die "Required firewall transaction tool missing: $restore"
  tmp="$(mktemp "$RUNTIME_DIR/firewall-rules.XXXXXX")"
  range="$(jq -r 'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end' "$state")"
  cert_mode="$(jq -r '.certificate.mode' "$state")"
  {
    echo '*filter'
    echo ':SBOX_INPUT - [0:0]'
    echo '-F SBOX_INPUT'
    if ! "$tool" -w -C INPUT -j SBOX_INPUT 2>/dev/null; then echo '-I INPUT 1 -j SBOX_INPUT'; fi
    while IFS=$'\t' read -r name proto port; do
      [ -n "$name" ] || continue
      printf -- '-A SBOX_INPUT -p %s --dport %s -m comment --comment sbox:%s -j ACCEPT\n' "$proto" "$port" "$name"
    done < <(enabled_transport_rows "$state")
    if [ "$cert_mode" = certbot-http01 ]; then echo '-A SBOX_INPUT -p tcp --dport 80 -m comment --comment sbox:http01 -j ACCEPT'; fi
    if [ -n "$range" ]; then
      printf -- '-A SBOX_INPUT -p udp --dport %s -m comment --comment sbox:hy2-hop -j ACCEPT\n' "$range"
    fi
    echo '-A SBOX_INPUT -j RETURN'
    echo COMMIT
  } > "$tmp"
  "$restore" -w 10 --noflush --test < "$tmp" || { rm -f "$tmp"; return 1; }
  "$restore" -w 10 --noflush < "$tmp" || { rm -f "$tmp"; return 1; }
  if [ -n "$range" ]; then
    main="$(jq -r '.protocols.hy2.port' "$state")"
    {
      echo '*nat'; echo ':SBOX_NAT - [0:0]'; echo '-F SBOX_NAT'
      if ! "$tool" -w -t nat -C PREROUTING -j SBOX_NAT 2>/dev/null; then echo '-I PREROUTING 1 -j SBOX_NAT'; fi
      printf -- '-A SBOX_NAT -p udp --dport %s -m addrtype --dst-type LOCAL -j REDIRECT --to-ports %s\n' "$range" "$main"
      echo COMMIT
    } > "$tmp"
    "$restore" -w 10 --noflush --test < "$tmp" && "$restore" -w 10 --noflush < "$tmp" || { rm -f "$tmp"; return 1; }
  elif "$tool" -w -t nat -S SBOX_NAT >/dev/null 2>&1; then
    # Removing the obsolete owned NAT path never removes the live allow chain.
    while "$tool" -w -t nat -C PREROUTING -j SBOX_NAT 2>/dev/null; do "$tool" -w -t nat -D PREROUTING -j SBOX_NAT; done
    "$tool" -w -t nat -F SBOX_NAT
    "$tool" -w -t nat -X SBOX_NAT
  fi
  rm -f "$tmp"
}

firewall_preflight_file() {
  local state="$1" listen mode
  firewall_assert_owned_family iptables
  firewall_assert_owned_family ip6tables
  if [ "$(jq -r '.firewall.enabled' "$state")" = true ]; then
    iptables -w -S INPUT >/dev/null || die "IPv4 firewall access unavailable; no runtime change applied."
    listen="$(jq -r '.server.listen' "$state")"
    mode="$(jq -r '.certificate.mode' "$state")"
    if { [[ "$listen" = *:* ]] || [ "$mode" = certbot-http01 ]; } && ipv6_available; then
      ip6tables -w -S INPUT >/dev/null || die "IPv6 firewall access unavailable; no runtime change applied."
    fi
  fi
}

firewall_apply_file() {
  local state="$1" enabled listen cert_mode need_v6=false
  firewall_preflight_file "$state" || return 1
  enabled="$(jq -r '.firewall.enabled' "$state")"; listen="$(jq -r '.server.listen' "$state")"; cert_mode="$(jq -r '.certificate.mode' "$state")"
  if [ "$enabled" != true ]; then firewall_remove_all || return 1
  else
    firewall_apply_family iptables "$state" || return 1
    [[ "$listen" = *:* ]] && need_v6=true
    [ "$cert_mode" = certbot-http01 ] && need_v6=true
    if [ "$need_v6" = true ] && ipv6_available; then firewall_apply_family ip6tables "$state" || return 1
    else firewall_remove_family ip6tables || return 1; fi
  fi
  # Early inet drops are independent of these allow/NAT transactions. A failed
  # ban-list read leaves the live guard and its addresses intact. Boot readiness
  # races must not withhold VPN allow rules or Hysteria2 redirect rules.
  security_reconcile_optional
  # UFW reload can remove the narrow panel INPUT hook while its persistent
  # user-chain allow remains. Restore the declared panel rule before the
  # hardening collector mirrors live INPUT ports; never mirror foreign ports.
  if declare -F webui_firewall_reconcile >/dev/null; then
    webui_firewall_reconcile || return 1
  fi
  hardening_reconcile_file "$state"
  return 0
}


security_is_configured() {
  local path
  for path in /etc/fail2ban/jail.d/sbox-manager.local /etc/fail2ban/action.d/sbox-manager.conf /usr/local/lib/sbox-manager-security/action "$BASE_DIR/security.json"; do
    if [ -e "$path" ] || [ -L "$path" ]; then return 0; fi
  done
  return 1
}
security_apply_mode() {
  if security_is_configured; then echo preserve
  elif ! state_exists || [ "${SBOX_INITIALIZE_SECURITY:-false}" = true ]; then echo initialize
  else echo pending; fi
}
security_preflight_for_apply() {
  case "$1" in
    initialize|preserve) security_run preflight || die "Security preflight failed; read the SECURITY ERROR above for the command, exit status and stderr. No runtime commit begun." ;;
    pending) warn "SSH protection setup pending; existing VPN operation preserved. Run sbox security setup explicitly (installs dependencies)." ;;
    *) die "Unknown security transition." ;;
  esac
}
security_reconcile_optional() {
  if security_is_configured; then
    if ! security_run reconcile; then
      warn "SECURITY DEGRADED: Fail2Ban reconciliation failed; existing early guard/bans retained. VPN allow/NAT rules applied. Run sbox security status and security repair."
    fi
  fi
  return 0
}

firewall_rules_healthy() {
  local state="$1" enabled name proto port range start end main tool listen cert_mode need_v6=false
  enabled="$(jq -r '.firewall.enabled' "$state")"
  [ "$enabled" = true ] || return 0
  listen="$(jq -r '.server.listen' "$state")"; cert_mode="$(jq -r '.certificate.mode' "$state")"
  local -a tools=(iptables)
  [[ "$listen" = *:* ]] && need_v6=true
  [ "$cert_mode" = certbot-http01 ] && need_v6=true
  [ "$need_v6" = true ] && ipv6_available && tools+=(ip6tables)
  for tool in "${tools[@]}"; do
    "$tool" -w -C INPUT -j SBOX_INPUT >/dev/null 2>&1 || return 1
    while IFS=$'	' read -r name proto port; do
      [ -n "$name" ] || continue
      "$tool" -w -C SBOX_INPUT -p "$proto" --dport "$port" -m comment --comment "sbox:$name" -j ACCEPT >/dev/null 2>&1 || return 1
    done < <(enabled_transport_rows "$state")
    if [ "$cert_mode" = certbot-http01 ]; then
      "$tool" -w -C SBOX_INPUT -p tcp --dport 80 -m comment --comment sbox:http01 -j ACCEPT >/dev/null 2>&1 || return 1
    fi
  done
  range="$(jq -r 'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end' "$state")"
  if [ -n "$range" ]; then
    start="${range%%:*}"; end="${range##*:}"; main="$(jq -r '.protocols.hy2.port' "$state")"
    for tool in "${tools[@]}"; do
      "$tool" -w -t nat -C PREROUTING -j SBOX_NAT >/dev/null 2>&1 || return 1
      "$tool" -w -C SBOX_INPUT -p udp --dport "$start:$end" -m comment --comment sbox:hy2-hop -j ACCEPT >/dev/null 2>&1 || return 1
      "$tool" -w -t nat -C SBOX_NAT -p udp --dport "$start:$end" -m addrtype --dst-type LOCAL -j REDIRECT --to-ports "$main" >/dev/null 2>&1 || return 1
    done
  fi
}

print_required_ports() {
  local state="$1" format="${2:-text}" range rows
  rows="$(enabled_transport_rows "$state")"
  range="$(jq -r 'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end' "$state")"
  if [ "$format" = json ]; then
    jq -n --argjson protocols "$(jq '[.protocols|to_entries[]|select(.value.enabled)|{name:.key,protocol:(if (.key=="hy2" or .key=="tuic") then "udp" else "tcp" end),port:.value.port}]' "$state")" --arg range "$range" \
      '{protocol_ports:$protocols,hysteria2_hop_range:(if $range=="" then null else {protocol:"udp",range:$range} end)}'
    return 0
  fi
  echo "Required VPS/provider inbound ports:"
  while IFS=$'\t' read -r name proto port; do [ -n "$name" ] && printf '  %-10s %s/%s\n' "$name" "$port" "$proto"; done <<< "$rows"
  [ -z "$range" ] || printf '  %-10s %s/udp (port hopping)\n' hy2-range "$range"
  if [ "$(jq -r '.certificate.mode' "$state")" = certbot-http01 ]; then
    printf '  %-10s 80/tcp (certificate issue/renewal)\n' http01
  fi
}

listener_present() {
  local port="$1" proto="$2"
  if [ "$proto" = tcp ]; then
    ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
  else
    ss -H -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
  fi
}

singbox_main_pid() {
  local pid
  pid="$(systemctl show -p MainPID --value sing-box.service 2>/dev/null || echo 0)"
  [[ "$pid" =~ ^[0-9]+$ ]] || pid=0
  printf '%s\n' "$pid"
}

# A port being "in LISTEN" is not proof that *sing-box* is serving it: any other
# process (or a leftover from a conflicting unit) could own it. Confirm the
# listening socket belongs to the running sing-box MainPID. Missing PID fails
# closed rather than accepting another process merely named sing-box.
listener_owned_by_singbox() {
  local port="$1" proto="$2" pid="${3:-}" flag socket_line
  [ -n "$pid" ] || pid="$(singbox_main_pid)"
  if [ "$proto" = tcp ]; then flag=-lntp; else flag=-lnup; fi
  socket_line="$(ss -H "$flag" 2>/dev/null | awk -v p="$port" '$4 ~ ("(^|:)" p "$")')"
  [ -n "$socket_line" ] || return 1
  if [ "$pid" != 0 ]; then
    printf '%s\n' "$socket_line" | grep -q "pid=${pid}," && return 0
    return 1
  fi
  return 1 # No MainPID means ownership cannot be established.
}

check_expected_listeners() {
  local state="$1" tries="${2:-15}" i name proto port missing pid
  for ((i=1;i<=tries;i++)); do
    missing=0
    pid="$(singbox_main_pid)"
    while IFS=$'\t' read -r name proto port; do
      [ -n "$name" ] || continue
      listener_owned_by_singbox "$port" "$proto" "$pid" || missing=$((missing+1))
    done < <(enabled_transport_rows "$state")
    [ "$missing" -eq 0 ] && return 0
    systemctl is-failed --quiet sing-box.service 2>/dev/null && return 1
    sleep 1
  done
  return 1
}

service_stable() {
  local first_pid first_restarts second_pid second_restarts
  first_pid="$(systemctl show -p MainPID --value sing-box.service 2>/dev/null || true)"
  first_restarts="$(systemctl show -p NRestarts --value sing-box.service 2>/dev/null || true)"
  sleep 2
  systemctl is-active --quiet sing-box.service || return 1
  second_pid="$(systemctl show -p MainPID --value sing-box.service 2>/dev/null || true)"
  second_restarts="$(systemctl show -p NRestarts --value sing-box.service 2>/dev/null || true)"
  [[ "$first_pid" =~ ^[1-9][0-9]*$ ]] && [ "$first_pid" = "$second_pid" ] && [ "$first_restarts" = "$second_restarts" ]
}

# Durability boundaries: fsync payloads before publishing pointers, and fsync
# parent directories after renames/unlinks. Failure is never silently ignored.
durable_paths() {
  python3 - "$@" <<'PYDURABLE'
import os, sys
from pathlib import Path
for raw in sys.argv[1:]:
    p=Path(raw)
    if p.is_symlink(): p=p.parent
    fd=os.open(str(p), os.O_RDONLY | (os.O_DIRECTORY if p.is_dir() else 0))
    try: os.fsync(fd)
    finally: os.close(fd)
PYDURABLE
}

firewall_owned_dump() {
  local tool table chain
  for tool in iptables ip6tables; do
    for table in filter nat; do
      if [ "$table" = filter ]; then chain=SBOX_INPUT; else chain=SBOX_NAT; fi
      printf '# %s %s
' "$tool" "$table"
      "$tool" -w -t "$table" -S "$chain" 2>/dev/null || true
    done
  done
}

capture_recovery_expectations() {
  local snap="$1" key val
  firewall_owned_dump > "$snap/firewall-before.txt"
  singbox_main_pid > "$snap/service-pid-before.txt"
  local tool
  for tool in iptables ip6tables; do
    if "$tool" -w -C INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT 2>/dev/null; then touch "$snap/http01-$tool"; fi
  done
  : > "$snap/sysctl-before.txt"
  for key in "${MANAGED_SYSCTLS[@]}"; do
    val="$(sysctl -n "$key" 2>/dev/null)" || continue
    printf '%s = %s\n' "$key" "$val" >> "$snap/sysctl-before.txt"
  done
}

runtime_snapshot_tool() {
  python3 - "$@" <<'PYSNAPSHOT'
import hashlib,json,os,stat,sys
from pathlib import Path
action=sys.argv[1]; root=Path(sys.argv[2])
def inventory(root):
    rows={}
    if root.is_symlink() or not root.is_dir(): raise SystemExit('snapshot must be a regular directory')
    for p in sorted(root.rglob('*')):
        rel=str(p.relative_to(root))
        if rel in {'.snapshot-complete','snapshot-hashes.json'}:continue
        st=p.lstat(); row={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
        if p.is_symlink():row.update(type='link',target=os.readlink(p))
        elif p.is_file():row.update(type='file',sha256=hashlib.sha256(p.read_bytes()).hexdigest())
        elif p.is_dir():row.update(type='dir')
        else:raise SystemExit('unsupported snapshot object: '+rel)
        rows[rel]=row
    return rows
if action=='seal':
    rows=inventory(root)
    f=root/'snapshot-hashes.json'; f.write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n');f.chmod(0o600)
    for p in root.rglob('*'):
        if p.is_file() and not p.is_symlink():
            with p.open('rb') as stream:os.fsync(stream.fileno())
    for p in sorted(root.rglob('*'),reverse=True):
        if p.is_dir() and not p.is_symlink():
            fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
elif action=='validate':
    f=root/'snapshot-hashes.json'
    if f.is_symlink() or not f.is_file():raise SystemExit('snapshot integrity manifest missing; assisted recovery required')
    if json.loads(f.read_text())!=inventory(root):raise SystemExit('snapshot integrity mismatch; evidence retained')
elif action=='compare':
@@SNAPSHOT_COMPARE@@
else:raise SystemExit('invalid snapshot action')
PYSNAPSHOT
}
seal_runtime_snapshot() { runtime_snapshot_tool seal "$1"; }
validate_runtime_snapshot() {
  local snap="$1"
  [ ! -L "$snap" ] && [ "$(dirname "$(readlink -f "$snap")")" = "$(readlink -f "$TXN_SNAPSHOT_DIR")" ] || return 1
  runtime_snapshot_tool validate "$snap"
}

verify_restored_runtime() {
  local snap="$1" phase="${2:-commit}" entry path name unit prefix expected actual line key val cert keyfile
  # Absence is an explicit legitimate pre-install state. Prepared certificate
  # material must not leave a half-install that blocks the next installation.
  if [ ! -e "$snap/had-state" ] && [ ! -e "$snap/had-service" ]; then
    for entry in "$BASE_DIR:base" "$LIB_DIR:lib"; do
      path="${entry%%:*}"; name="${entry##*:}"
      if [ "$phase" = prepare ] && [ -e "$snap/had-$name" ]; then runtime_snapshot_tool compare "$snap/$name" "$path" || return 1
      else [ ! -e "$path" ] && [ ! -L "$path" ] || return 1; fi
    done
    for path in "$STATE_FILE" "$CONFIG_FILE" "$CLI_BIN" "$SERVICE_FILE" "$FIREWALL_SERVICE_FILE"; do
      [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
    done
  else
    state_exists || return 1
    state_tool_ro validate "$STATE_FILE" || return 1
    runtime_snapshot_tool compare "$snap/base" "$BASE_DIR" "${3:-strict}" || return 1
    runtime_snapshot_tool compare "$snap/lib" "$LIB_DIR" || return 1
    [ -x "$SBOX_BIN" ] || return 1
    "$SBOX_BIN" check -c "$CONFIG_FILE" || return 1
    if state_needs_certificate "$STATE_FILE"; then
      resolve_service_certificate || return 1
      cert_valid_now "$EFFECTIVE_CERT" || return 1
      cert_matches_domain "$EFFECTIVE_CERT" "$(jq -r '.domain' "$STATE_FILE")" || return 1
    fi
    firewall_rules_healthy "$STATE_FILE" || return 1
  fi
  for entry in "$SERVICE_FILE:service" "$FIREWALL_SERVICE_FILE:firewall" "$OLD_WATCHDOG_SERVICE:old-watchdog-service" "$OLD_WATCHDOG_TIMER:old-watchdog-timer" "$CERT_HOOK_FILE:cert-hook" "$SYSCTL_FILE:sysctl" "$CLI_BIN:cli" \
    "$FALLBACK_WEB_SERVICE_FILE:fallback-web-service" \
    "/etc/fail2ban/jail.d/sbox-manager.local:security-jail" "/etc/fail2ban/action.d/sbox-manager.conf:security-action" \
    "/usr/local/lib/sbox-manager-security/action:security-program"; do
    path="${entry%%:*}"; name="${entry##*:}"
    if [ -e "$snap/had-$name" ]; then
      if [ -L "$snap/files/$name" ]; then
        [ -L "$path" ] && [ "$(readlink "$path")" = "$(readlink "$snap/files/$name")" ] || return 1
      else
        [ -f "$path" ] && [ ! -L "$path" ] && cmp -s "$snap/files/$name" "$path" || return 1
      fi
    else
      [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
    fi
  done
  for entry in sing-box.service:service sbox-manager-firewall.service:firewall; do
    unit="${entry%%:*}"; prefix="${entry##*:}"
    if [ -s "$snap/$prefix-enablement" ]; then
      [ "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = "$(cat "$snap/$prefix-enablement")" ] || return 1
    fi
    if [ -e "$snap/$prefix-enabled" ]; then systemctl is-enabled --quiet "$unit" || return 1
    else systemctl is-enabled --quiet "$unit" && return 1; fi
    if [ -e "$snap/$prefix-active" ]; then systemctl is-active --quiet "$unit" || return 1
    else systemctl is-active --quiet "$unit" && return 1; fi
  done
  if [ -e "$snap/fallback-web-active" ]; then systemctl is-active --quiet "$FALLBACK_WEB_UNIT" || return 1
  elif [ -e "$FALLBACK_WEB_SERVICE_FILE" ]; then systemctl is-active --quiet "$FALLBACK_WEB_UNIT" && return 1; fi
  if [ -e "$snap/service-active" ]; then
    check_expected_listeners "$STATE_FILE" 3 && service_stable || return 1
  fi
  if [ -f "$snap/firewall-before.txt" ]; then
    actual="$(firewall_owned_dump)"; expected="$(cat "$snap/firewall-before.txt")"
    [ "$actual" = "$expected" ] || return 1
  fi
  if [ -f "$snap/sysctl-before.txt" ]; then
    while IFS= read -r line; do
      key="${line%% = *}"; val="${line#* = }"
      actual="$(sysctl -n "$key" 2>/dev/null)" || return 1
      [ "$actual" = "$val" ] || return 1
    done < "$snap/sysctl-before.txt"
  fi
  if [ "$phase" = commit ] && [ -e "$snap/had-security-jail" ]; then
    # Use the restored trusted action, including when the snapshot predates
    # this release. A degraded security restore must keep its recovery evidence.
    /usr/local/lib/sbox-manager-security/action status >/dev/null || return 1
  fi
  return 0
}

# The snapshot predates certificate materialisation, including fresh install.
# A failure anywhere before apply_candidate commits is recoverable too.
apply_planned_candidate() (
  set -Eeuo pipefail
  local state="$1" binary="$2" reason="$3" plan="$4" snap mode
  acquire_lock; guard_no_pending_transaction
  firewall_preflight_file "$state"
  mode="$(security_apply_mode)"; security_preflight_for_apply "$mode"
  assert_candidate_ports_free "$state"
  install -d -m 0700 "$TXN_SNAPSHOT_DIR"
  snap="$(mktemp -d "$TXN_SNAPSHOT_DIR/prepared.XXXXXXXX")"
  SBOX_CERT_PREPARE_PLAN="$plan" snapshot_runtime "$snap"
  write_txn_journal "$snap" "$reason" prepare
  SBOX_PREPARED_SNAPSHOT="$snap"; SBOX_ROLLBACK_ATTEMPTED=false
  trap 'rc=$?; if [ "$rc" -ne 0 ] && transaction_in_progress && [ "$SBOX_ROLLBACK_ATTEMPTED" != true ]; then if rollback_transaction_verified "$SBOX_PREPARED_SNAPSHOT"; then clear_txn_journal; rm -rf -- "$SBOX_PREPARED_SNAPSHOT"; else warn "Rollback incomplete; journal and snapshot retained."; fi; fi; exit "$rc"' EXIT
  trap 'exit 143' TERM HUP
  trap 'exit 130' INT
  materialize_certificate_plan "$plan"
  apply_candidate "$state" "$binary" "$reason"
)

snapshot_runtime() {
  local snap="$1" path name
  install -d -m 0700 "$snap/files"
  [ -d "$BASE_DIR" ] && { cp -a "$BASE_DIR" "$snap/base"; touch "$snap/had-base"; }
  [ -d "$LIB_DIR" ] && { cp -a "$LIB_DIR" "$snap/lib"; touch "$snap/had-lib"; }
  for entry in \
    "$SERVICE_FILE:service" "$FIREWALL_SERVICE_FILE:firewall" "$OLD_WATCHDOG_SERVICE:old-watchdog-service" \
    "$OLD_WATCHDOG_TIMER:old-watchdog-timer" "$CERT_HOOK_FILE:cert-hook" "$SYSCTL_FILE:sysctl" "$CLI_BIN:cli" \
    "$FALLBACK_WEB_SERVICE_FILE:fallback-web-service" \
    "/etc/fail2ban/jail.d/sbox-manager.local:security-jail" "/etc/fail2ban/action.d/sbox-manager.conf:security-action" \
    "/usr/local/lib/sbox-manager-security/action:security-program"; do
    path="${entry%%:*}"; name="${entry##*:}"
    if [ -e "$path" ] || [ -L "$path" ]; then cp -a "$path" "$snap/files/$name"; touch "$snap/had-$name"; fi
  done
  state_exists && touch "$snap/had-state" || true
  systemctl is-active --quiet sing-box.service 2>/dev/null && touch "$snap/service-active" || true
  systemctl is-enabled --quiet sing-box.service 2>/dev/null && touch "$snap/service-enabled" || true
  systemctl is-active --quiet sbox-manager-firewall.service 2>/dev/null && touch "$snap/firewall-active" || true
  systemctl is-enabled --quiet sbox-manager-firewall.service 2>/dev/null && touch "$snap/firewall-enabled" || true
  systemctl is-active --quiet "$FALLBACK_WEB_UNIT" 2>/dev/null && touch "$snap/fallback-web-active" || true
  id "$SERVICE_USER" >/dev/null 2>&1 && touch "$snap/had-user" || true
  getent group "$SERVICE_GROUP" >/dev/null 2>&1 && touch "$snap/had-group" || true
  if [ -n "${SBOX_CERT_PREPARE_PLAN:-}" ]; then
    cp -a "$SBOX_CERT_PREPARE_PLAN" "$snap/certificate-plan.json"
    # Refuse to prepare over an existing self-signed target; only a newly
    # created target can be removed by preparation rollback.
    if [ "$(jq -r .method "$snap/certificate-plan.json")" = self-signed ]; then
      [ ! -e "$(jq -r .target "$snap/certificate-plan.json")" ] || die "Certificate preparation target already exists."
    fi
  fi
  for entry in sing-box.service:service sbox-manager-firewall.service:firewall "$FALLBACK_WEB_UNIT:fallback-web"; do
    path="${entry%%:*}"; name="${entry##*:}"
    systemctl is-enabled "$path" > "$snap/$name-enablement" 2>/dev/null || true
  done
  capture_recovery_expectations "$snap"
  seal_runtime_snapshot "$snap"
  sync 2>/dev/null || true
  # Completion marker written last: recover_command treats a snapshot without it
  # as incomplete and fails closed rather than restoring from a partial copy.
  touch "$snap/.snapshot-complete"
  durable_paths "$snap/.snapshot-complete" "$snap" "$(dirname "$snap")"
  sync 2>/dev/null || true
}

restore_path_from_snapshot() {
  local snap="$1" path="$2" name="$3"
  rm -rf -- "$path" || return 1
  if [ -e "$snap/had-$name" ]; then
    install -d -m 0755 "$(dirname "$path")" || return 1
    cp -a "$snap/files/$name" "$path" || return 1
  fi
  return 0
}


restore_runtime() (
  # Callers often use `if`/`||`, which disables errexit inside Bash functions.
  # Every recovery step has an explicit status; isolate helpers that call die
  # so neither exit nor an inherited ERR trap can skip essential service work.
  set +e; trap - ERR
  local snap="$1" SBOX_FIREWALL_RECOVERY=true failed=0 security_removed=true path name entry unit prefix line key val current
  validate_runtime_snapshot "$snap" || { warn "Invalid snapshot; live runtime untouched and evidence retained."; return 1; }
  restore_attempt() {
    local label="$1"; shift
    ( "$@" )
    if [ "$?" -ne 0 ]; then warn "Restore failed: $label"; failed=1; fi
    return 0
  }
  restore_tree() {
    rm -rf -- "$2" || return 1
    if [ -e "$snap/had-$1" ]; then cp -a "$snap/$1" "$2" || return 1; fi
    return 0
  }
  warn "Restoring the previous runtime; all essential recovery steps will be attempted..."
  if [ ! -e "$snap/had-security-jail" ] && security_is_configured; then
    ( security_run remove ) || { warn "Security cleanup failed; active guard/files retained for repair."; failed=1; security_removed=false; }
  fi
  for entry in "$SERVICE_FILE:sing-box.service" "$FIREWALL_SERVICE_FILE:sbox-manager-firewall.service" "$FALLBACK_WEB_SERVICE_FILE:$FALLBACK_WEB_UNIT"; do
    path="${entry%%:*}"; unit="${entry##*:}"
    if [ -e "$path" ] || [ -L "$path" ]; then restore_attempt "stop candidate $unit" systemctl stop "$unit"; fi
  done
  # Keep existing owned allow/NAT paths until their restored replacements are
  # installed atomically. An absent pre-install state instead removes our paths.
  if [ ! -e "$snap/had-state" ]; then restore_attempt 'remove candidate firewall' firewall_remove_all; fi
  restore_attempt 'temporary HTTP-01 rules' restore_http01_rules "$snap"
@@COLLECTOR_RESTORE_PAUSE@@
  restore_attempt 'base tree' restore_tree base "$BASE_DIR"
  restore_attempt 'manager tree' restore_tree lib "$LIB_DIR"
  if [ ! -e "$snap/had-state" ] && [ ! -e "$snap/had-service" ]; then restore_attempt 'fresh-install directory cleanup' rm -rf -- "$BASE_DIR" "$LIB_DIR"; fi
  for entry in "$SERVICE_FILE:service" "$FIREWALL_SERVICE_FILE:firewall" "$OLD_WATCHDOG_SERVICE:old-watchdog-service" "$OLD_WATCHDOG_TIMER:old-watchdog-timer" "$CERT_HOOK_FILE:cert-hook" "$SYSCTL_FILE:sysctl" "$CLI_BIN:cli" "$FALLBACK_WEB_SERVICE_FILE:fallback-web-service"; do
    path="${entry%%:*}"; name="${entry##*:}"
    restore_attempt "$name file" restore_path_from_snapshot "$snap" "$path" "$name"
  done
  if [ "$security_removed" = true ]; then
    for entry in /etc/fail2ban/jail.d/sbox-manager.local:security-jail /etc/fail2ban/action.d/sbox-manager.conf:security-action /usr/local/lib/sbox-manager-security/action:security-program; do
      path="${entry%%:*}"; name="${entry##*:}"
      restore_attempt "$name file" restore_path_from_snapshot "$snap" "$path" "$name"
    done
  fi
  if [ -e "$snap/had-security-jail" ]; then
    restore_attempt 'early guard' security_run start
    restore_attempt 'SSH jail reload' fail2ban-client reload sbox-sshd
    restore_attempt 'SSH ban reconciliation' security_run reconcile
  fi
  restore_attempt 'systemd reload' systemctl daemon-reload
  # Exact pre-transaction live values, not a stale original baseline. One failed
  # key never prevents later keys, firewall or either service from recovering.
  if [ -f "$snap/sysctl-before.txt" ]; then
    while IFS= read -r line; do
      key="${line%% = *}"; val="${line#* = }"
      current="$(sysctl -n "$key" 2>/dev/null)"
      if [ "$?" -ne 0 ]; then warn "Restore cannot read sysctl: $key"; failed=1; continue; fi
      [ "$current" = "$val" ] || restore_attempt "sysctl $key" sysctl -w "$key=$val"
    done < "$snap/sysctl-before.txt"
  else
    # Older sealed snapshots normally have this inventory; absence is not
    # permission to reset the rest of the host's kernel settings.
    warn "Snapshot has no live sysctl inventory; kernel restore cannot be verified."; failed=1
  fi
  if state_exists; then restore_attempt 'VPN allow/NAT rules' firewall_apply_file "$STATE_FILE"; fi
  for entry in sing-box.service:service sbox-manager-firewall.service:firewall; do
    unit="${entry%%:*}"; prefix="${entry##*:}"
    restore_attempt "$unit enablement" restore_unit_enablement "$snap" "$prefix" "$unit"
  done
  for entry in "$SERVICE_FILE:sing-box.service" "$FIREWALL_SERVICE_FILE:sbox-manager-firewall.service"; do
    path="${entry%%:*}"; unit="${entry##*:}"
    if [ -e "$path" ]; then restore_attempt "$unit failed-state reset" systemctl reset-failed "$unit"; fi
  done
  if [ -e "$snap/firewall-active" ]; then restore_attempt 'firewall service restart' systemctl restart sbox-manager-firewall.service
  elif [ -e "$FIREWALL_SERVICE_FILE" ]; then restore_attempt 'firewall inactive state' systemctl stop sbox-manager-firewall.service; fi
  # The website is restored before the VPN so REALITY never relays to nothing.
  if [ -e "$FALLBACK_WEB_SERVICE_FILE" ]; then
    restore_attempt "$FALLBACK_WEB_UNIT enablement" restore_unit_enablement "$snap" fallback-web "$FALLBACK_WEB_UNIT"
    restore_attempt "$FALLBACK_WEB_UNIT failed-state reset" systemctl reset-failed "$FALLBACK_WEB_UNIT"
    if [ -e "$snap/fallback-web-active" ]; then restore_attempt 'Personal Cloud website restart' systemctl restart "$FALLBACK_WEB_UNIT"
    else restore_attempt 'Personal Cloud website inactive state' systemctl stop "$FALLBACK_WEB_UNIT"; fi
  fi
  if [ -e "$snap/service-active" ]; then restore_attempt 'VPN service restart' systemctl restart sing-box.service
  elif [ -e "$SERVICE_FILE" ]; then restore_attempt 'VPN inactive state' systemctl stop sing-box.service; fi
  if [ ! -e "$snap/had-user" ] && id "$SERVICE_USER" >/dev/null 2>&1; then restore_attempt 'new service user cleanup' userdel "$SERVICE_USER"; fi
  if [ ! -e "$snap/had-group" ] && getent group "$SERVICE_GROUP" >/dev/null 2>&1; then restore_attempt 'new service group cleanup' groupdel "$SERVICE_GROUP"; fi
@@COLLECTOR_RESTORE_RESUME@@
  [ "$failed" -eq 0 ] || warn "Recovery completed its VPN attempts with failures; snapshot/journal must be retained."
  return "$failed"
)

restore_unit_enablement() {
  local snap="$1" prefix="$2" unit="$3" expected
  if [ -s "$snap/$prefix-enablement" ]; then
    expected="$(cat "$snap/$prefix-enablement")"
    case "$expected" in
      enabled) systemctl enable "$unit" || return 1 ;;
      enabled-runtime) systemctl disable "$unit" || return 1; systemctl enable --runtime "$unit" || return 1 ;;
      disabled) systemctl disable "$unit" || return 1 ;;
      masked|masked-runtime|not-found) : ;; # unit file snapshot restores masks/absence
      static|indirect|generated|transient|alias) systemctl disable "$unit" || return 1 ;;
      *) warn "Unknown saved unit enablement: $expected"; return 1 ;;
    esac
    [ "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = "$expected" ] || return 1
  elif [ -e "$snap/$prefix-enabled" ]; then systemctl enable "$unit" || return 1
  elif systemctl cat "$unit" >/dev/null 2>&1; then systemctl disable "$unit" || return 1
  fi
  return 0
}

restore_http01_rules() {
  local snap="$1" tool failed=0 present
  for tool in iptables ip6tables; do
    # Missing markers in old snapshots mean no pre-existing temporary rule.
    present=false
    "$tool" -w -C INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT 2>/dev/null && present=true
    if [ -e "$snap/http01-$tool" ]; then
      if [ "$present" != true ]; then "$tool" -w -I INPUT 1 -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT || failed=1; fi
    elif [ "$present" = true ]; then "$tool" -w -D INPUT -p tcp --dport 80 -m comment --comment sbox-manager-http01 -j ACCEPT || failed=1; fi
  done
  return "$failed"
}

restore_preparation() (
  set +e; trap - ERR
  local snap="$1" failed=0 target parent relative
  validate_runtime_snapshot "$snap" || return 1
  restore_path_from_snapshot "$snap" "$CERT_HOOK_FILE" cert-hook || failed=1
  restore_http01_rules "$snap" || failed=1
  if [ -f "$snap/certificate-plan.json" ] && [ "$(jq -r .method "$snap/certificate-plan.json")" = self-signed ]; then
    target="$(jq -r .target "$snap/certificate-plan.json")"
    case "$target" in "$CERT_SOURCE_DIR/self-signed/"*) ;;
      *) warn "Unsafe preparation target; evidence retained."; return 1 ;; esac
    relative="${target#"$BASE_DIR"/}"
    [ ! -e "$snap/base/$relative" ] || return 1
    rm -rf -- "$target" || failed=1
    parent="$(dirname "$target")"
    while [[ "$parent" == "$BASE_DIR"/* ]] || [ "$parent" = "$BASE_DIR" ]; do
      relative="${parent#"$BASE_DIR"/}"
      if [ "$parent" = "$BASE_DIR" ]; then [ ! -e "$snap/had-base" ] || break
      else [ ! -d "$snap/base/$relative" ] || break; fi
      [ ! -d "$parent" ] || rmdir -- "$parent" || { failed=1; break; }
      parent="$(dirname "$parent")"
    done
  fi
  # Publicly issued Certbot lineages and verified renewal credentials are kept;
  # preparation never deletes a valid external certificate or changes services.
  verify_restored_runtime "$snap" prepare || failed=1
  if [ -f "$snap/service-pid-before.txt" ]; then
    [ "$(singbox_main_pid)" = "$(cat "$snap/service-pid-before.txt")" ] || failed=1
  fi
  return "$failed"
)

rollback_transaction_verified() {
  local snap="$1" phase rc=0
  phase="$(jq -r '.phase // "commit"' "$TXN_JOURNAL")" || return 1
  case "$phase" in
    prepare) restore_preparation "$snap" || rc=1 ;;
    commit)
      restore_runtime "$snap" || rc=1
      # Verification still runs after a failed restore. Neither a successful
      # verifier nor a later success may erase the earlier failure status.
      verify_restored_runtime "$snap" || rc=1 ;;
    *) warn "Unknown transaction phase; evidence retained."; rc=1 ;;
  esac
  return "$rc"
}

cleanup_old_artifacts() {
  systemctl disable --now sbox-manager-watchdog.timer sbox-manager-watchdog.service >/dev/null 2>&1 || true
  rm -f "$OLD_WATCHDOG_SERVICE" "$OLD_WATCHDOG_TIMER"
  local path
  for path in /usr/local/sbin/sbox-manager /usr/local/bin/sb /usr/local/bin/sbox-status /usr/local/bin/sbox-doctor /usr/local/bin/sbox-url /usr/local/bin/sbox-qr /usr/local/bin/sbox-logs /usr/local/bin/sbox-repair; do
    if [ -L "$path" ]; then
      case "$(readlink -f "$path" 2>/dev/null || true)" in "$MANAGER_BIN"|"/usr/local/sbin/sbox-manager") rm -f "$path" ;; esac
    elif manager_owned_file "$path"; then
      rm -f "$path"
    fi
  done
}

# The journal is created EXCLUSIVELY (O_EXCL via noclobber): if one already
# exists, a previous transaction was interrupted and is awaiting recovery, so we
# must not overwrite its snapshot pointer (AUD-04). Callers check
# transaction_in_progress and fail closed before reaching here.
write_txn_journal() {
  local snap="$1" reason="$2" phase="${3:-commit}"
  install -d -m 0700 "$(dirname "$TXN_JOURNAL")"
  if [ -e "$TXN_JOURNAL" ]; then
    die "A transaction journal already exists ($TXN_JOURNAL); an earlier interrupted transaction awaits recovery. Run 'sbox recover' first."
  fi
  if ! ( set -o noclobber; jq -n --arg snap "$snap" --arg reason "$reason" --arg at "$(date -Is)" --arg phase "$phase" \
          '{format:1,snapshot:$snap,reason:$reason,started_at:$at,phase:$phase}' > "$TXN_JOURNAL" ) 2>/dev/null; then
    die "Could not create the transaction journal exclusively ($TXN_JOURNAL); another transaction may be in progress. Run 'sbox recover'."
  fi
  sync 2>/dev/null || true
}
mark_transaction_commit() {
  local tmp
  tmp="$(mktemp "$(dirname "$TXN_JOURNAL")/.journal.XXXXXXXX")" || return 1
  jq '.phase="commit"' "$TXN_JOURNAL" > "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 0600 "$tmp" || return 1
  durable_paths "$tmp" || return 1
  mv -f "$tmp" "$TXN_JOURNAL" || return 1
  durable_paths "$TXN_JOURNAL" "$(dirname "$TXN_JOURNAL")"
}

# Persist the completed/restored runtime before removing its recovery pointer.
# In particular, cp-a exports and snapshot restores are not atomic_install calls.
durable_runtime_commit() {
  python3 - "$BASE_DIR" "$LIB_DIR" "$SERVICE_FILE" "$FIREWALL_SERVICE_FILE" "$SYSCTL_FILE" "$CERT_HOOK_FILE" "$CLI_BIN" \
    /etc/fail2ban/jail.d/sbox-manager.local /etc/fail2ban/action.d/sbox-manager.conf /usr/local/lib/sbox-manager-security/action <<'PYCOMMIT'
import os,sys
from pathlib import Path
roots=[Path(p) for p in sys.argv[1:3]]
paths=set(Path(p) for p in sys.argv[1:])
for root in roots:
    if root.is_dir() and not root.is_symlink():paths.update(root.rglob('*'))
directories=set()
for p in paths:
    directories.update(p.parents)
    if p.is_symlink():continue
    if p.is_dir():directories.add(p)
    elif p.is_file():
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
for p in sorted(directories,key=lambda p:len(p.parts),reverse=True):
    if p.is_dir() and not p.is_symlink():
        fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
PYCOMMIT
}
clear_txn_journal() {
  durable_runtime_commit || die "Runtime durability check failed; recovery journal and snapshot retained."
  rm -f "$TXN_JOURNAL" || die "Could not remove the verified transaction journal."
  durable_paths "$(dirname "$TXN_JOURNAL")"
}
transaction_in_progress() { [ -e "$TXN_JOURNAL" ] || [ -L "$TXN_JOURNAL" ]; }

# A pending policy-only journal lives next to the backups; surface it too.
policy_journal_pending() {
  [ -e "$BACKUP_DIR/.policy-journal.json" ] || [ -L "$BACKUP_DIR/.policy-journal.json" ]
}

# Refuse to begin any new mutation while an interrupted transaction (full or
# policy-only) is pending recovery. Fail closed (AUD-04).
no_pending_transactions() { ! transaction_in_progress && ! policy_journal_pending; }

guard_no_pending_transaction() {
  if [ "${SBOX_FEATURE_HELD:-false}" != true ] && [ -e "$BACKUP_DIR/features.pending" ]; then die "Interrupted feature upgrade; run sbox recover before making changes."; fi
  if transaction_in_progress; then
    die "An interrupted transaction awaits recovery (run: sbox recover) before any new change can be applied."
  fi
  if policy_journal_pending; then
    die "An interrupted policy-only transaction awaits recovery (run: sbox recover) before any new change can be applied."
  fi
}

recover_command() {
  need_root; need_systemd
  ensure_runtime_dir
  acquire_lock
  local did=0 failed=0
  # --- full transaction recovery (fail closed on a missing/invalid snapshot) ---
  if transaction_in_progress; then
    did=1
    local snap reason
    snap="$(jq -r '.snapshot // empty' "$TXN_JOURNAL" 2>/dev/null || true)"
    reason="$(jq -r '.reason // "operation"' "$TXN_JOURNAL" 2>/dev/null || true)"
    if [ -z "$snap" ] || [ ! -d "$snap" ] || [ ! -e "$snap/.snapshot-complete" ]; then
      warn "An interrupted '$reason' transaction was found, but its pre-operation snapshot is missing or incomplete ($snap)."
      warn "Refusing to report success or clear the recovery journal. The journal is preserved at: $TXN_JOURNAL"
      warn "Assisted recovery: inspect 'sbox doctor', verify /etc/sbox-manager and the sing-box service, then once the runtime is confirmed consistent remove the journal manually ('rm -f $TXN_JOURNAL'). Do NOT delete the journal until recovery is verified."
      failed=1
    else
      warn "An interrupted '$reason' transaction was found; restoring the previous runtime from its snapshot."
      SBOX_ANSWER="$(yes_no 'Roll the runtime back to the pre-operation snapshot now?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { echo "Left as-is. Re-run 'sbox recover' when ready."; return 0; }
      validate_runtime_snapshot "$snap" || die "Recovery snapshot is invalid; journal preserved."
      if rollback_transaction_verified "$snap"; then
        clear_txn_journal
        rm -rf -- "$snap"
        ok "Full-transaction recovery complete and state re-validated."
      else
        warn "Post-recovery validation did not pass cleanly; the journal and snapshot are preserved at $TXN_JOURNAL / $snap."
        failed=1
      fi
    fi
  fi
  # --- policy-only transaction recovery (delegated to the policy helper) ---
  if policy_journal_pending; then
    did=1
    warn "An interrupted policy-only transaction was found; recovering exports/state/helpers from its durable snapshot."
    if policy_transaction recover; then
      ok "Policy-only recovery complete."
    else
      warn "Policy-only recovery could not be verified; the policy journal is preserved for assisted recovery. Run 'sbox doctor'."
      failed=1
    fi
  fi
  # Recover nested native/policy transactions before the enclosing feature snapshot.
  if [ "$failed" -eq 0 ] && [ -d "$BACKUP_DIR/features.pending" ]; then
    did=1
    feature_upgrade_recover || failed=1
  fi
  if [ "$did" -eq 0 ]; then
    ok "No interrupted transaction to recover."
    return 0
  fi
  [ "$failed" -eq 0 ] || die "Recovery incomplete; evidence preserved. Resolve the issues above and re-run 'sbox recover'."
  ok "Recovery complete. Run 'sbox doctor' to confirm."
}

assert_candidate_ports_free() {
  local state="$1" name proto port pid
  pid="$(singbox_main_pid)"
  while IFS=$'\t' read -r name proto port; do
    [ -n "$name" ] || continue
    if port_in_use "$port" "$proto" && ! listener_owned_by_singbox "$port" "$proto" "$pid"; then
      die "Candidate port $port/$proto belongs to another process ($name); no service was changed."
    fi
  done < <(enabled_transport_rows "$state")
  local range conflict current_range=''
  range="$(jq -r 'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end' "$state")"
  # Keeping an already owned NAT range does not claim new listener ports.
  # Resolver/outbound sockets can temporarily use ephemeral ports in that range.
  if state_exists; then current_range="$(jq -r 'if .protocols.hy2.enabled then (.protocols.hy2.udp_range // "") else "" end' "$STATE_FILE")"; fi
  if [ -n "$range" ] && [ "$range" != "$current_range" ]; then
    conflict="$(udp_range_conflict "$range" "$pid" || true)"
    [ -z "$conflict" ] || die "Candidate HY2 hop range overlaps UDP listener $conflict."
  fi
}

apply_candidate() {
  local candidate_state="$1" candidate_binary="${2:-}" reason="${3:-configuration change}"
  local tx render staged_config binary version cert key snap security_mode rc=0
  need_root; need_systemd
  state_exists && assert_safe_namespaces
  acquire_lock
  if [ -n "${SBOX_PREPARED_SNAPSHOT:-}" ]; then
    [ "$(jq -r .snapshot "$TXN_JOURNAL")" = "$SBOX_PREPARED_SNAPSHOT" ] || die "Prepared journal mismatch."
  else guard_no_pending_transaction; fi
  if [ -n "${CURRENT_STATE_SHA:-}" ] && [ -s "$STATE_FILE" ] && [ "$(state_fingerprint "$STATE_FILE")" != "$CURRENT_STATE_SHA" ]; then
    die "The live state changed while this session was open (another sbox command ran); re-run the command."
  fi
  if [ -f "$STATE_FILE" ] && jq -e '.accounting.enabled == true' "$STATE_FILE" >/dev/null; then
    jq -e '.accounting.enabled == true' "$candidate_state" >/dev/null || die 'Refusing an implicit accounting/quotas downgrade. Restore a compatible accounting-enabled backup.'
  fi
  state_tool validate "$candidate_state"
  if jq -e '.accounting.enabled == true' "$candidate_state" >/dev/null; then
    [ "$(sha256sum "${candidate_binary:-$SBOX_BIN}" | awk '{print $1}')" = "$(jq -r .accounting.core_sha256 "$candidate_state")" ] || die 'Accounting requires the validated source-pinned core. Stock/unsupported core replacement is refused while quotas are enabled.'
  fi
  firewall_preflight_file "$candidate_state"
  security_mode="$(security_apply_mode)"; security_preflight_for_apply "$security_mode"
  reconcile_client_policy "$candidate_state"
  assert_candidate_ports_free "$candidate_state"
  binary="${candidate_binary:-$SBOX_BIN}"
  [ -x "$binary" ] || die "Candidate sing-box binary is missing."
  version="$(binary_version "$binary")"; [ -n "$version" ] || die "Cannot read candidate sing-box version."
  [ "$version" = "$(jq -r '.sing_box.version' "$candidate_state")" ] || die "State/core version mismatch: state=$(jq -r '.sing_box.version' "$candidate_state"), binary=$version"

  tx="$(mktemp -d "$RUNTIME_DIR/apply.XXXXXX")"; render="$tx/render"
  # The pre-commit snapshot lives on persistent storage (not the tmpfs runtime
  # dir) and is pointed to by a durable journal, so a crash or power loss during
  # the commit can be detected and rolled back after a reboot (sbox recover).
  install -d -m 0700 "$TXN_SNAPSHOT_DIR"
  snap="$TXN_SNAPSHOT_DIR/$(date +%Y%m%d-%H%M%S)-$$.$RANDOM"
  SBOX_CERT_LAYOUT=live render_bundle "$candidate_state" "$render"
  install -d -m 0700 "$tx/certs"
  if state_needs_certificate "$candidate_state"; then
    select_candidate_certificate "$candidate_state" || { rm -rf "$tx"; die "Candidate certificate/key pair is invalid."; }
    cert="$EFFECTIVE_CERT"; key="$EFFECTIVE_KEY"
    cert_valid_now "$cert" || { rm -rf "$tx"; die "Candidate certificate is not currently valid."; }
    cert_matches_domain "$cert" "$(jq -r '.domain' "$candidate_state")" || { rm -rf "$tx"; die "Candidate certificate does not cover the endpoint domain."; }
    if [ "$(jq -r '.certificate.insecure' "$candidate_state")" != true ]; then
      cert_trusted "$cert" "$(jq -r '.domain' "$candidate_state")" || { rm -rf "$tx"; die 'Candidate certificate chain/domain/EKU is not trusted.'; }
    fi
    # Mirror the live/ layout so the staged check-config paths resolve.
    install -d -m 0700 "$tx/certs/live"
    install -m 0644 "$cert" "$tx/certs/live/fullchain.pem"; install -m 0600 "$key" "$tx/certs/live/privkey.pem"
  fi
  staged_config="$tx/check-config.json"
  sed "s#${CERT_DIR}#${tx}/certs#g" "$render/server.json" > "$staged_config"
  "$binary" check -c "$staged_config" || { rm -rf "$tx"; die "Candidate server config failed sing-box validation."; }

  if [ -n "${SBOX_PREPARED_SNAPSHOT:-}" ]; then
    snap="$SBOX_PREPARED_SNAPSHOT"
  else
    snapshot_runtime "$snap"
    write_txn_journal "$snap" "$reason"
  fi
  if [ -f /usr/local/lib/sbox-accounting/current/accounting.py ] && [ -f "$STATE_FILE" ] && jq -e '.accounting.enabled == true' "$STATE_FILE" >/dev/null; then
    python3 -B /usr/local/lib/sbox-accounting/current/accounting.py reconcile --inherited-lock >&2
  fi
  mark_transaction_commit || die "Cannot durably enter commit; runtime unchanged, journal retained."
  log "Applying $reason transactionally..."
  # Command failures are handled through $? below, but a signal would kill this
  # shell and the transaction subshell together before the rollback could run.
  # Mask signals for the critical section so the runtime is never left half
  # applied; the policy-only transaction does the same in Python.
  trap '' INT TERM HUP
  set +e
  (
    set -Eeuo pipefail
    # Everything is written before the restart, so an interruption leaves either
    # the old or the new configuration in place rather than a stopped service
    # with a half-written runtime. The restart below also performs the stop.
    ensure_service_user
    [ -z "$candidate_binary" ] || atomic_install "$candidate_binary" "$SBOX_BIN" 0755 root root
    atomic_install "$candidate_state" "$STATE_FILE" 0600 root root
    atomic_install "$render/server.json" "$CONFIG_FILE" 0640 root "$SERVICE_GROUP"
    install -d -m 0700 "$EXPORT_DIR"
    if [ -d "${RESTORE_EXPORT_SOURCE:-/nonexistent}" ]; then cp -a "$RESTORE_EXPORT_SOURCE"/. "$EXPORT_DIR"/; fi
    cp -a "$render"/. "$EXPORT_DIR"/
    find "$EXPORT_DIR" -type d -exec chmod 0700 {} +
    find "$EXPORT_DIR" -type f -exec chmod 0600 {} +
    if state_needs_certificate "$candidate_state"; then copy_service_certificate "$cert" "$key"; else clear_service_certificate; fi
    install_manager_self
    ensure_helpers
    atomic_install "$STATE_HELPER" "$LIB_DIR/sbox-state" 0755 root root
    atomic_install "$POLICY_HELPER" "$LIB_DIR/sbox-policy" 0755 root root
    write_systemd_units
    # The website tree exists only while the self-hosted target is selected.
    if reality_fallback_active "$candidate_state"; then install_fallback_web_files; fi
    fallback_web_sync "$candidate_state"
    reality_fallback_active "$candidate_state" || rm -rf -- "$FALLBACK_WEB_DIR"
    lab_fault apply-website
    if [ "$security_mode" = initialize ]; then security_run setup; fi
    cleanup_old_artifacts
    apply_tuning "$candidate_state"
    firewall_apply_file "$candidate_state"
    systemctl daemon-reload
    systemctl enable sbox-manager-firewall.service sing-box.service >/dev/null
    systemctl reset-failed sbox-manager-firewall.service sing-box.service >/dev/null 2>&1 || true
    systemctl restart sbox-manager-firewall.service
    # The self-hosted website must be healthy before REALITY is declared ready.
    fallback_web_activate "$candidate_state"
    systemctl restart sing-box.service
    check_expected_listeners "$candidate_state" 15
    service_stable
    fallback_web_verify_relay "$candidate_state"
  )
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    journalctl --no-pager -u sing-box.service -n 80 >&2 || true
    SBOX_ROLLBACK_ATTEMPTED=true
    if rollback_transaction_verified "$snap"; then
      clear_txn_journal
      rm -rf "$tx" "$snap"
      trap - INT TERM HUP
      die "$reason failed; the previous runtime was restored and verified."
    fi
    trap - INT TERM HUP
    die "$reason failed; automatic rollback is unverified. Journal retained; run sbox recover."
  fi
  trap - INT TERM HUP
  clear_txn_journal
  rm -rf "$tx" "$snap"
  ok "$reason completed successfully."
}

normalized_current_state() {
  local output="$1"
  require_installed
  # Remember which revision of the live state this session edits from, so that
  # apply_candidate can refuse to clobber a change made by another command
  # while this one was still asking questions.
  CURRENT_STATE_SHA="$(state_fingerprint "$STATE_FILE")"
  normalize_state_to "$STATE_FILE" "$output"
}

install_command() {
  local region requested channel temp existing='' candidate version state plan confirmed
  parse_install_options "$@"
  need_root; need_systemd; check_os
  guard_no_pending_transaction
  assert_safe_namespaces
  install_dependencies
  ensure_dirs
  # apply_candidate takes the transaction lock; this session guard only keeps
  # two administrators (or two menu invocations) from editing state at once.
  acquire_session
  temp="$(exec_mktemp_dir install)"
  if state_exists; then
    existing="$temp/existing.json"
    CURRENT_STATE_SHA="$(state_fingerprint "$STATE_FILE")"
    normalize_state_to "$STATE_FILE" "$existing"
  fi

  if [ -n "$OPT_region" ]; then
    case "${OPT_region,,}" in global|cn) region="${OPT_region,,}" ;; *) die "Region must be global or cn." ;; esac
  else
    region="$(choose_region "$([ -s "$existing" ] && jq -r '.region' "$existing" || echo global)")"
  fi
  if [ -n "$OPT_core" ]; then
    requested="$OPT_core"
  else
    requested="$(choose_core_request pinned)"
  fi
  channel=fixed
  candidate="$temp/sing-box"
  obtain_core "$requested" "$candidate" "${OPT_core_sha256:-}"
  if [ -s "$existing" ] && jq -e '.accounting.enabled == true' "$existing" >/dev/null; then
    [ "$(binary_version "$candidate")" = "$(jq -r .sing_box.version "$existing")" ] || die 'Existing quotas require the validated accounting core version. Use an accounting-compatible upgrade.'
    cp "$SBOX_BIN" "$candidate"
  fi
  version="$(binary_version "$candidate")"
  local installed_core_version=''
  if [ -x "$SBOX_BIN" ]; then installed_core_version="$(binary_version "$SBOX_BIN")"; fi
  if [ -s "$existing" ] && ! valid_version "$installed_core_version"; then installed_core_version="$(jq -r '.sing_box.version' "$existing")"; fi
  if [ -s "$existing" ] && version_lt "$version" "$installed_core_version"; then
    case "$requested" in ''|pinned|embedded|bundled) die "Refusing implicit reinstall downgrade to $version." ;; esac
    SBOX_ANSWER="$(yes_no "Downgrade installed core to $version?" no)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; return 0; }
  fi
  state="$temp/state.json"; plan="$temp/certificate-plan.json"
  build_guided_state "$state" "$existing" "$region" "$candidate" "$version" "$channel" "$plan"

  echo >&2
  printf '%b%s%b\n' "$BOLD" "Review installation plan" "$RESET" >&2
  print_plan_summary "$state" "$plan" >&2
  confirmed="$(yes_no 'Apply this plan now?' yes)" || die "No answer was given (input ended); nothing was changed."
  [ "$confirmed" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  SBOX_INITIALIZE_SECURITY=true apply_planned_candidate "$state" "$candidate" "install/reinstall" "$plan"
  rm -rf "$temp"
  webui_install_if_enabled
  fallback_web_refresh_sandbox
  print_completion_summary
}

network_command() (
  set -Eeuo pipefail
  local action="${1:-show}" input="${2:-}" tmp archive
  need_root; require_installed
  case "$action" in show|report) [ "$#" -le 1 ] || die 'Usage: sbox network show' ;;
    preview|apply) [ "$#" -eq 2 ] || die 'Usage: sbox network preview|apply /secure/network.json'
      [ -f "$input" ] && [ ! -L "$input" ] && [ "$(stat -c '%u %a' "$input")" = '0 600' ] || die 'Network policy file must be a root-owned0600 regular file.' ;;
    *) die 'Usage: sbox network show|preview FILE|apply FILE (apply restarts VPN; backup created first)' ;; esac
  if [ "$action" = apply ]; then acquire_session; fi
  tmp="$(mktemp -d "$RUNTIME_DIR/network-policy.XXXXXXXX")"; trap 'rm -rf -- "$tmp"' EXIT
  normalize_state_ro "$STATE_FILE" "$tmp/current.json"
  if [ "$action" = show ]; then state_tool network-policy "$tmp/current.json"; return; fi
  if [ "$action" = report ]; then
    state_tool endpoint-preflight "$tmp/current.json" > "$tmp/endpoints.json" || true
    write_network_helper | python3 - report "$tmp/current.json" "$tmp/endpoints.json"; return
  fi
  write_network_helper | python3 - patch "$tmp/current.json" "$input" "$tmp/candidate.json"
  state_tool validate "$tmp/candidate.json"
  echo 'Network migration preview (credentials/users/subscriptions unchanged):' >&2
  state_tool network-policy "$tmp/current.json"
  state_tool network-policy "$tmp/candidate.json"
  render_bundle "$tmp/candidate.json" "$tmp/render"
  state_tool endpoint-preflight "$tmp/candidate.json" || die 'Endpoint preflight failed; no settings changed.'
  if [ "$action" = preview ]; then echo 'Preview only; no state, firewall or service changes.'; return; fi
  SBOX_ANSWER="$(yes_no 'Apply this network policy and restart the VPN? A native backup is created first.' no)" || die 'Input ended; no changes made.'
  [ "$SBOX_ANSWER" = true ] || { echo 'Cancelled.'; return; }
  archive="$(create_backup_archive network-policy)"; echo "Pre-change native backup: $archive" >&2
  SBOX_REUSE_MANAGED_CERT=true apply_candidate "$tmp/candidate.json" '' 'explicit network policy migration'
)

configure_command() {
  need_root; require_installed; acquire_session
  local family keep_network=false temp current candidate plan merged node domain ipv4 ipv6 listen reality_sni fp vmess_path vmess_tls firewall tuning block needed=false
  local reality_enabled vmess_enabled
  temp="$(mktemp -d "$RUNTIME_DIR/configure.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"; plan="$temp/cert-plan.json"
  normalized_current_state "$current"
  node="$(ask_label 'Node name' "$(jq -r '.node_name' "$current")")"
  domain="$(ask_domain 'Client domain' "$(jq -r '.domain' "$current")")"
  ipv4="$(ask_optional_ip 'Public IPv4' 4 "$(jq -r '.server.ipv4 // empty' "$current")")"
  ipv6="$(ask_optional_ip 'Public IPv6' 6 "$(jq -r '.server.ipv6 // empty' "$current")")"
  listen="$(choose_listen "$(jq -r '.server.listen' "$current")" "$ipv6" true)"
  if [ "$listen" = preserve ]; then
    keep_network=true
    family="$(jq -r '.server.mode // "preserve"' "$current")"; listen="$(jq -r '.server.listen' "$current")"
  else
    case "$listen" in 0.0.0.0) family=ipv4 ;; ::) family=dual ;; *) family=ipv6 ;; esac
  fi
  reality_enabled="$(jq -r '.protocols.reality.enabled' "$current")"; vmess_enabled="$(jq -r '.protocols.vmess.enabled' "$current")"
  reality_sni="$(jq -r '.protocols.reality.sni' "$current")"; fp="$(jq -r '.protocols.reality.fingerprint' "$current")"
  local old_fallback fallback='{"mode":"remote"}' remote_sni
  old_fallback="$(jq -c '.protocols.reality.fallback // {}' "$current")"
  remote_sni="$(jq -r --arg sni "$reality_sni" 'if .mode == "self_hosted" then .remote_sni else $sni end' <<< "$old_fallback")"
  [ "$(jq -r '.mode // "remote"' <<< "$old_fallback")" = self_hosted ] && fallback="$old_fallback"
  if [ "$reality_enabled" = true ]; then
    if jq -e '.zgo_legacy_compat == true' "$current" >/dev/null; then
      reality_sni="$(choose_reality_sni "$reality_sni")"
    else
      fallback="$(choose_reality_fallback "$old_fallback" "$domain" "$remote_sni" \
        $(jq -r '.protocols|to_entries[]|select(.value.enabled and .key!="hy2" and .key!="tuic" and .key!="reality")|.value.port' "$current") "$(jq -r '.protocols.reality.port' "$current")")"
      if [ "$(jq -r '.mode' <<< "$fallback")" = self_hosted ]; then reality_sni="$domain"; else reality_sni="$(choose_reality_sni "$remote_sni")"; fi
    fi
    fp="$(choose_fingerprint "$fp")"
  elif [ "$(jq -r '.mode // "remote"' <<< "$old_fallback")" = self_hosted ]; then
    # Keep a dormant self-hosted choice consistent with a changed domain.
    reality_sni="$domain"; fallback="$(jq -c --arg host "$domain" '.hostname=$host' <<< "$old_fallback")"
  fi
  vmess_path="$(jq -r '.protocols.vmess.path' "$current")"; vmess_tls="$(jq -r '.protocols.vmess.tls' "$current")"
  if [ "$vmess_enabled" = true ]; then
    vmess_path="$(ask_vmess_path "$vmess_path")"
    vmess_tls="$(yes_no 'Enable TLS on VMess-WS?' "$([ "$vmess_tls" = true ] && echo yes || echo no)")"
  fi
  firewall="$(yes_no 'Install/reconcile local firewall allow rules?' "$([ "$(jq -r '.firewall.enabled' "$current")" = true ] && echo yes || echo no)")"
  tuning="$(yes_no 'Apply legacy BBR/fq socket tuning (measure before opting in)?' "$([ "$(jq -r '.tuning.enabled' "$current")" = true ] && echo yes || echo no)")"
  block="$(yes_no 'Block proxied access to private/link-local VPS destinations?' "$([ "$(jq -r '.security.block_private' "$current")" = true ] && echo yes || echo no)")"
  jq --argjson keep_network "$keep_network" --arg family "$family" --arg node "$node" --arg domain "$domain" --arg ipv4 "$ipv4" --arg ipv6 "$ipv6" --arg listen "$listen"     --arg reality_sni "$reality_sni" --arg fp "$fp" --arg path "$vmess_path" --argjson vmess_tls "$vmess_tls"     --argjson firewall "$firewall" --argjson tuning "$tuning" --argjson block "$block" --argjson fallback "$fallback" --arg manager "$MANAGER_VERSION"     '.node_name=$node|.domain=$domain|.server=((if $keep_network then .server else {scope:(if .server.scope=="internal" then "internal" else "public" end)} end)+{ipv4:$ipv4,ipv6:$ipv6,listen:$listen,mode:$family})|.protocols.reality.sni=$reality_sni|(if $fallback.mode=="self_hosted" then .protocols.reality.fallback=$fallback else del(.protocols.reality.fallback) end)|.protocols.reality.fingerprint=$fp|.protocols.vmess.path=$path|.protocols.vmess.tls=$vmess_tls|.protocols.vmess.sni=$domain|.firewall.enabled=$firewall|.tuning.enabled=$tuning|.security.block_private=$block|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$current" > "$candidate"
  state_tool endpoint-preflight "$candidate" || die 'Endpoint preflight failed; no settings changed.'
  collect_state_certificate_plan "$candidate" "$domain" "$current" "$plan"
  merged="$temp/merged.json"; merge_plan_certificate "$candidate" "$plan" "$merged"; mv -f "$merged" "$candidate"
  echo >&2; print_plan_summary "$candidate" "$plan" >&2
  SBOX_ANSWER="$(yes_no 'Apply these settings?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_planned_candidate "$candidate" '' "configuration change" "$plan"
  rm -rf "$temp"
  print_completion_summary
}

ports_command() {
  need_root; require_installed; acquire_session
  local temp current candidate reality vmess anytls hy2 tuic range tcp1='' tcp2='' udp1='' other_for_range=0
  local reality_enabled vmess_enabled anytls_enabled hy2_enabled tuic_enabled
  temp="$(mktemp -d "$RUNTIME_DIR/ports.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"
  normalized_current_state "$current"
  reality="$(jq -r '.protocols.reality.port' "$current")"; vmess="$(jq -r '.protocols.vmess.port' "$current")"
  anytls="$(jq -r '.protocols.anytls.port' "$current")"; hy2="$(jq -r '.protocols.hy2.port' "$current")"; tuic="$(jq -r '.protocols.tuic.port' "$current")"
  reality_enabled="$(jq -r '.protocols.reality.enabled' "$current")"; vmess_enabled="$(jq -r '.protocols.vmess.enabled' "$current")"
  anytls_enabled="$(jq -r '.protocols.anytls.enabled' "$current")"; hy2_enabled="$(jq -r '.protocols.hy2.enabled' "$current")"; tuic_enabled="$(jq -r '.protocols.tuic.enabled' "$current")"
  if [ "$reality_enabled" = true ]; then reality="$(ask_port 'REALITY' tcp "$reality")"; tcp1="$reality"; fi
  if [ "$vmess_enabled" = true ]; then vmess="$(ask_port 'VMess-WS' tcp "$vmess" "$tcp1")"; tcp2="$vmess"; fi
  if [ "$anytls_enabled" = true ]; then anytls="$(ask_port 'AnyTLS' tcp "$anytls" "$tcp1" "$tcp2")"; fi
  if [ "$hy2_enabled" = true ]; then hy2="$(ask_port 'Hysteria2' udp "$hy2")"; udp1="$hy2"; fi
  if [ "$tuic_enabled" = true ]; then tuic="$(ask_port 'TUIC-v5' udp "$tuic" "$udp1")"; other_for_range="$tuic"; fi
  if [ "$hy2_enabled" = true ]; then range="$(ask_hy2_range "$hy2" "$other_for_range" "$(jq -r '.protocols.hy2.udp_range // empty' "$current")")"; else range=''; fi
  jq --argjson reality "$reality" --argjson vmess "$vmess" --argjson anytls "$anytls" --argjson hy2 "$hy2" --argjson tuic "$tuic" --arg range "$range" --arg manager "$MANAGER_VERSION"     '.protocols.reality.port=$reality|.protocols.vmess.port=$vmess|.protocols.anytls.port=$anytls|.protocols.hy2.port=$hy2|.protocols.tuic.port=$tuic|.protocols.hy2.udp_range=$range|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$current" > "$candidate"
  state_tool validate "$candidate"
  echo >&2; print_required_ports "$candidate" >&2
  SBOX_ANSWER="$(yes_no 'Apply these ports?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_candidate "$candidate" '' "port change"
  rm -rf "$temp"
}

protocols_command() {
  need_root; require_installed; acquire_session
  local temp current candidate enabled plan merged needed=false
  local reality vmess anytls hy2 tuic range tcp1='' tcp2='' udp1='' other_for_range=0
  local reality_new vmess_new anytls_new hy2_new tuic_new reality_old vmess_old anytls_old hy2_old tuic_old
  temp="$(mktemp -d "$RUNTIME_DIR/protocols.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"; plan="$temp/cert-plan.json"
  normalized_current_state "$current"
  enabled="$(select_protocols "$current")"
  reality_new="$(jq -r '.reality' <<< "$enabled")"; vmess_new="$(jq -r '.vmess' <<< "$enabled")"; anytls_new="$(jq -r '.anytls' <<< "$enabled")"
  hy2_new="$(jq -r '.hy2' <<< "$enabled")"; tuic_new="$(jq -r '.tuic' <<< "$enabled")"
  reality_old="$(jq -r '.protocols.reality.enabled' "$current")"; vmess_old="$(jq -r '.protocols.vmess.enabled' "$current")"; anytls_old="$(jq -r '.protocols.anytls.enabled' "$current")"
  hy2_old="$(jq -r '.protocols.hy2.enabled' "$current")"; tuic_old="$(jq -r '.protocols.tuic.enabled' "$current")"
  reality="$(jq -r '.protocols.reality.port' "$current")"; vmess="$(jq -r '.protocols.vmess.port' "$current")"; anytls="$(jq -r '.protocols.anytls.port' "$current")"
  hy2="$(jq -r '.protocols.hy2.port' "$current")"; tuic="$(jq -r '.protocols.tuic.port' "$current")"

  if [ "$reality_new" = true ]; then [ "$reality_old" = true ] || reality="$(ask_port 'REALITY' tcp '')"; tcp1="$reality"; fi
  if [ "$vmess_new" = true ]; then [ "$vmess_old" = true ] || vmess="$(ask_port 'VMess-WS' tcp '' "$tcp1")"; tcp2="$vmess"; fi
  if [ "$anytls_new" = true ] && [ "$anytls_old" != true ]; then anytls="$(ask_port 'AnyTLS' tcp '' "$tcp1" "$tcp2")"; fi
  if [ "$hy2_new" = true ]; then [ "$hy2_old" = true ] || hy2="$(ask_port 'Hysteria2' udp '')"; udp1="$hy2"; fi
  if [ "$tuic_new" = true ]; then [ "$tuic_old" = true ] || tuic="$(ask_port 'TUIC-v5' udp '' "$udp1")"; other_for_range="$tuic"; fi
  if [ "$hy2_new" = true ]; then
    if [ "$hy2_old" = true ]; then range="$(jq -r '.protocols.hy2.udp_range // empty' "$current")"; else range=''; fi
    range="$(ask_hy2_range "$hy2" "$other_for_range" "$range")"
  else
    range=''
  fi

  jq --argjson enabled "$enabled" --argjson reality "$reality" --argjson vmess "$vmess" --argjson anytls "$anytls" \
    --argjson hy2 "$hy2" --argjson tuic "$tuic" --arg range "$range" --arg manager "$MANAGER_VERSION" \
    '.protocols.reality.enabled=$enabled.reality|.protocols.vmess.enabled=$enabled.vmess|.protocols.hy2.enabled=$enabled.hy2|.protocols.tuic.enabled=$enabled.tuic|.protocols.anytls.enabled=$enabled.anytls|
     .protocols.reality.port=$reality|.protocols.vmess.port=$vmess|.protocols.anytls.port=$anytls|.protocols.hy2.port=$hy2|.protocols.tuic.port=$tuic|.protocols.hy2.udp_range=$range|
     .manager_version=$manager|.updated_at=(now|todateiso8601)' "$current" > "$candidate"
  collect_state_certificate_plan "$candidate" "$(jq -r '.domain' "$candidate")" "$current" "$plan"
  merged="$temp/merged.json"; merge_plan_certificate "$candidate" "$plan" "$merged"; mv -f "$merged" "$candidate"
  echo >&2; print_plan_summary "$candidate" "$plan" >&2
  SBOX_ANSWER="$(yes_no 'Apply protocol selection?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_planned_candidate "$candidate" '' "protocol change" "$plan"
  rm -rf "$temp"
}

certificate_command() {
  need_root; require_installed; acquire_session
  local temp current candidate plan merged
  temp="$(mktemp -d "$RUNTIME_DIR/certificate.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"; plan="$temp/cert-plan.json"
  normalized_current_state "$current"
  if ! state_needs_certificate "$current"; then
    echo "No enabled protocol currently requires a certificate."
    rm -rf "$temp"; return 0
  fi
  CERT_TRUSTED_ONLY=false; reality_fallback_active "$current" && CERT_TRUSTED_ONLY=true
  collect_certificate_plan "$(jq -r '.domain' "$current")" true '' "$plan"
  [ "$(jq -r '.method' "$plan")" != cancel-self-hosted ] || { rm -rf "$temp"; echo "Cancelled. Use 'sbox reality-fallback remote' to stop the self-hosted website."; return 0; }
  merge_plan_certificate "$current" "$plan" "$candidate"
  echo >&2; print_plan_summary "$candidate" "$plan" >&2
  SBOX_ANSWER="$(yes_no 'Replace the certificate now?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_planned_candidate "$candidate" '' "certificate change" "$plan"
  rm -rf "$temp"
}

region_command() {
  need_root; require_installed; acquire_session
  local requested="${1:-}" temp current candidate region
  temp="$(mktemp -d "$RUNTIME_DIR/region.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"
  normalized_current_state "$current"
  if [ -n "$requested" ]; then
    case "${requested,,}" in global|cn) region="${requested,,}" ;; *) die "Region must be global or cn." ;; esac
  else
    region="$(choose_region "$(jq -r '.region' "$current")")"
  fi
  jq --arg region "$region" --arg manager "$MANAGER_VERSION" '.region=$region|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$current" > "$candidate"
  apply_candidate "$candidate" '' "profile change"
  rm -rf "$temp"
}

rotate_command() {
  need_root; require_installed; acquire_session
  local target="${1:-}" temp current candidate private public
  if [ -z "$target" ]; then
    echo "Rotate: 1 all, 2 reality, 3 vmess, 4 hy2, 5 tuic, 6 anytls, 0 cancel" >&2
    case "$(prompt_choice 'Select target' '1' '0 1 2 3 4 5 6')" in 0) return 0 ;; 1) target=all ;; 2) target=reality ;; 3) target=vmess ;; 4) target=hy2 ;; 5) target=tuic ;; 6) target=anytls ;; esac
  fi
  case "$target" in all|reality|vmess|hy2|tuic|anytls) ;; *) die "Unknown rotation target: $target" ;; esac
  temp="$(mktemp -d "$RUNTIME_DIR/rotate.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"
  normalized_current_state "$current"; cp "$current" "$candidate"
  if [ "$target" = all ] || [ "$target" = reality ]; then
    IFS=$'\t' read -r private public < <(generate_reality_keypair "$SBOX_BIN")
    private_jq --arg uuid "$(random_uuid)" --arg private "$private" --arg public "$public" --arg short "$(random_hex 8)" \
      '.protocols.reality.uuid=$uuid|.protocols.reality.private_key=$private|.protocols.reality.public_key=$public|.protocols.reality.short_id=$short' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"
  fi
  if [ "$target" = all ] || [ "$target" = vmess ]; then private_jq --arg uuid "$(random_uuid)" '.protocols.vmess.uuid=$uuid' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"; fi
  if [ "$target" = all ] || [ "$target" = hy2 ]; then private_jq --arg pass "$(random_hex 24)" '.protocols.hy2.password=$pass' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"; fi
  if [ "$target" = all ] || [ "$target" = tuic ]; then private_jq --arg uuid "$(random_uuid)" --arg pass "$(random_hex 24)" '.protocols.tuic.uuid=$uuid|.protocols.tuic.password=$pass' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"; fi
  if [ "$target" = all ] || [ "$target" = anytls ]; then private_jq --arg pass "$(random_hex 24)" '.protocols.anytls.password=$pass' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"; fi
  jq --arg manager "$MANAGER_VERSION" '.manager_version=$manager|.updated_at=(now|todateiso8601)' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"
  state_tool validate "$candidate"
  warn "Old links for $target will stop working immediately."
  SBOX_ANSWER="$(yes_no 'Rotate now?' no)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_candidate "$candidate" '' "credential rotation ($target)"
  rm -rf "$temp"
}

update_command() {
  local requested='' digest='' temp current candidate binary version channel=fixed
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --sha256|--core-sha256) [ "$#" -ge 2 ] || die "$1 requires a value."; digest="$2"; shift 2 ;;
      --sha256=*|--core-sha256=*) digest="${1#*=}"; shift ;;
      -*) die "Unknown update option: $1" ;;
      *) [ -z "$requested" ] || die "Usage: sbox update [latest|stable|beta|pinned|VERSION|/path/to/sing-box-or-archive] [--sha256 HEX]"; requested="$1"; shift ;;
    esac
  done
  need_root; require_installed
  temp="$(exec_mktemp_dir update)"; current="$temp/current.json"; candidate="$temp/state.json"; binary="$temp/sing-box"
  normalized_current_state "$current"
  [ -n "$requested" ] || requested="$(choose_core_request pinned)"
  obtain_core "$requested" "$binary" "$digest"
  version="$(binary_version "$binary")"
  local installed; installed="$(binary_version "$SBOX_BIN")"
  # Downgrade protection. The implicit pinned source must never move to an
  # OLDER core than the one installed. An explicit local file may downgrade,
  # but only with an explicit confirmation (interactively, or --force for
  # scripted use); --yes alone keeps the default "No" and cancels.
  if [ -n "$installed" ] && valid_version "$installed" && version_lt "$version" "$installed"; then
    case "$requested" in
      ''|pinned|embedded|bundled)
        rm -rf "$temp"
        die "Refusing an implicit downgrade from $installed to the pinned core $version. To intentionally install an older core, pass its local file explicitly with --force."
        ;;
      *)
        warn "Requested core $version is OLDER than the installed $installed."
        SBOX_ANSWER="$(yes_no "Downgrade sing-box from $installed to $version?" no)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Downgrade cancelled."; return 0; }
        ;;
    esac
  fi
  jq --arg version "$version" --arg channel "$channel" --arg manager "$MANAGER_VERSION" '.sing_box.version=$version|.sing_box.channel=$channel|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$current" > "$candidate"
  echo "Current: $installed  Candidate: $version" >&2
  SBOX_ANSWER="$(yes_no 'Apply core update?' yes)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
  apply_candidate "$candidate" "$binary" "sing-box core update"
  rm -rf "$temp"
}

regenerate_command() {
  need_root; require_installed
  local temp current candidate actual
  temp="$(mktemp -d "$RUNTIME_DIR/regenerate.XXXXXX")"; current="$temp/current.json"; candidate="$temp/state.json"
  normalized_current_state "$current"; actual="$(binary_version "$SBOX_BIN")"
  jq --arg manager "$MANAGER_VERSION" --arg version "$actual" '.manager_version=$manager|.sing_box.version=$version|.updated_at=(now|todateiso8601)' "$current" > "$candidate"
  apply_candidate "$candidate" '' "regeneration/repair"
  rm -rf "$temp"
}

# Policy-only transactions deliberately do not call apply_candidate: that path
# restarts the server and reapplies firewall/certificates, which is unnecessary
# for a client group change. Durable snapshots include the old manager as well.
@@HELPER_POLICY@@

policy_transaction() {
  ensure_helpers
  SBOX_POLICY_RUNTIME=1 python3 "$POLICY_HELPER" "$1" "${2:-}" "${3:-}" "${4:-}" "$STATE_FILE" "$EXPORT_DIR" "$MANAGER_BIN" "$CONFIG_FILE" "$SBOX_BIN" "$BACKUP_DIR" "${5:-}"
}

client_policy_command() (
  # Subshell keeps temporary cleanup and signal handlers local to this command.
  set -Eeuo pipefail
  local action="${1:-show}" primary='' temp='' source snapshot helpers_json='[]' probe_mode='' probe_url='' expected_status='' tolerance='' default_group='' h_interval='' h_timeout='' h_failed=''
  [ "$#" -gt 0 ] && shift || true
  case "$action" in
    show|apply) [ "$#" -eq 0 ] || die "Usage: sbox client-policy $action" ;;
    primary)
      [ "$#" -eq 1 ] || die "Usage: sbox client-policy primary tuic|hy2|reality|anytls|vmess"
      primary="$1"
      case "$primary" in tuic|hy2|reality|anytls|vmess) ;; *) die "Unknown primary protocol: $primary" ;; esac ;;
    probes)
      [ "$#" -eq 1 ] || die "Usage: sbox client-policy probes active-only|continuous"
      case "$1" in active-only) probe_mode=true ;; continuous) probe_mode=false ;; *) die "Invalid probe mode" ;; esac ;;
    probe-url)
      [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "Usage: sbox client-policy probe-url https://host/path [200|204|200/204]"
      probe_url="$1"; expected_status="${2:-}" ;;
    tolerance)
      [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]] || die 'Usage: sbox client-policy tolerance10..300'
      tolerance="$1" ;;
    health)
      [ "$#" -eq 3 ] && [[ "$1$2$3" =~ ^[0-9]+$ ]] || die 'Usage: sbox client-policy health INTERVAL_S(30..600) TIMEOUT_MS(1000..10000) FAILURES(1..5)'
      h_interval="$1"; h_timeout="$2"; h_failed="$3" ;;
    default)
      [ "$#" -eq 1 ] || die 'Usage: sbox client-policy default smart|anti-block'
      case "$1" in smart) default_group=smart ;; anti-block|anti_block) default_group=anti_block ;; *) die 'Default group must be smart or anti-block' ;; esac ;;
    rollback) [ "$#" -eq 1 ] || die "Usage: sbox client-policy rollback /var/backups/sbox-manager/policy-DIR" ;;
    *) die "Usage: sbox client-policy show|apply|primary NAME|default smart|anti-block|rollback DIR" ;;
  esac
  need_root; require_installed
  if [ "$action" = show ]; then
    jq -r '"Fallback priority  : " + (.client_policy.primary // "tuic"),
           "Client default     : " + (if (.client_policy.default_group // "anti_block") == "smart" then "🧠 Smart Auto (measured latency)" else "🛡 Anti-Block Auto (ordered fallback)" end),
           "Health checks      : every " + ((.client_policy.health_interval_s // 60)|tostring) + "s, probe timeout " + ((.client_policy.health_timeout_ms // 5000)|tostring) + "ms, immediate re-check after " + ((.client_policy.health_max_failed // 2)|tostring) + " failed connections",
           "Anti-Block Auto    : first healthy enabled node in priority order (no speed comparison)",
           "Smart Auto         : URL-test, switches when faster by more than " + ((.client_policy.smart_tolerance_ms // 120)|tostring) + "ms",
           "Smart probe mode   : " + (if (.client_policy.smart_lazy // false) then "active-only (unused group sleeps)" else "continuous" end),
           "Probe URL          : " + (.client_policy.probe_url // "https://www.gstatic.com/generate_204"),
           "Expected HTTP      : " + (.client_policy.expected_status // "204") + " (HEAD; redirects rejected)",
           "Failover scope     : new connections only; no established-flow migration or live-call guarantee",
           "Fallback order     : preferred, then tuic -> hy2 -> reality -> anytls -> vmess (enabled only)",
           "LOCK               : optional manual pinning for any application; network loss still interrupts flows",
           "Phone requirement  : reimport/reload YAML; clients may keep a locally stored group choice",
           "Redundancy         : five transports share one VPS/IP; health checks do not detect every filtering rule",
           "AI status          : NOT active; YAML has no persistent AI learner or media packet-loss/jitter telemetry"' "$STATE_FILE"
    return 0
  fi
  acquire_lock
  guard_no_pending_transaction
  assert_safe_namespaces
  [ -L "$CLI_BIN" ] && [ "$(readlink -f "$CLI_BIN")" = "$(readlink -f "$MANAGER_BIN")" ] || die "Repair the public sbox CLI link before a policy-only upgrade."
  if [ "$action" = rollback ]; then
    snapshot="$1"
    policy_transaction rollback "$snapshot" '' ''
    return 0
  fi
  temp="$(mktemp -d "$RUNTIME_DIR/client-policy.XXXXXX")"
  trap 'rm -rf -- "$temp"' EXIT
  normalize_state_to "$STATE_FILE" "$temp/current.json"
  if [ -n "$primary" ]; then
    jq -e --arg key "$primary" '.protocols[$key].enabled == true' "$temp/current.json" >/dev/null || die "Primary protocol is not enabled: $primary"
  fi
  jq --arg primary "$primary" --arg manager "$MANAGER_VERSION" --arg probe_mode "$probe_mode" --arg probe_url "$probe_url" --arg expected_status "$expected_status" --arg tolerance "$tolerance" --arg default_group "$default_group" --arg h_interval "$h_interval" --arg h_timeout "$h_timeout" --arg h_failed "$h_failed" '
    .client_policy = (.client_policy // {primary:"tuic"}) |
    if $primary != "" then .client_policy.primary=$primary else . end |
    if $default_group != "" then .client_policy.default_group=$default_group else . end |
    if $h_interval != "" then .client_policy.health_interval_s=($h_interval|tonumber) | .client_policy.health_timeout_ms=($h_timeout|tonumber) | .client_policy.health_max_failed=($h_failed|tonumber) else . end |
    if $probe_mode != "" then .client_policy.smart_lazy=($probe_mode == "true") else . end |
    if $probe_url != "" then .client_policy.probe_url=$probe_url else . end |
    if $expected_status != "" then .client_policy.expected_status=$expected_status else . end |
    if $tolerance != "" then .client_policy.smart_tolerance_ms=($tolerance|tonumber) else . end |
    .manager_version=$manager | .updated_at=(now|todateiso8601)
  ' "$temp/current.json" > "$temp/candidate.json"
  state_tool validate "$temp/candidate.json"
  render_bundle "$temp/candidate.json" "$temp/render"
  source="${SBOX_MANAGER_SOURCE:-$0}"
  [ -f "$source" ] && [ -r "$source" ] || die "Manager source is unavailable. Run the complete script again."
  # The installed sbox CLI is a symlink; resolve it before the regular-file guard.
  source="$(readlink -f "$source")"
  bash -n "$source"
  [ "$(bash "$source" version)" = "$MANAGER_VERSION" ] || die "Manager source display-version mismatch."
  [ "$(bash "$source" _build-id 2>/dev/null || true)" = "$MANAGER_BUILD_ID" ] || die "Manager source build identity mismatch."
  # Helpers belong to the manager/policy layer, so the same transaction installs
  # them: no service restart, no core or server-config change, no firewall or
  # certificate change, and a failure restores manager, state, helpers and
  # client exports together.
  install -d -m 0700 "$temp/helpers"
  write_state_helper > "$temp/helpers/sbox-state"
  write_policy_helper > "$temp/helpers/sbox-policy"
  python_syntax_ok "$temp/helpers/sbox-state" "$temp/helpers/sbox-policy" || die "Embedded helpers failed Python syntax validation."
  chmod 0700 "$temp/helpers/sbox-state" "$temp/helpers/sbox-policy"
  helpers_json="$(jq -n --arg state "$temp/helpers/sbox-state" --arg policy "$temp/helpers/sbox-policy" \
    --arg state_target "$LIB_DIR/sbox-state" --arg policy_target "$LIB_DIR/sbox-policy" \
    '[{source:$state,target:$state_target},{source:$policy,target:$policy_target}]')"
  policy_transaction apply "$temp/candidate.json" "$temp/render" "$source" "$helpers_json"
  [ -f /etc/fail2ban/jail.d/sbox-manager.local ] || warn "Server security setup pending: sudo sbox security setup (policy upgrade kept the server unchanged)."
  echo "Client YAML: $EXPORT_DIR/clmi-global.yaml | $EXPORT_DIR/clmi-cn.yaml | $EXPORT_DIR/clmi-internal.yaml"
)

client_policy_menu() {
  local choice
  client_policy_command show
  echo "1) Apply policy/export upgrade  2) Set primary  0) Cancel" >&2
  choice="$(prompt_choice 'Select action' '0' '0 1 2')"
  case "$choice" in
    1) client_policy_command apply ;;
    2) choice="$(prompt_choice 'Primary protocol' 'tuic' 'tuic hy2 reality anytls vmess')"; client_policy_command primary "$choice" ;;
    0) return 0 ;;
  esac
}

print_completion_summary() {
  [ -s "$STATE_FILE" ] || return 0
  echo >&2
  printf '%b%s%b\n' "$BOLD" "sbox completed successfully" "$RESET" >&2
  jq -r --arg exports "$EXPORT_DIR" '
    "  Node       : \(.node_name)",
    "  Domain     : \(.domain)",
    "  Profile    : \(.region|ascii_upcase)",
    "  sing-box   : \(.sing_box.version)",
    "  Protocols  : \([.protocols|to_entries[]|select(.value.enabled)|.key]|join(", "))",
    "  Active YAML: \($exports)/clmi.yaml",
    "  GLOBAL YAML: \($exports)/clmi-global.yaml",
    "  CN YAML    : \($exports)/clmi-cn.yaml",
    "  INTERNAL   : \($exports)/internal.yaml",
    "  Links      : \($exports)/links.txt"
  ' "$STATE_FILE" >&2
  print_required_ports "$STATE_FILE" >&2
  echo "  Client policy: 🛡 Anti-Block Auto (fallback) is the fresh default; 🧠 Smart Auto and 🔒 LOCK are optional." >&2
  echo "  Re-import the complete YAML; individual QR/node links do not carry policy groups." >&2
  echo "  Reload/reimport and select Anti-Block Auto; client-local stored choices may persist." >&2
  echo "  Fallback helps new connections; neither fallback nor LOCK prevents network loss or preserves a live call." >&2
  echo "  Commands    : sbox status | sbox client-policy show | sbox doctor" >&2
}

status_command() {
  need_root; require_installed
  local temp state active enabled firewall_active firewall_enabled restarts pid memory memory_text cli_state
  local json=false arg
  for arg in "$@"; do
    case "$arg" in
      --json) json=true ;;
      '') ;;
      *) die "Usage: sbox status [--json]" ;;
    esac
  done
  temp="$(mktemp "$RUNTIME_DIR/status.XXXXXX.json")"; normalize_state_ro "$STATE_FILE" "$temp"; state="$temp"
  active="$(systemctl is-active sing-box.service 2>/dev/null || true)"; enabled="$(systemctl is-enabled sing-box.service 2>/dev/null || true)"
  firewall_active="$(systemctl is-active sbox-manager-firewall.service 2>/dev/null || true)"; firewall_enabled="$(systemctl is-enabled sbox-manager-firewall.service 2>/dev/null || true)"
  if [ -L "$CLI_BIN" ] && [ "$(readlink -f "$CLI_BIN" 2>/dev/null || true)" = "$(readlink -f "$MANAGER_BIN" 2>/dev/null || true)" ]; then cli_state=ok; else cli_state=broken; fi
  restarts="$(systemctl show -p NRestarts --value sing-box.service 2>/dev/null || echo 0)"; pid="$(systemctl show -p MainPID --value sing-box.service 2>/dev/null || echo 0)"
  memory="$(systemctl show -p MemoryCurrent --value sing-box.service 2>/dev/null || true)"
  if [[ "$memory" =~ ^[0-9]+$ ]]; then memory_text="$(numfmt --to=iec-i --suffix=B "$memory" 2>/dev/null || echo "$memory")"; else memory_text="unknown"; fi
  # Never include credentials or protocol secrets in the machine-readable form.
  if [ "$json" = true ]; then
    jq -n --slurpfile st "$state" \
      --arg manager "$MANAGER_VERSION" --arg service "$active" --arg service_enabled "$enabled" \
      --arg firewall "$firewall_active" --arg firewall_enabled "$firewall_enabled" --arg cli "$cli_state" \
      --arg pid "$pid" --arg restarts "$restarts" --arg memory "$memory_text" \
      --arg binary "$(binary_version "$SBOX_BIN")" \
      --argjson ports "$(print_required_ports "$state" json)" \
      '{manager_version:$manager,
        region:$st[0].region,node_name:$st[0].node_name,domain:$st[0].domain,listen:$st[0].server.listen,
        sing_box:$st[0].sing_box,
        certificate:{mode:$st[0].certificate.mode,insecure:$st[0].certificate.insecure},
        firewall_enabled:$st[0].firewall.enabled,tuning_enabled:$st[0].tuning.enabled,
        block_private:$st[0].security.block_private,
        enabled_protocols:[$st[0].protocols|to_entries[]|select(.value.enabled)|.key],
        service:{active:$service,enabled:$service_enabled,pid:$pid,restarts:$restarts,memory:$memory},
        firewall_helper:{active:$firewall,enabled:$firewall_enabled},
        cli_link:$cli,binary_version:$binary,required_ports:$ports}'
    rm -f "$temp"
    return 0
  fi
  echo "===== sbox status ====="
  echo "Client policy   : 🛡 Anti-Block Auto (fresh default fallback) | 🧠 Smart Auto | 🔒 LOCK"
  jq -r '
    "Manager         : \(.manager_version)",
    "Profile         : \(.region|ascii_upcase)",
    "Node            : \(.node_name)",
    "Domain          : \(.domain)",
    "Public IPv4     : \(.server.ipv4 // "")",
    "Public IPv6     : \(.server.ipv6 // "")",
    "Listen          : \(.server.listen)",
    "Network policy  : \(.server.mode // "preserve")",
    "sing-box saved  : \(.sing_box.version) (\(.sing_box.channel))",
    "Certificate     : \(.certificate.mode)" + (if .certificate.insecure then " [INSECURE/TEST]" else "" end),
    "Local firewall  : \(.firewall.enabled)",
    "BBR/fq tuning   : \(.tuning.enabled)",
    "Block private   : \(.security.block_private)",
    "Protocols       : \([.protocols|to_entries[]|select(.value.enabled)|.key]|join(", "))"
  ' "$state"
  printf 'Service         : %s / %s\n' "$active" "$enabled"
  printf 'Firewall helper : %s / %s\n' "$firewall_active" "$firewall_enabled"
  printf 'CLI link        : %s -> %s\n' "$cli_state" "$MANAGER_BIN"
  printf 'Runtime dir     : %s\n' "$RUNTIME_DIR"
  printf 'Main PID        : %s\n' "$pid"
  printf 'Restarts        : %s\n' "${restarts:-0}"
  printf 'Memory          : %s\n' "$memory_text"
  printf 'Binary version  : %s\n' "$(binary_version "$SBOX_BIN")"
  echo
  print_required_ports "$state"
  echo
  echo "Generated files:"
  printf '  %s\n' "$EXPORT_DIR/mihomo.yaml" "$EXPORT_DIR/clmi.yaml" "$EXPORT_DIR/links.txt" "$CONFIG_FILE"
  if state_needs_certificate "$state" && resolve_service_certificate; then
    echo
    echo "Certificate:"
    openssl x509 -in "$EFFECTIVE_CERT" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'
  fi
  rm -f "$temp"
}

doctor_record() {
  local status="$1" label="$2"
  if [ "${DOCTOR_JSON:-false}" = true ]; then
    DOCTOR_CHECKS+=("$(jq -nc --arg s "$status" --arg l "$label" '{status:$s,label:$l}')")
    return 0
  fi
  case "$status" in
    ok)   printf '[OK]   %s\n' "$label" ;;
    fail) printf '[FAIL] %s\n' "$label" ;;
    warn) printf '[WARN] %s\n' "$label" ;;
    info) printf '[INFO] %s\n' "$label" ;;
  esac
}

doctor_check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    doctor_record ok "$label"
    return 0
  fi
  doctor_record fail "$label"
  return 1
}

doctor_command() {
  need_root; require_installed
  if [ "${1:-}" = --network ]; then
    shift
    write_performance_helper | python3 - --network "$@"
    return
  fi
  local temp state failures=0 warnings=0 name proto port cert key restarts memory logs cert_rule_bash
  local arg started journal_since
  DOCTOR_CHECKS=()
  for arg in "$@"; do
    case "$arg" in
      --json) DOCTOR_JSON=true ;;
      '') ;;
      *) die "Usage: sbox doctor [--json]" ;;
    esac
  done
  temp="$(mktemp "$RUNTIME_DIR/doctor.XXXXXX.json")"; normalize_state_ro "$STATE_FILE" "$temp"; state="$temp"
  [ "$DOCTOR_JSON" = true ] || echo "===== sbox doctor ====="
  doctor_check "runtime directory recreated and writable" test -d "$RUNTIME_DIR" -a -w "$RUNTIME_DIR" || failures=$((failures+1))
  doctor_check "no interrupted transaction pending recovery (run: sbox recover)" no_pending_transactions || failures=$((failures+1))
  doctor_check "state schema and values" state_tool_ro validate "$state" || failures=$((failures+1))
  if state_needs_certificate "$state"; then cert_rule_bash=true; else cert_rule_bash=false; fi
  doctor_check "certificate requirement rule agrees with the renderer" test "$cert_rule_bash" = "$(state_tool_ro cert-needed "$state")" || failures=$((failures+1))
  doctor_check "manager executable" test -x "$MANAGER_BIN" || failures=$((failures+1))
  doctor_check "manager Bash syntax" bash -n "$MANAGER_BIN" || failures=$((failures+1))
  doctor_check "manager display version" bash -c '[ "$1" = "$2" ]' _ "$("$MANAGER_BIN" version 2>/dev/null || true)" "$MANAGER_VERSION" || failures=$((failures+1))
  doctor_check "manager build identity" bash -c '[ "$1" = "$2" ]' _ "$("$MANAGER_BIN" _build-id 2>/dev/null || true)" "$MANAGER_BUILD_ID" || failures=$((failures+1))
  doctor_check "public sbox CLI link" bash -c '[ -L "$1" ] && [ "$(readlink -f "$1" 2>/dev/null)" = "$(readlink -f "$2" 2>/dev/null)" ]' _ "$CLI_BIN" "$MANAGER_BIN" || failures=$((failures+1))
  doctor_check "server JSON syntax" jq -e . "$CONFIG_FILE" || failures=$((failures+1))
  doctor_check "sing-box server config" "$SBOX_BIN" check -c "$CONFIG_FILE" || failures=$((failures+1))
  doctor_check "Mihomo GLOBAL/CN/INTERNAL YAML" validate_client_bundle "$EXPORT_DIR" || failures=$((failures+1))
  doctor_check "helpers match this manager build (runtime and persistent)" helper_files_current || failures=$((failures+1))
  doctor_check "helpers are regular root-owned files, not group/world writable" helper_files_secure || failures=$((failures+1))
  doctor_check "links export" test -s "$EXPORT_DIR/links.txt" || failures=$((failures+1))
  doctor_check "service active" systemctl is-active --quiet sing-box.service || failures=$((failures+1))
  doctor_check "service enabled for reboot" systemctl is-enabled --quiet sing-box.service || failures=$((failures+1))
  doctor_check "firewall helper active" systemctl is-active --quiet sbox-manager-firewall.service || failures=$((failures+1))
  doctor_check "firewall helper enabled for reboot" systemctl is-enabled --quiet sbox-manager-firewall.service || failures=$((failures+1))
  doctor_check "SSH Fail2Ban and early IPv4/IPv6 guard (security setup required after policy upgrade)" security_run status || failures=$((failures+1))
  doctor_check "firewall rules" firewall_rules_healthy "$state" || failures=$((failures+1))
  doctor_check "service PID/restart stability" service_stable || failures=$((failures+1))

  local singbox_pid; singbox_pid="$(singbox_main_pid)"
  while IFS=$'\t' read -r name proto port; do
    [ -n "$name" ] || continue
    doctor_check "$name listener $port/$proto owned by sing-box" listener_owned_by_singbox "$port" "$proto" "$singbox_pid" || failures=$((failures+1))
  done < <(enabled_transport_rows "$state")

  if state_needs_certificate "$state"; then
    cert="$(jq -r '.certificate.source_fullchain' "$state")"; key="$(jq -r '.certificate.source_key' "$state")"
    doctor_check "certificate source pair" certificate_pair_ok "$cert" "$key" || failures=$((failures+1))
    if resolve_service_certificate; then
    doctor_check "service certificate pair" certificate_pair_ok "$EFFECTIVE_CERT" "$EFFECTIVE_KEY" || failures=$((failures+1))
    doctor_check "certificate currently valid" cert_valid_now "$EFFECTIVE_CERT" || failures=$((failures+1))
    doctor_check "certificate covers domain" cert_matches_domain "$EFFECTIVE_CERT" "$(jq -r '.domain' "$state")" || failures=$((failures+1))
    if [ "$(jq -r '.certificate.insecure' "$state")" != true ]; then
      doctor_check "TLS server certificate chain and EKU trusted" cert_trusted "$EFFECTIVE_CERT" "$(jq -r '.domain' "$state")" || failures=$((failures+1))
    fi
    doctor_check "service certificate matches source" files_same_sha256 "$cert" "$EFFECTIVE_CERT" || failures=$((failures+1))
    doctor_check "service private key matches source" files_same_sha256 "$key" "$EFFECTIVE_KEY" || failures=$((failures+1))
    if cert_valid_week "$EFFECTIVE_CERT"; then doctor_record ok "certificate valid for more than 7 days"; else doctor_record warn "certificate expires within 7 days"; warnings=$((warnings+1)); fi
    else
      doctor_record fail "effective served certificate pair"; failures=$((failures+1))
    fi
  else
    doctor_record info "no enabled protocol requires a certificate"
  fi

  reality_fallback_doctor "$state"

  restarts="$(systemctl show -p NRestarts --value sing-box.service 2>/dev/null || echo 0)"
  memory="$(systemctl show -p MemoryCurrent --value sing-box.service 2>/dev/null || true)"
  doctor_record info "systemd NRestarts=${restarts:-0} MemoryCurrent=${memory:-unknown}"
  # Scan since the current service instance started, so entries from an earlier
  # failed transaction (already rolled back) are not reported as current
  # problems. While the service is not active, keep the plain time window so a
  # restart loop is still diagnosed.
  journal_since='-15 min'
  if systemctl is-active --quiet sing-box.service; then
    started="$(systemctl show -p ActiveEnterTimestamp --value sing-box.service 2>/dev/null || true)"
    [ -n "$started" ] && journal_since="$started"
  fi
  logs="$(journalctl --no-pager -u sing-box.service --since "$journal_since" 2>/dev/null | grep -Ei 'panic|fatal|out of memory|killed process|too many open files|cannot allocate memory' || true)"
  if [ -n "$logs" ]; then
    [ "$DOCTOR_JSON" = true ] || printf '[WARN] recent fatal/resource-related log entries found:\n%s\n' "$logs"
    doctor_record warn "fatal or resource-related log signatures since $journal_since"
    warnings=$((warnings+1))
  else
    doctor_record ok "no fatal/OOM/file-descriptor signatures since $journal_since"
  fi
  if ! systemctl is-active --quiet sing-box.service; then
    doctor_record info "sing-box is not active; recent service journal follows"
    [ "$DOCTOR_JSON" = true ] || journalctl --no-pager -u sing-box.service -n 40 2>/dev/null || true
  fi
  if ! systemctl is-active --quiet sbox-manager-firewall.service; then
    doctor_record info "firewall helper is not active; recent helper journal follows"
    [ "$DOCTOR_JSON" = true ] || journalctl --no-pager -u sbox-manager-firewall.service -n 40 2>/dev/null || true
  fi
  if [ "$DOCTOR_JSON" = true ]; then
    local checks_json='[]'
    [ "${#DOCTOR_CHECKS[@]}" -eq 0 ] || checks_json="$(printf '%s\n' "${DOCTOR_CHECKS[@]}" | jq -s .)"
    jq -n --argjson failures "$failures" --argjson warnings "$warnings" \
      --argjson checks "$checks_json" --argjson ports "$(print_required_ports "$state" json)" \
      '{failures:$failures,warnings:$warnings,checks:$checks,required_ports:$ports}'
  else
    printf 'Result: %d failure(s), %d warning(s).\n' "$failures" "$warnings"
    print_required_ports "$state"
  fi
  rm -f "$temp"
  [ "$failures" -eq 0 ]
}

restart_command() {
  need_root; require_installed; acquire_lock; guard_no_pending_transaction
  local temp
  temp="$(mktemp "$RUNTIME_DIR/restart.XXXXXX.json")"; normalize_state_to "$STATE_FILE" "$temp"
  "$SBOX_BIN" check -c "$CONFIG_FILE" || die "Current sing-box config is invalid."
  firewall_apply_file "$temp"
  systemctl restart sbox-manager-firewall.service
  systemctl reset-failed sing-box.service
  systemctl restart sing-box.service
  check_expected_listeners "$temp" 15 || die "Expected listeners did not appear after restart."
  service_stable || die "sing-box restarted again during the stability window."
  rm -f "$temp"
  ok "sing-box restarted and listeners are stable."
}

firewall_ports_command() {
  need_root; require_installed
  local format="${1:-text}" temp
  case "$format" in text|plain) format=text ;; json) ;; *) die "Usage: sbox firewall ports [text|json]" ;; esac
  temp="$(mktemp "$RUNTIME_DIR/firewall-ports.XXXXXX.json")"; normalize_state_ro "$STATE_FILE" "$temp"
  print_required_ports "$temp" "$format"
  rm -f "$temp"
}

firewall_apply_command() {
  need_root; require_installed; acquire_lock; guard_no_pending_transaction
  local temp
  temp="$(mktemp "$RUNTIME_DIR/firewall.XXXXXX.json")"; normalize_state_to "$STATE_FILE" "$temp"
  firewall_apply_file "$temp"
  firewall_rules_healthy "$temp" || die "Firewall reconciliation failed."
  rm -f "$temp"
  ok "Manager-owned firewall rules reconciled."
}

firewall_status_command() {
  need_root; require_installed
  local temp
  temp="$(mktemp "$RUNTIME_DIR/firewall-status.XXXXXX.json")"; normalize_state_ro "$STATE_FILE" "$temp"
  local panel_ok=true
  if declare -F webui_firewall_healthy >/dev/null; then webui_firewall_healthy || panel_ok=false; fi
  if firewall_rules_healthy "$temp"; then echo "Firewall rules: healthy"; else echo "Firewall rules: missing or inconsistent"; rm -f "$temp"; return 1; fi
  [ "$panel_ok" = true ] || { rm -f "$temp"; return 1; }
  iptables -w -S SBOX_INPUT 2>/dev/null || true
  iptables -w -t nat -S SBOX_NAT 2>/dev/null || true
  rm -f "$temp"
}

firewall_dispatch() {
  local sub="${1:-status}"; [ "$#" -gt 0 ] && shift || true
  case "$sub" in
    ports|required|open-ports) [ "$#" -le 1 ] || die "Too many firewall ports arguments."; firewall_ports_command "${1:-text}" ;;
    apply|reconcile) [ "$#" -eq 0 ] || die "Unexpected firewall apply argument."; firewall_apply_command ;;
    status|show) [ "$#" -eq 0 ] || die "Unexpected firewall status argument."; firewall_status_command ;;
    default-drop) [ "$#" -eq 1 ] || die "Usage: sbox firewall default-drop on|off"; firewall_default_drop_command "$1" ;;
    confirm) [ "$#" -eq 0 ] || die "Usage: sbox firewall confirm"; firewall_default_drop_command confirm ;;
    *) die "Usage: sbox firewall {ports [text|json]|apply|status|default-drop on|off|confirm}" ;;
  esac
}

# on: load the gate now with a 300 s dead-man rollback; nothing is persisted.
# confirm: after a fresh SSH login works, persist firewall.default_drop=true.
# off: persist false and remove the gate immediately.
firewall_default_drop_command() (
  set -Eeuo pipefail
  local action="$1" temp
  need_root; require_installed
  case "$action" in
    on)
      [ "$(jq -r '.firewall.enabled' "$STATE_FILE")" = true ] || die "Enable the managed firewall first."
      systemctl is-active --quiet sbox-hardening-rollback.timer 2>/dev/null && die "A trial is already pending; run sbox firewall confirm or wait for rollback."
      hardening_tool check >&2 || die "Default-drop preview failed; nothing changed."
      systemd-run --quiet --unit=sbox-hardening-rollback --on-active=300s --timer-property=AccuracySec=1s \
        /bin/bash -c 'nft delete table inet sbox_hardening 2>/dev/null; exit 0' || die "Could not arm the automatic rollback; nothing changed."
      hardening_tool apply >&2 || { systemctl stop sbox-hardening-rollback.timer 2>/dev/null || true; die "Apply failed; previous state kept."; }
      echo "Default-drop is ACTIVE ON TRIAL. Open a NEW SSH session now. If it works, run: sbox firewall confirm"
      echo "Without confirmation the gate is removed automatically in 5 minutes."
      ;;
    confirm)
      nft list table inet sbox_hardening >/dev/null 2>&1 || die "No default-drop gate is loaded; run sbox firewall default-drop on first."
      acquire_lock; guard_no_pending_transaction
      temp="$(mktemp "$RUNTIME_DIR/default-drop.XXXXXX.json")"
      jq '.firewall.default_drop=true | .updated_at=(now|todateiso8601)' "$STATE_FILE" > "$temp"
      state_tool validate "$temp"
      atomic_install "$temp" "$STATE_FILE" 0600 root root; rm -f -- "$temp"
      systemctl stop sbox-hardening-rollback.timer 2>/dev/null || true
      echo "Default-drop confirmed and persisted (re-applied at every boot by sbox-manager-firewall.service)."
      ;;
    off)
      acquire_lock; guard_no_pending_transaction
      temp="$(mktemp "$RUNTIME_DIR/default-drop.XXXXXX.json")"
      jq '.firewall.default_drop=false | .updated_at=(now|todateiso8601)' "$STATE_FILE" > "$temp"
      state_tool validate "$temp"
      atomic_install "$temp" "$STATE_FILE" 0600 root root; rm -f -- "$temp"
      systemctl stop sbox-hardening-rollback.timer 2>/dev/null || true
      hardening_tool remove >&2 || true
      echo "Default-drop disabled; previous accept-list behaviour restored."
      ;;
    *) die "Usage: sbox firewall default-drop on|off" ;;
  esac
)

links_command() {
  need_root; require_installed
  local mode="${1:-text}" label='' line
  [ -s "$EXPORT_DIR/links.txt" ] || die "Links export is missing; run sbox regenerate."
  case "$mode" in
    text) cat "$EXPORT_DIR/links.txt" ;;
    qr)
      command -v qrencode >/dev/null 2>&1 || die "qrencode is not installed. Run sbox install again or apt install qrencode."
      while IFS= read -r line; do
        case "$line" in
          \[*\]) label="${line#[}"; label="${label%]}" ;;
          vless://*|vmess://*|hysteria2://*|tuic://*|anytls://*)
            printf '\n%b%s%b\n%s\n' "$BOLD" "${label:-Node}" "$RESET" "$line"
            printf '%s' "$line" | qrencode -t ANSIUTF8
            ;;
        esac
      done < "$EXPORT_DIR/links.txt"
      ;;
    *) die "Usage: sbox links [text|qr]" ;;
  esac
}

client_files_command() {
  need_root; require_installed
  echo "Active CLMI  : $EXPORT_DIR/clmi.yaml"
  echo "GLOBAL CLMI  : $EXPORT_DIR/clmi-global.yaml"
  echo "CN CLMI      : $EXPORT_DIR/clmi-cn.yaml"
  echo "INTERNAL     : $EXPORT_DIR/internal.yaml"
  echo "INTERNAL CLMI: $EXPORT_DIR/clmi-internal.yaml"
  echo "Active Mihomo: $EXPORT_DIR/mihomo.yaml"
  echo "GLOBAL Mihomo: $EXPORT_DIR/mihomo-global.yaml"
  echo "CN Mihomo    : $EXPORT_DIR/mihomo-cn.yaml"
  echo "INTERNAL Miho: $EXPORT_DIR/mihomo-internal.yaml"
  echo "Client links : $EXPORT_DIR/links.txt"
  echo "Server JSON  : $CONFIG_FILE"
  echo "State JSON   : $STATE_FILE"
}

logs_command() {
  need_root; require_installed
  local arg="${1:-120}"
  if [ "$arg" = follow ]; then journalctl -u sing-box.service -f; else [[ "$arg" =~ ^[0-9]+$ ]] || die "LINES must be a number or follow."; journalctl --no-pager -u sing-box.service -n "$arg"; fi
}

ensure_backup_key() {
  [ -s "$BACKUP_KEY_FILE" ] && return 0
  install -d -m 0700 "$(dirname "$BACKUP_KEY_FILE")"
  local tmp; tmp="$(mktemp "$(dirname "$BACKUP_KEY_FILE")/.key.XXXXXX")"
  ( umask 077; openssl rand -hex 32 > "$tmp" )
  chmod 0600 "$tmp"; mv -f "$tmp" "$BACKUP_KEY_FILE"
  durable_paths "$BACKUP_KEY_FILE" "$(dirname "$BACKUP_KEY_FILE")"
}

# HMAC-SHA256 of a file keyed by the per-install backup key. The key is read
# from a file inside Python so it never appears in the process table.
backup_hmac() {
  local file="$1" keyfile="$2"
  SBOX_HMAC_KEY_FILE="$keyfile" python3 -I - "$file" <<'PY'
import hmac, hashlib, os, sys
key = open(os.environ['SBOX_HMAC_KEY_FILE'], 'rb').read().strip()
print(hmac.new(key, open(sys.argv[1], 'rb').read(), hashlib.sha256).hexdigest())
PY
}

create_backup_archive() {
  local label="${1:-manual}" temp payload archive stamp
  require_installed
  assert_safe_namespaces
  ensure_backup_key
  temp="$(mktemp -d "$RUNTIME_DIR/backup.XXXXXX")"; payload="$temp/payload"
  install -d -m 0700 "$payload/certs"
  normalize_state_to "$STATE_FILE" "$payload/state.json"
  install -m 0755 "$SBOX_BIN" "$payload/sing-box"
  if state_needs_certificate "$payload/state.json"; then
    resolve_service_certificate || { rm -rf "$temp"; die "Cannot back up the effective TLS pair; backup refused."; }
    install -m 0644 "$EFFECTIVE_CERT" "$payload/certs/fullchain.pem"
    install -m 0600 "$EFFECTIVE_KEY" "$payload/certs/privkey.pem"
    certificate_pair_ok "$payload/certs/fullchain.pem" "$payload/certs/privkey.pem" || { rm -rf "$temp"; die "Backup TLS pair changed while copying."; }
  fi
  if [ -d "$EXPORT_DIR" ]; then
    python3 - "$EXPORT_DIR" <<'PYEXPORTSAFE'
import sys
from pathlib import Path
root=Path(sys.argv[1])
if root.is_symlink():raise SystemExit('exports symlink refused')
for p in root.rglob('*'):
    if p.is_symlink() or not (p.is_file() or p.is_dir()):raise SystemExit('unsafe export entry')
PYEXPORTSAFE
    cp -a "$EXPORT_DIR" "$payload/exports"
  fi
  [ ! -f "$BASE_DIR/security.json" ] || install -m 0600 "$BASE_DIR/security.json" "$payload/security.json"
  if jq -e '.accounting.enabled == true' "$payload/state.json" >/dev/null; then
    python3 -B /usr/local/lib/sbox-accounting/current/accounting.py backup >&2
    install -d -m 0700 "$payload/accounting"
    install -m 0600 /var/lib/sbox-accounting/last-good.db "$payload/accounting/usage.db"
    install -m 0600 "$BASE_DIR/stats-auth.key" "$payload/accounting/stats-auth.key"
    install -m 0600 /usr/local/lib/sbox-accounting/current/core_manifest.json "$payload/accounting/core_manifest.json"
  fi
  printf '%s\n' "$MANAGER_VERSION" > "$payload/manager-version.txt"
  (cd "$payload" && find . -type f ! -name SHA256SUMS ! -name backup-auth.json -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  # Authenticate the manifest with this install's secret key. backup-auth.json
  # is intentionally NOT listed in SHA256SUMS; its HMAC covers SHA256SUMS, which
  # in turn covers every payload file (state, core, certs).
  jq -n --arg hmac "$(backup_hmac "$payload/SHA256SUMS" "$BACKUP_KEY_FILE")" \
    '{format:1,hmac_sha256_of_sha256sums:$hmac}' > "$payload/backup-auth.json"
  chmod 0600 "$payload/backup-auth.json"
  # Include a uniqueness suffix so two backups taken within the same second do
  # not overwrite each other (e.g. a scripted backup immediately before another
  # operation that also backs up).
  stamp="$(date +%Y%m%d-%H%M%S)"; archive="$BACKUP_DIR/sbox-${label}-${stamp}-$$$RANDOM.tar.gz"
  while [ -e "$archive" ]; do archive="$BACKUP_DIR/sbox-${label}-${stamp}-$$$RANDOM.tar.gz"; done
  local pending
  pending="$(mktemp "$BACKUP_DIR/.backup.XXXXXXXX")"
  tar --numeric-owner --owner=0 --group=0 -C "$temp" -czf "$pending" payload || { rm -f "$pending"; rm -rf "$temp"; return 1; }
  chmod 0600 "$pending"
  validate_backup_archive "$pending" || { rm -f "$pending"; rm -rf "$temp"; return 1; }
  durable_paths "$pending"
  mv -T -- "$pending" "$archive"
  durable_paths "$BACKUP_DIR"
  rm -rf "$temp"
  echo "$archive"
}

backup_command() {
  need_root; require_installed; acquire_lock; ensure_dirs
  local archive
  archive="$(create_backup_archive manual)"
  ok "Backup created: $archive"
  echo "$archive"
}

validate_backup_archive() {
  local archive="$1"
  [ -f "$archive" ] || die "Backup archive not found: $archive"
  python3 - "$archive" <<'PY'
import hashlib,re,resource,sys,tarfile
from pathlib import Path, PurePosixPath
resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024, 768*1024*1024))
if Path(sys.argv[1]).stat().st_size>600*1024*1024:raise SystemExit('compressed backup too large')
with tarfile.open(sys.argv[1],'r:gz') as tf:
    seen=set();total=0;files={};count=0
    for m in tf:
        count+=1
        if count>5000:raise SystemExit('invalid backup member count')
        p=PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or p.parts[0]!='payload' or '\\' in m.name or any(c in m.name for c in '\r\n\x00'):
            raise SystemExit('unsafe archive path')
        normalized=str(p)
        if normalized in seen or any(x in ('','.') for x in m.name.rstrip('/').split('/')) or not (m.isdir() or m.isfile()):raise SystemExit('duplicate, noncanonical or unsupported archive entry')
        seen.add(normalized)
        if m.isfile():
            total+=m.size
            if total>600*1024*1024:raise SystemExit('backup too large')
            files[str(p.relative_to('payload'))]=m
    if total>600*1024*1024:raise SystemExit('backup too large')
    for n in ('state.json','sing-box','SHA256SUMS'):
        if n not in files:raise SystemExit('missing '+n)
    text=tf.extractfile(files['SHA256SUMS']).read().decode('utf-8');listed={}
    for line in text.splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  (?:\./)?(.+)',line)
        if not match:raise SystemExit('invalid backup manifest')
        digest,name=match.groups()
        if name not in files or name in listed or name in ('SHA256SUMS','backup-auth.json'):raise SystemExit('invalid manifest member')
        if hashlib.sha256(tf.extractfile(files[name]).read()).hexdigest()!=digest:raise SystemExit('backup digest mismatch')
        listed[name]=digest
    if set(listed)!=set(files)-{'SHA256SUMS','backup-auth.json'}:raise SystemExit('manifest does not cover the complete payload')

PY
}

restore_command() {
  local archive='' temp root current candidate binary version restored_dir cert key insecure
  local trusted=no auth expect actual installed_ver want_core='' want_digest='' dlbin
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --core) [ "$#" -ge 2 ] || die "--core requires a value."; want_core="$2"; shift 2 ;;
      --core=*) want_core="${1#*=}"; shift ;;
      --sha256|--core-sha256) [ "$#" -ge 2 ] || die "$1 requires a value."; want_digest="$2"; shift 2 ;;
      --sha256=*|--core-sha256=*) want_digest="${1#*=}"; shift ;;
      --) shift ;;
      -*) die "Unknown restore option: $1" ;;
      *) [ -z "$archive" ] && archive="$1" || die "Unexpected argument: $1"; shift ;;
    esac
  done
  [ -n "$archive" ] || die "Usage: sbox restore <archive.tar.gz> [--core pinned|VERSION|/path/to/sing-box-or-archive [--sha256 HEX]]"
  need_root; need_systemd; check_os; guard_no_pending_transaction; install_dependencies; assert_safe_namespaces; ensure_dirs; acquire_session
  archive="$(readlink -f "$archive" 2>/dev/null || echo "$archive")"
  validate_backup_archive "$archive"
  temp="$(exec_mktemp_dir restore)"
  tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$temp"
  root="$temp/payload"
  (cd "$root" && sha256sum -c SHA256SUMS >/dev/null) || { rm -rf "$temp"; die "Backup checksum verification failed."; }

  # Trust gate. The archive's own SHA256SUMS proves only internal consistency,
  # not provenance: anyone can rebuild it around a hostile binary. A backup is
  # trusted only if its manifest HMAC verifies against THIS install's secret
  # key, i.e. it was produced here. The bundled sing-box binary is executed or
  # installed ONLY for a trusted backup. For any other archive the saved
  # configuration is restored onto the already-installed, trusted core instead,
  # and the untrusted binary is never run as root.
  auth="$root/backup-auth.json"
  if [ -s "$auth" ] && [ -s "$BACKUP_KEY_FILE" ]; then
    expect="$(jq -r '.hmac_sha256_of_sha256sums // empty' "$auth" 2>/dev/null || true)"
    actual="$(backup_hmac "$root/SHA256SUMS" "$BACKUP_KEY_FILE" 2>/dev/null || true)"
    [ -n "$expect" ] && [ "$expect" = "$actual" ] && trusted=yes
  fi
  current="$root/state.json"; candidate="$temp/state.json"
  normalize_state_to "$current" "$candidate"

  if [ "$trusted" = yes ] && [ -z "$want_core" ]; then
    binary="$root/sing-box"; chmod 0755 "$binary"
    version="$(binary_version "$binary")"; [ -n "$version" ] || { rm -rf "$temp"; die "Backup sing-box binary is invalid."; }
  else
    warn "This backup is NOT authenticated for this host (made elsewhere, pre-authentication, or tampered)."
    warn "Its bundled sing-box binary will NOT be executed or installed. The saved configuration will be restored onto the trusted core already installed here."
    if [ "$ASSUME_FORCE" != true ] && [ "$ASSUME_DEFAULTS" != true ]; then
      SBOX_ANSWER="$(yes_no 'Restore saved configuration from this unauthenticated backup onto a trusted core?' no)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { rm -rf "$temp"; echo "Cancelled."; return 0; }
    fi
    if [ -n "$want_core" ]; then
      # Disaster-recovery path: obtain a TRUSTED core from the operator-chosen
      # local source (the verified pinned core or a SHA-256-verified local
      # file; never the network) and restore the saved configuration onto it.
      # The archived binary is never executed. This is the supported backup ->
      # uninstall -> reinstall trusted core -> restore procedure (AUD-07).
      dlbin="$temp/trusted-core"
      obtain_core "$want_core" "$dlbin" "$want_digest"
      version="$(binary_version "$dlbin")"; [ -n "$version" ] || { rm -rf "$temp"; die "Supplied trusted core is invalid."; }
      core_minimum_ok "$version" || { rm -rf "$temp"; die "Supplied trusted core $version is older than the required minimum ($MIN_SINGBOX_VERSION)."; }
      binary="$dlbin"
      log "Restoring onto the operator-supplied trusted core $version; the archived binary is ignored."
    elif [ -x "$SBOX_BIN" ]; then
      installed_ver="$(binary_version "$SBOX_BIN")"
      valid_version "$installed_ver" && core_minimum_ok "$installed_ver" || { rm -rf "$temp"; die "The installed core version could not be verified; refusing to restore an unauthenticated backup onto it."; }
      binary=""   # reuse the installed, trusted core (no candidate binary)
      version="$installed_ver"
    else
      rm -rf "$temp"
      die "No trusted core is installed to restore onto. Re-run with --core pinned|/path/to/trusted/sing-box --sha256 HEX to restore the saved configuration onto a freshly obtained trusted core (the archived binary is never executed). See UPGRADE-AND-ROLLBACK for the backup->uninstall->reinstall->restore procedure."
    fi
  fi
  jq --arg version "$version" --arg manager "$MANAGER_VERSION" '.sing_box.version=$version|.sing_box.channel="fixed"|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"

  if state_needs_certificate "$candidate"; then
    cert="$root/certs/fullchain.pem"; key="$root/certs/privkey.pem"
    certificate_pair_ok "$cert" "$key" || { rm -rf "$temp"; die "Backup certificate/key pair is missing or invalid."; }
    cert_matches_domain "$cert" "$(jq -r '.domain' "$candidate")" || { rm -rf "$temp"; die "Backup certificate does not cover the saved domain."; }
    if restore_keeps_certbot_lineage "$candidate"; then
      log "Keeping the renewable Let's Encrypt lineage for $(jq -r '.domain' "$candidate"); automatic renewal stays active."
    else
      restored_dir="$BACKUP_DIR/restored-cert-$(date +%Y%m%d-%H%M%S)-$$"
      install -d -m 0700 "$restored_dir"
      install -m 0644 "$cert" "$restored_dir/fullchain.pem"; install -m 0600 "$key" "$restored_dir/privkey.pem"
      insecure="$(jq -r '.certificate.insecure' "$candidate")"
      jq --arg cert "$restored_dir/fullchain.pem" --arg key "$restored_dir/privkey.pem" --argjson insecure "$insecure" \
        '.certificate={mode:"existing",source_mode:"restored-backup",source_fullchain:$cert,source_key:$key,insecure:$insecure}' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"
    fi
  fi
  state_tool validate "$candidate"
  echo >&2; print_plan_summary "$candidate" >&2
  SBOX_ANSWER="$(yes_no 'Restore this backup?' no)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { restore_declined "${restored_dir:-}" "$temp"; return 0; }
  if jq -e '.accounting.enabled == true' "$candidate" >/dev/null; then
    ensure_service_user
    install -d -m 0700 "$temp/accounting-assets"
    write_webui_assets "$temp/accounting-assets"
    python3 -B "$temp/accounting-assets/backend/accounting_restore.py" validate "$root/accounting/usage.db"
    python3 -B "$temp/accounting-assets/backend/accounting_install.py" stage
    # Disaster recovery onto an operator-chosen trusted core (--core pinned or a
    # SHA-256-verified file) may change the engine. As for core updates, accept
    # it only with bundled/tested provenance covering all five protocols, and
    # record it as the restored accounting core.
    if [ -n "$want_core" ] && [ -n "$binary" ] && [ -f "$binary.provenance.json" ]; then
      local restore_sha; restore_sha="$(sha256sum "$binary" | cut -d' ' -f1)"
      if jq -e --arg sha "$restore_sha" '.sha256==$sha and (.tests_passed==true or .origin=="bundled") and ([.coverage.reality,.coverage.vmess,.coverage.hy2,.coverage.tuic,.coverage.anytls]|all)' "$binary.provenance.json" >/dev/null; then
        jq --arg sha "$restore_sha" '.accounting.core_sha256=$sha' "$candidate" > "$candidate.tmp" && mv "$candidate.tmp" "$candidate"
        log "Restored accounting moves to the verified core $restore_sha (bundled provenance, all five protocols)."
      fi
    fi
    [ "$(sha256sum "${binary:-$SBOX_BIN}" | cut -d' ' -f1)" = "$(jq -r .sha256 /usr/local/lib/sbox-accounting/current/core_manifest.json)" ] || die 'Restored quotas require the verified accounting core; no silent fallback is allowed. For a backup taken under another engine, restore with --core pinned.'
  fi
  SBOX_INITIALIZE_SECURITY=true RESTORE_EXPORT_SOURCE="$root/exports" apply_candidate "$candidate" "$binary" "backup restore"
  if jq -e '.accounting.enabled == true' "$candidate" >/dev/null; then
    python3 -B /usr/local/lib/sbox-accounting/current/accounting_restore.py merge "$root/accounting/usage.db" "$STATE_FILE"
    accounting_start_ready
  fi
  if state_needs_certificate "$candidate"; then
    warn "The restored service certificate is a static backup copy. Replace it with sbox certificate to restore automatic renewal."
  fi
  rm -rf "$temp"
  print_completion_summary
}

renew_test_command() {
  need_root; require_installed
  local mode domain
  mode="$(jq -r '.certificate.mode' "$STATE_FILE")"; domain="$(jq -r '.domain' "$STATE_FILE")"
  case "$mode" in certbot-dns-cloudflare|certbot-http01) ;; *) die "The active certificate is not managed by Certbot." ;; esac
  acquire_lock; guard_no_pending_transaction
  ensure_certbot "$([ "$mode" = certbot-dns-cloudflare ] && echo dns || echo http)"
  certbot renew --cert-name "$domain" --dry-run 9>&-
}

cert_deploy_command() {
  local lineage="$1" expected cert key temp state
  need_root; require_installed; acquire_lock
  lineage="$(readlink -f "$lineage" 2>/dev/null || echo "$lineage")"
  expected="$(jq -r '.certificate.source_fullchain // empty' "$STATE_FILE")"
  [ "$expected" = "$lineage/fullchain.pem" ] || { log "Renewed lineage is not active in sbox; no action taken."; return 0; }
  cert="$lineage/fullchain.pem"; key="$lineage/privkey.pem"
  certificate_pair_ok "$cert" "$key" || die "Renewed certificate/key pair is invalid."
  cert_matches_domain "$cert" "$(jq -r '.domain' "$STATE_FILE")" || die "Renewed certificate does not cover the active domain."

  guard_no_pending_transaction
  cert_valid_now "$cert" || die "Renewed certificate is expired."
  temp="$(mktemp -d "$RUNTIME_DIR/cert-deploy.XXXXXX")"
  state="$temp/state.json"; normalize_state_to "$STATE_FILE" "$state"
  # apply_candidate reuses the lock already held by this process.
  apply_candidate "$state" '' "certificate renewal deployment"
  rm -rf "$temp"
  ok "Renewed certificate deployed and verified."

}

verify_uninstalled_runtime() {
  local path tool line key val
  for path in "$BASE_DIR" "$LIB_DIR" "$CLI_BIN" "$SERVICE_FILE" "$FIREWALL_SERVICE_FILE" "$FALLBACK_WEB_SERVICE_FILE" "$SYSCTL_FILE" "$CERT_HOOK_FILE" /etc/fail2ban/jail.d/sbox-manager.local /etc/fail2ban/action.d/sbox-manager.conf /usr/local/lib/sbox-manager-security/action; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || return 1
  done
  systemctl is-active --quiet sing-box.service && return 1
  systemctl is-enabled --quiet sing-box.service && return 1
  systemctl is-active --quiet sbox-manager-firewall.service && return 1
  systemctl is-enabled --quiet sbox-manager-firewall.service && return 1
  systemctl is-active --quiet "$FALLBACK_WEB_UNIT" && return 1
  for tool in iptables ip6tables; do
    "$tool" -w -S SBOX_INPUT >/dev/null 2>&1 && return 1
    "$tool" -w -t nat -S SBOX_NAT >/dev/null 2>&1 && return 1
  done
  return 0
}

uninstall_command() {
  need_root; require_installed; acquire_session
  SBOX_ANSWER="$(yes_no 'Uninstall sbox? A final backup will be kept.' no)" || die "No answer was given (input ended); nothing was changed."; [ "$SBOX_ANSWER" = true ] || { echo "Cancelled."; return 0; }
  acquire_lock; guard_no_pending_transaction; assert_safe_namespaces
  local archive created_user=false created_group=false snap rc
  [ ! -s "$OWNERSHIP_FILE" ] || created_user="$(jq -r '.created_user // false' "$OWNERSHIP_FILE")"
  [ ! -s "$OWNERSHIP_FILE" ] || created_group="$(jq -r '.created_group // false' "$OWNERSHIP_FILE")"
  archive="$(create_backup_archive final-before-uninstall)"
  install -d -m 0700 "$TXN_SNAPSHOT_DIR"
  snap="$(mktemp -d "$TXN_SNAPSHOT_DIR/uninstall.XXXXXXXX")"
  snapshot_runtime "$snap"; write_txn_journal "$snap" uninstall
  trap '' INT TERM HUP
  set +e
  (
    set -Eeuo pipefail
    systemctl disable --now sing-box.service sbox-manager-firewall.service >/dev/null
    if [ -e "$FALLBACK_WEB_SERVICE_FILE" ] && manager_owned_file "$FALLBACK_WEB_SERVICE_FILE"; then
      systemctl disable --now "$FALLBACK_WEB_UNIT" >/dev/null; rm -f -- "$FALLBACK_WEB_SERVICE_FILE"
    fi
    # Old optional units are removed only when manager-owned.
    cleanup_old_artifacts
    security_run remove
    firewall_remove_all; close_http01_rule force
    if [ -f "$SYSCTL_FILE" ]; then restore_sysctl_baseline managed; fi
    rm -f "$SERVICE_FILE" "$FIREWALL_SERVICE_FILE" "$OLD_WATCHDOG_SERVICE" "$OLD_WATCHDOG_TIMER" "$CERT_HOOK_FILE" "$SYSCTL_FILE"
    if [ -L "$CLI_BIN" ] && [ "$(readlink -f "$CLI_BIN")" = "$MANAGER_BIN" ]; then rm -f "$CLI_BIN"; fi
    rm -rf "$BASE_DIR" "$LIB_DIR"
    systemctl daemon-reload
    verify_uninstalled_runtime
  )
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    if rollback_transaction_verified "$snap"; then
      clear_txn_journal; rm -rf -- "$snap"
      trap - INT TERM HUP
      die "Uninstall failed; previous runtime restored and verified. Final backup retained: $archive"
    fi
    trap - INT TERM HUP
    die "Uninstall failed; rollback unverified. Journal retained. Use the complete installer with recover."
  fi
  clear_txn_journal; rm -rf -- "$snap"
  trap - INT TERM HUP
  # Accounting data survives uninstall; the collector stops with the removed VPN.
  if [ -f /etc/systemd/system/sbox-accounting.service ]; then systemctl disable --now sbox-accounting.service; fi
  # Panel lifecycle cleanup follows verified VPN uninstall.
  if [ -f /etc/systemd/system/sbox-webui.service ] && [ -f /usr/local/lib/sbox-webui/current/backend/install.py ]; then
    python3 /usr/local/lib/sbox-webui/current/backend/install.py uninstall
  fi
  # Non-runtime cleanup follows the verified commit; a crash here can only leave
  # harmless owned user/key material, never erase a pending recovery pointer.
  rm -f "$SYSCTL_BASELINE_FILE" "$BACKUP_KEY_FILE"
  rmdir "$(dirname "$TXN_JOURNAL")" 2>/dev/null || true
  [ "$created_user" = true ] && id "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER" >/dev/null 2>&1 || true
  [ "$created_group" = true ] && getent group "$SERVICE_GROUP" >/dev/null 2>&1 && groupdel "$SERVICE_GROUP" >/dev/null 2>&1 || true
  rm -rf -- "$RUNTIME_DIR" >/dev/null 2>&1 || true
  ok "sbox uninstalled; runtime removal verified."
  echo "Final backup: $archive"
  echo "Let's Encrypt lineages and renewal credentials were kept. Disaster restore requires an independently trusted core."
}

menu_command() {
  local choice
  if state_exists; then
    echo
    printf '%b%s%b\n' "$BOLD" "sbox $MANAGER_VERSION" "$RESET"
    cat <<'MENU'
  1) Status
  2) Client links / QR
  3) Configure
  4) Ports / Hysteria2 hopping
  5) Protocols
  6) Rotate credentials
  7) Certificate
  8) GLOBAL/CN profile
  9) sing-box core (pinned or local verified file)
 10) Regenerate / repair
 11) Doctor
 12) Logs
 13) Backup
 14) Restore
 15) Provider firewall ports
 16) Uninstall
 17) Client policy / primary protocol (no service restart)
  0) Exit
MENU
    choice="$(prompt_choice 'Select menu item' '0' '0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17')"
    case "$choice" in
      1) status_command ;; 2) links_command qr ;; 3) configure_command ;; 4) ports_command ;;
      5) protocols_command ;; 6) rotate_command ;; 7) certificate_command ;; 8) region_command ;;
      9) update_command ;; 10) regenerate_command ;; 11) doctor_command ;; 12) logs_command 120 ;;
      13) backup_command ;; 14) read -r -p 'Backup archive path: ' choice || die "Input ended before an archive path was given."; restore_command "$choice" ;;
      15) firewall_ports_command text ;; 16) uninstall_command ;; 17) client_policy_menu ;; 0) return 0 ;;
    esac
  else
    echo
    printf '%b%s%b\n' "$BOLD" "sbox $MANAGER_VERSION - not installed" "$RESET"
    cat <<'MENU'
  1) Install GLOBAL profile
  2) Install CN profile
  3) Restore backup
  0) Exit
MENU
    choice="$(prompt_choice 'Select menu item' '0' '0 1 2 3')"
    case "$choice" in 1) install_command global ;; 2) install_command cn ;; 3) read -r -p 'Backup archive path: ' choice || die "Input ended before an archive path was given."; restore_command "$choice" ;; 0) return 0 ;; esac
  fi
}

@@HELPER_PERFORMANCE@@
@@HELPER_SECURITY@@
@@HELPER_HARDENING@@

# 1.8.0 D4: default-drop inbound gate (table inet sbox_hardening). Ports are read
# from SBOX_INPUT (owned by this manager) plus every sshd port, so it can never
# drift from the allow rules. Run from a temporary copy: nothing extra installed.
hardening_tool() {
  local t rc=0
  t="$(mktemp "$RUNTIME_DIR/sbox-hardening.XXXXXX")" || return 1
  write_hardening_helper > "$t" && python3 -I "$t" "$@" || rc=$?
  rm -f -- "$t"
  return "$rc"
}
hardening_reconcile_file() {
  local state="$1"
  if [ "$(jq -r '.firewall.enabled == true and .firewall.default_drop == true' "$state")" = true ]; then
    hardening_tool apply >&2 || warn "Default-drop gate could not be applied; previous gate (if any) kept."
  elif nft list table inet sbox_hardening >/dev/null 2>&1 && ! systemctl is-active --quiet sbox-hardening-rollback.timer 2>/dev/null \
       && ! systemctl is-active --quiet sbox-hardening-sync.timer 2>/dev/null; then
    # Not requested and no staged trial or interim 1.4.x tooling owns it: remove.
    hardening_tool remove >&2 || true
  fi
  return 0
}
security_run() (
  local tmp rc=0
  ensure_runtime_dir
  tmp="$(mktemp "$RUNTIME_DIR/security.XXXXXX.py")"
  trap 'rm -f -- "$tmp"' EXIT
  write_security_helper > "$tmp"
  python3 "$tmp" "$@" || rc=$?
  return "$rc"
)
fail2ban_jails() {
  fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' '\n' | tr -d ' \t' | grep -E '^[A-Za-z0-9_.-]+$' || true
}

security_command() {
  local sub="${1:-status}" snap rc=0
  [ "$#" -eq 0 ] || shift
  need_root; require_installed
  case "$sub" in
    status) [ "$#" -eq 0 ] || die "Unexpected argument"; security_run "$sub" ;;
    bans)
      [ "$#" -eq 0 ] || die "Unexpected argument"
      security_run bans
      # Other enabled jails (for example the distribution's own [sshd] jail)
      # can hold the same address; show them so an unban is never a surprise.
      local jail list
      for jail in $(fail2ban_jails); do
        [ "$jail" != sbox-sshd ] || continue
        list="$(fail2ban-client get "$jail" banip 2>/dev/null | tr -s ' ,' '\n\n' | grep -v '^$' | paste -sd' ' || true)"
        [ -z "$list" ] || printf 'Also banned by Fail2Ban jail %s: %s\n' "$jail" "$list"
      done ;;
    unban)
      [ "$#" -eq 1 ] || die "Usage: sbox security unban IP"
      acquire_lock; guard_no_pending_transaction
      local ip jail held=()
      ip="$(python3 -c 'import ipaddress,sys;print(ipaddress.ip_address(sys.argv[1]))' "$1")" || die "Not an IP address: $1"
      # An operator unban means "this address may connect again": remove it
      # from every jail that holds it, not only the SBOX SSH jail.
      for jail in $(fail2ban_jails); do
        fail2ban-client get "$jail" banip 2>/dev/null | tr -s ' ,' '\n\n' | grep -Fxq -- "$ip" && held+=("$jail")
      done
      if [ "${#held[@]}" -eq 0 ]; then echo "$ip is not banned by any Fail2Ban jail."; return 0; fi
      for jail in "${held[@]}"; do fail2ban-client set "$jail" unbanip "$ip" >/dev/null || die "Fail2Ban could not unban $ip from $jail."; done
      echo "Unbanned $ip from: ${held[*]}" ;;
    setup|repair)
      [ "$#" -eq 0 ] || die "Unexpected argument"
      install_dependencies
      acquire_lock; guard_no_pending_transaction; assert_safe_namespaces
      security_run preflight
      install -d -m 0700 "$TXN_SNAPSHOT_DIR"
      snap="$(mktemp -d "$TXN_SNAPSHOT_DIR/security.XXXXXXXX")"
      snapshot_runtime "$snap"; write_txn_journal "$snap" security-setup
      if security_run setup; then
        clear_txn_journal; rm -rf -- "$snap"
      else
        if rollback_transaction_verified "$snap"; then clear_txn_journal; rm -rf -- "$snap"; fi
        die "Security setup failed; inspect doctor/recovery evidence."
      fi ;;
    *) die "Usage: sbox security setup|repair|status|bans|unban IP" ;;
  esac
}
performance_command() (
  local sub="${1:-report}" tmp snap candidate mode rc=0
  [ "$#" -eq 0 ] || shift
  case "$sub" in
    report)
      # Does not require an installation, root, locks, helper reconciliation or
      # a writable /run; output is read-only and bounded.
      write_performance_helper | python3 - "$@" ;;
    apply)
      mode="${1:-}"
      [ "$#" -eq 1 ] || die "Usage: sbox performance apply baseline|legacy"
      case "$mode" in baseline|legacy) ;; *) die "Unknown tuning profile" ;; esac
      need_root; require_installed; acquire_lock; guard_no_pending_transaction; assert_safe_namespaces
      install -d -m 0700 "$TXN_SNAPSHOT_DIR"
      snap="$(mktemp -d "$TXN_SNAPSHOT_DIR/performance.XXXXXXXX")"
      snapshot_runtime "$snap"; write_txn_journal "$snap" performance-apply
      tmp="$(mktemp -d "$RUNTIME_DIR/performance.XXXXXXXX")"; candidate="$tmp/state.json"
      jq --arg mode "$mode" '.tuning.enabled=($mode=="legacy")|.updated_at=(now|todateiso8601)' "$STATE_FILE" > "$candidate"
      # Success changes only the captured tuning keys, owned file and state;
      # does not restart sing-box or disturb established connections.
      set +e
      ( set -e; SBOX_TUNING_EXPLICIT=true apply_tuning "$candidate"; atomic_install "$candidate" "$STATE_FILE" 0600 root root )
      rc=$?
      set -e
      if [ "$rc" -eq 0 ]; then
        clear_txn_journal; rm -rf -- "$snap" "$tmp"
        ok "Tuning $mode applied without a service restart. Check effective sysctls/qdisc with performance report."
      else
        if rollback_transaction_verified "$snap"; then clear_txn_journal; rm -rf -- "$snap" "$tmp"; fi
        die "Tuning apply failed; inspect recovery evidence."
      fi ;;
    tfo)
      # REALITY TCP Fast Open: one server transaction (render, core restart,
      # verified rollback). Exported Mihomo profiles gain tfo: true; clients
      # must re-import. Clients without TFO keep working unchanged.
      mode="${1:-status}"
      [ "$#" -le 1 ] || die "Usage: sbox performance tfo on|off|status"
      case "$mode" in
        status)
          need_root; require_installed
          printf 'REALITY TCP Fast Open : %s\nKernel tcp_fastopen  : %s (server bit 0x2 is set when sing-box starts)\n' \
            "$(jq -r 'if .protocols.reality.tcp_fast_open == true then "on" else "off" end' "$STATE_FILE")" "$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo unknown)" ;;
        on|off)
          need_root; require_installed; acquire_session
          tmp="$(mktemp -d "$RUNTIME_DIR/tfo.XXXXXX")"; candidate="$tmp/state.json"
          normalized_current_state "$tmp/current.json"
          jq -e '.protocols.reality.enabled == true' "$tmp/current.json" >/dev/null || { rm -rf "$tmp"; die "Enable VLESS REALITY first (sbox protocols)."; }
          jq --argjson on "$([ "$mode" = on ] && echo true || echo false)" --arg manager "$MANAGER_VERSION" \
            '.protocols.reality.tcp_fast_open=$on|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$tmp/current.json" > "$candidate"
          apply_candidate "$candidate" '' "REALITY TCP Fast Open $mode"
          rm -rf "$tmp"
          echo "Server TFO setting saved. Exported clients use ordinary TCP dialing for reliable address-family fallback." ;;
        *) die "Usage: sbox performance tfo on|off|status" ;;
      esac ;;
    vmess-mux)
      # VMess connection reuse: one server transaction (render, core restart,
      # verified rollback). The server keeps accepting plain clients; refreshed
      # YAML/JSON profiles gain sing-mux and WebSocket early data. Links/QR are unchanged.
      mode="${1:-status}"
      [ "$#" -le 1 ] || die "Usage: sbox performance vmess-mux on|off|status"
      case "$mode" in
        status)
          need_root; require_installed
          printf 'VMess connection reuse : %s\n' "$(jq -r 'if .protocols.vmess.multiplex == true then "on" else "off" end' "$STATE_FILE")" ;;
        on|off)
          need_root; require_installed; acquire_session
          tmp="$(mktemp -d "$RUNTIME_DIR/vmessmux.XXXXXX")"; candidate="$tmp/state.json"
          normalized_current_state "$tmp/current.json"
          jq -e '.protocols.vmess.enabled == true' "$tmp/current.json" >/dev/null || { rm -rf "$tmp"; die "Enable VMess first (sbox protocols)."; }
          jq --argjson on "$([ "$mode" = on ] && echo true || echo false)" --arg manager "$MANAGER_VERSION" \
            '.protocols.vmess.multiplex=$on|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$tmp/current.json" > "$candidate"
          apply_candidate "$candidate" '' "VMess connection reuse $mode"
          rm -rf "$tmp"
          echo "Saved. Clients receive the change when they refresh their subscription or re-import the YAML/JSON profile." ;;
        *) die "Usage: sbox performance vmess-mux on|off|status" ;;
      esac ;;
    dns-cache)
      # Resilient server DNS: 24 h optimistic cache in front of the local
      # resolver (keeps REALITY's remote handshake target and cached names
      # working through resolver outages). One transactional core restart.
      mode="${1:-status}"
      [ "$#" -le 1 ] || die "Usage: sbox performance dns-cache on|off|status"
      case "$mode" in
        status) need_root; require_installed
          printf 'Resilient server DNS cache : %s\n' "$(jq -r 'if .server_dns.optimistic == true then "on (24 h optimistic)" else "off" end' "$STATE_FILE")" ;;
        on|off) need_root; require_installed; acquire_session
          tmp="$(mktemp -d "$RUNTIME_DIR/dnscache.XXXXXX")"; candidate="$tmp/state.json"
          normalized_current_state "$tmp/current.json"
          jq --argjson on "$([ "$mode" = on ] && echo true || echo false)" --arg manager "$MANAGER_VERSION" \
            '.server_dns={optimistic:$on}|.manager_version=$manager|.updated_at=(now|todateiso8601)' "$tmp/current.json" > "$candidate"
          apply_candidate "$candidate" '' "resilient server DNS cache $mode"
          rm -rf "$tmp" ;;
        *) die "Usage: sbox performance dns-cache on|off|status" ;;
      esac ;;
    *) die "Usage: sbox performance report [--json] | apply baseline|legacy | tfo on|off|status | dns-cache on|off|status | vmess-mux on|off|status" ;;
  esac
)

main() {
  local command="${1:-menu}"
  [ "$#" -gt 0 ] && shift || true
  if ! state_exists; then SBOX_FRESH_INSTALL=true; else SBOX_FRESH_INSTALL=false; fi
  # --yes accepts every prompt default, which is what makes the manager usable
  # from cloud-init, Ansible and the smoke test without a terminal attached.
  local -a args=()
  local arg
  for arg in "$@"; do
    case "$arg" in
      -y|--yes|--non-interactive|--assume-defaults) ASSUME_DEFAULTS=true ;;
      --force) ASSUME_FORCE=true ;;
      *) args+=("$arg") ;;
    esac
  done
  if [ "${#args[@]}" -gt 0 ]; then set -- "${args[@]}"; else set --; fi
  # Reject ignored arguments BEFORE dispatching a mutating command.
  case "$command" in
    menu|configure|config|ports|port|protocols|protocol|regenerate|regen|repair|restart|recover|qr|client-files|files|renew-test|uninstall|remove|version|--version|-V|_build-id|help|command|commands|-h|--help|_helper-status|_firewall-apply|_firewall-remove)
      [ "$#" -eq 0 ] || die "Unexpected argument for $command: $1" ;;
    rotate|region|profile|firewall-ports|open-ports|links|url|logs|_cert-deploy|_dump-helpers)
      [ "$#" -le 1 ] || die "Too many arguments for $command." ;;
  esac
  case "$command" in
    menu) menu_command ;;
    install|reinstall) install_command "$@" ;;
    configure|config) configure_command ;;
    ports|port) ports_command ;;
    protocols|protocol) protocols_command ;;
    rotate) rotate_command "${1:-}" ;;
    certificate|cert) parse_install_options "$@"; certificate_command ;;
    region|profile) region_command "${1:-}" ;;
    update) update_command "$@" ;;
    regenerate|regen|repair) regenerate_command ;;
    upgrade-policy) client_policy_command apply "$@" ;;
    client-policy) client_policy_command "$@" ;;
    network) network_command "$@" ;;
    accounting|quota-doctor) accounting_command "$@" ;;
    quota|portal) quota_command "$command" "$@" ;;
    upgrade-features) upgrade_features_command "$@" ;;
    webui) webui_command "$@" ;;
    _webui-control) webui_control_command "$@" ;;
    performance) performance_command "$@" ;;
    security) security_command "$@" ;;
    _security-action) need_root; security_run "$@" ;;
    status) status_command "$@" ;;
    doctor|check) doctor_command "$@" ;;
    reality-fallback|fallback-web) reality_fallback_command "$@" ;;
    _fallback-unit)
      need_root; require_installed
      local unit_state; unit_state="$(mktemp "$RUNTIME_DIR/fallback-unit.XXXXXX.json")"; normalize_state_ro "$STATE_FILE" "$unit_state"
      reality_fallback_active "$unit_state" && fallback_web_unit_content "$unit_state"; rm -f "$unit_state" ;;
    restart) restart_command ;;
    recover) recover_command ;;
    firewall) firewall_dispatch "$@" ;;
    firewall-ports|open-ports) firewall_ports_command "${1:-text}" ;;
    links|url) links_command "${1:-text}" ;;
    qr) links_command qr ;;
    client-files|files) client_files_command ;;
    logs) logs_command "${1:-120}" ;;
    backup) backup_command ;;
    restore) restore_command "$@" ;;
    renew-test) renew_test_command ;;
    uninstall|remove) uninstall_command ;;
    version|--version|-V) printf '%s\n' "$MANAGER_VERSION" ;;
    _build-id) printf '%s\n' "$MANAGER_BUILD_ID" ;;
    help|command|commands|-h|--help) usage ;;
    _dump-helpers)
      [ -n "${1:-}" ] || die "_dump-helpers requires a destination directory."
      install -d -m 0700 "$1"
      write_state_helper > "$1/sbox-state"
      write_policy_helper > "$1/sbox-policy"
      chmod 0600 "$1/sbox-state" "$1/sbox-policy"
      ;;
    _helper-status)
      # Machine-readable helper provenance for tooling and the QA scripts.
      need_root
      ensure_helpers
      jq -n --arg manager "$MANAGER_VERSION" --arg build_id "$MANAGER_BUILD_ID" \
        --arg runtime_state "$(helper_sha256 "$STATE_HELPER" || echo missing)" \
        --arg runtime_policy "$(helper_sha256 "$POLICY_HELPER" || echo missing)" \
        --arg persistent_state "$(helper_sha256 "$LIB_DIR/sbox-state" || echo missing)" \
        --arg persistent_policy "$(helper_sha256 "$LIB_DIR/sbox-policy" || echo missing)" \
        --argjson current "$(helper_files_current && echo true || echo false)" \
        --argjson secure "$(helper_files_secure && echo true || echo false)" \
        '{manager_version:$manager,build_id:$build_id,runtime:{state:$runtime_state,policy:$runtime_policy},persistent:{state:$persistent_state,policy:$persistent_policy},current:$current,secure:$secure}'
      ;;
    _firewall-apply)
      need_root; require_installed
      local temp
      temp="$(mktemp "$RUNTIME_DIR/firewall-systemd.XXXXXX.json")"; normalize_state_to "$STATE_FILE" "$temp"; firewall_apply_file "$temp"
      # Boot-time hook (this unit runs before sing-box on every boot): NICs exist
      # before sysctl sets default_qdisc, so re-attach it. Best effort, never fatal.
      if jq -e '.tuning.enabled == true' "$temp" >/dev/null 2>&1; then apply_egress_qdisc || true; fi
      rm -f "$temp"
      ;;
    _firewall-remove) need_root; firewall_remove_all ;;
    _cert-deploy) [ -n "${1:-}" ] || die "_cert-deploy requires a lineage path."; cert_deploy_command "$1" ;;
    *) usage >&2; die "Unknown command: $command" ;;
  esac
}

@@WEBUI_INTEGRATION@@
main "$@"
