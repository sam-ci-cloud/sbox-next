#!/usr/bin/env python3
"""Shared no-GitHub core-source migration for Universal and private ZgoCloud managers.

The current public manager carries the @@CORE_SOURCE@@ token. A manager sealed by
an older release still contains the removed GitHub API/Release/mirror download
code; ``migrate`` rewrites exactly the known sites and fails closed on anything
unrecognised, without printing private text.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = '# BEGIN SBOX LOCAL CORE SOURCE'
END = '# END SBOX LOCAL CORE SOURCE'
LEGACY_BLOCK = ['release_api_url', 'fetch_release_json', 'resolve_version', 'asset_name', 'official_asset_url',
                'release_digest', 'validate_tarball', 'download_url_with_resume', 'download_binary', 'choose_core_request']
# Literal fragments that must never survive in a built manager.
FORBIDDEN = ('api.github.com', 'github.com/SagerNet/sing-box/releases', 'ghproxy', 'gh-proxy', 'ghfast',
             'download_binary', 'CN_PROXY_PREFIXES', 'FALLBACK_STABLE_VERSION', 'SBOX_ALLOW_UNVERIFIED_MIRROR')


class MigrationError(ValueError):
    pass


def include():
    return (ROOT / 'src/core_source.sh').read_text().rstrip('\n')


def _replace(text, old, new, label, required=True):
    n = text.count(old)
    if n == 1:
        return text.replace(old, new)
    if n == 0 and not required:
        return text
    raise MigrationError('Core-source migration site not recognised: ' + label)


def _replace_any(text, pairs, label):
    for old, new in pairs:
        if text.count(old) == 1:
            return text.replace(old, new)
    raise MigrationError('Core-source migration site not recognised: ' + label)


SITES = [
    ('constants', 'MIN_SINGBOX_VERSION="${SBOX_MIN_SINGBOX_VERSION:-1.12.0}"\nFALLBACK_STABLE_VERSION="${SBOX_FALLBACK_SINGBOX_VERSION:-1.14.3}"\n',
     'MIN_SINGBOX_VERSION="${SBOX_MIN_SINGBOX_VERSION:-1.12.0}"\n'),
    ('option defaults', "OPT_propagation=''; OPT_cert_path=''; OPT_key_path=''; OPT_core=''; OPT_listen=''",
     "OPT_propagation=''; OPT_cert_path=''; OPT_key_path=''; OPT_core=''; OPT_core_sha256=''; OPT_listen=''"),
    ('mirror list', 'CN_PROXY_PREFIXES=(\n  "https://ghproxy.net/"\n  "https://gh-proxy.com/"\n  "https://ghfast.top/"\n)\n\n', ''),
    ('download validation', 'validate_download_settings() {\n  local name value\n  for name in DOWNLOAD_CONNECT_TIMEOUT DOWNLOAD_STALL_TIME DOWNLOAD_STALL_SPEED DOWNLOAD_MAX_TIME DOWNLOAD_ATTEMPTS; do\n'
     '    value="${!name}"\n    positive_integer "$value" || die "$name must be a positive integer; got: $value"\n  done\n}\n\n', ''),
    ('work dir', '  local requested="$EXEC_WORK_DIR" candidate\n  validate_download_settings\n', '  local requested="$EXEC_WORK_DIR" candidate\n'),
    ('region menu', '''  echo "VPS profile:" >&2
  echo "  1) GLOBAL - official GitHub first" >&2
  echo "  2) CN     - digest-verified mirrors first; unverified fallback needs explicit approval" >&2''', '''  echo "Default client routing profile:" >&2
  echo "  1) GLOBAL - international routing and DNS (mihomo.yaml = GLOBAL)" >&2
  echo "  2) CN     - mainland-China direct routing and DNS (mihomo.yaml = CN)" >&2'''),
    ('install core', '''  case "$requested" in latest|stable|'') channel=stable ;; beta|prerelease) channel=beta ;; *) channel=fixed ;; esac
  candidate="$temp/sing-box"
  download_binary "$requested" "$region" "$candidate"''', '''  channel=fixed
  candidate="$temp/sing-box"
  obtain_core "$requested" "$candidate" "${OPT_core_sha256:-}"'''),
    ('install downgrade', '''    case "$requested" in latest|stable|'') die "Refusing implicit reinstall downgrade to $version." ;; esac''',
     '''    case "$requested" in ''|pinned|embedded|bundled) die "Refusing implicit reinstall downgrade to $version." ;; esac'''),
    ('update command', '''update_command() {
  need_root; require_installed
  local requested="${1:-}" temp current candidate binary region version channel
  temp="$(exec_mktemp_dir update)"; current="$temp/current.json"; candidate="$temp/state.json"; binary="$temp/sing-box"
  normalized_current_state "$current"
  [ -n "$requested" ] || requested="$(choose_core_request latest)"
  region="$(jq -r '.region' "$current")"
  case "$requested" in latest|stable|'') channel=stable ;; beta|prerelease) channel=beta ;; *) channel=fixed ;; esac
  download_binary "$requested" "$region" "$binary"''', '''update_command() {
  local requested='' digest='' temp current candidate binary version channel=fixed
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --sha256|--core-sha256) [ "$#" -ge 2 ] || die "$1 requires a value."; digest="$2"; shift 2 ;;
      --sha256=*|--core-sha256=*) digest="${1#*=}"; shift ;;
      -*) die "Unknown update option: $1" ;;
      *) [ -z "$requested" ] || die "Usage: sbox update [pinned|VERSION|/path/to/sing-box-or-archive] [--sha256 HEX]"; requested="$1"; shift ;;
    esac
  done
  need_root; require_installed
  temp="$(exec_mktemp_dir update)"; current="$temp/current.json"; candidate="$temp/state.json"; binary="$temp/sing-box"
  normalized_current_state "$current"
  [ -n "$requested" ] || requested="$(choose_core_request pinned)"
  obtain_core "$requested" "$binary" "$digest"'''),
    ('update downgrade', '''  # Downgrade protection. An implicit request (latest/stable) must never move to
  # an OLDER core: that only happens when the release API is unreachable and the
  # offline fallback is older than what is installed, which would be a silent
  # downgrade the operator did not ask for. Refuse it outright. An explicit
  # version downgrade is allowed, but only with an explicit confirmation
  # (interactively, or --force for scripted use); --yes alone keeps the default
  # "No" and cancels.
  if [ -n "$installed" ] && valid_version "$installed" && version_lt "$version" "$installed"; then
    case "$requested" in
      latest|stable|'')
        rm -rf "$temp"
        die "Refusing an implicit downgrade from $installed to $version. The release API was likely unreachable and returned the offline fallback ($FALLBACK_STABLE_VERSION). To intentionally install an older core, pass the explicit version (e.g. sbox update $version --force)."
        ;;''', '''  # Downgrade protection. The implicit pinned source must never move to an
  # OLDER core than the one installed. An explicit local file may downgrade,
  # but only with an explicit confirmation (interactively, or --force for
  # scripted use); --yes alone keeps the default "No" and cancels.
  if [ -n "$installed" ] && valid_version "$installed" && version_lt "$version" "$installed"; then
    case "$requested" in
      ''|pinned|embedded|bundled)
        rm -rf "$temp"
        die "Refusing an implicit downgrade from $installed to the pinned core $version. To intentionally install an older core, pass its local file explicitly with --force."
        ;;'''),
    ('restore locals', '''  local trusted=no auth expect actual installed_ver want_core='' region dlbin''',
     '''  local trusted=no auth expect actual installed_ver want_core='' want_digest='' dlbin'''),
    ('restore options', '''      --core=*) want_core="${1#*=}"; shift ;;''', '''      --core=*) want_core="${1#*=}"; shift ;;
      --sha256|--core-sha256) [ "$#" -ge 2 ] || die "$1 requires a value."; want_digest="$2"; shift 2 ;;
      --sha256=*|--core-sha256=*) want_digest="${1#*=}"; shift ;;'''),
    ('restore usage', '''  [ -n "$archive" ] || die "Usage: sbox restore <archive.tar.gz> [--core latest|beta|VERSION|/path/to/sing-box]"''',
     '''  [ -n "$archive" ] || die "Usage: sbox restore <archive.tar.gz> [--core pinned|VERSION|/path/to/sing-box-or-archive [--sha256 HEX]]"'''),
    ('restore core', '''      # Disaster-recovery path: obtain a TRUSTED core from the operator-chosen
      # source (official release with digest verification, or a trusted local
      # binary) and restore the saved configuration onto it. The archived binary
      # is never executed. This is the supported backup -> uninstall -> reinstall
      # trusted core -> restore procedure (AUD-07).
      region="$(jq -r '.region // "global"' "$candidate")"
      dlbin="$temp/trusted-core"
      download_binary "$want_core" "$region" "$dlbin"''', '''      # Disaster-recovery path: obtain a TRUSTED core from the operator-chosen
      # local source (the verified pinned core or a SHA-256-verified local
      # file; never the network) and restore the saved configuration onto it.
      # The archived binary is never executed. This is the supported backup ->
      # uninstall -> reinstall trusted core -> restore procedure (AUD-07).
      dlbin="$temp/trusted-core"
      obtain_core "$want_core" "$dlbin" "$want_digest"'''),
    ('restore hint', 'Re-run with --core latest|beta|VERSION|/path/to/trusted/sing-box to restore',
     'Re-run with --core pinned|/path/to/trusted/sing-box --sha256 HEX to restore'),
    ('usage update', '''  region <global|cn>           Change the source order used by future core downloads
  update [latest|beta|VERSION|/path/to/sing-box]''', '''  region <global|cn>           Change the default client routing profile (mihomo.yaml)
  update [pinned|VERSION|PATH] [--sha256 HEX]
                               Reinstall the verified pinned core, or import a local
                               sing-box binary/upstream archive verified by SHA-256.
                               SBOX never downloads cores (no GitHub dependency).'''),
    ('usage restore', '''  restore <archive.tar.gz> [--core SRC]  Restore from a backup (--core to supply a trusted core for DR)''',
     '''  restore <archive.tar.gz> [--core SRC [--sha256 HEX]]
                               Restore from a backup (--core supplies a trusted local core for DR)'''),
    ('usage options', '''  --region global|cn             VPS profile
  --core latest|beta|VERSION|PATH  sing-box source (--binary is an alias for a path)''', '''  --region global|cn             Default client routing profile
  --core pinned|VERSION|PATH     sing-box source: the verified pinned core (default)
                                 or a local binary/archive (--binary is an alias)
  --core-sha256 HEX              Required SHA-256 of a local --core file when unattended'''),
    ('usage env', '''  SBOX_EXEC_WORK_DIR             Staging directory for downloaded binaries''', '''  SBOX_EXEC_WORK_DIR             Staging directory for core binaries'''),
    ('usage fallback', '''  SBOX_MIN_SINGBOX_VERSION       Minimum accepted core version (default: 1.12.0)
  SBOX_FALLBACK_SINGBOX_VERSION  Offline fallback core version (default: 1.14.3)''', '''  SBOX_MIN_SINGBOX_VERSION       Minimum accepted core version (default: 1.12.0)
  SBOX_CORE_SHA256               SHA-256 of a local core file (same as --sha256)'''),
    ('option names', '''    region|domain|node|email|cert|cf_token_file|propagation|cert_path|key_path|core|listen|''',
     '''    region|domain|node|email|cert|cf_token_file|propagation|cert_path|key_path|core|core_sha256|listen|'''),
    ('dispatch guard', '''    rotate|region|profile|update|firewall-ports|open-ports|links|url|logs|_cert-deploy|_dump-helpers)''',
     '''    rotate|region|profile|firewall-ports|open-ports|links|url|logs|_cert-deploy|_dump-helpers)'''),
    ('dispatch update', '''    update) update_command "${1:-}" ;;''', '''    update) update_command "$@" ;;'''),
    ('menu label', '''  9) Update sing-box\n''', '''  9) sing-box core (pinned or local verified file)\n'''),
]
# Sites whose legacy text differs between the public and the private manager.
ALTERNATIVES = [
    ('download settings', [
        ('DOWNLOAD_CONNECT_TIMEOUT="${SBOX_DOWNLOAD_CONNECT_TIMEOUT:-20}"\nDOWNLOAD_STALL_TIME="${SBOX_DOWNLOAD_STALL_TIME:-300}"\n'
         'DOWNLOAD_STALL_SPEED="${SBOX_DOWNLOAD_STALL_SPEED:-1024}"\nDOWNLOAD_MAX_TIME="${SBOX_DOWNLOAD_MAX_TIME:-7200}"\n'
         'DOWNLOAD_ATTEMPTS="${SBOX_DOWNLOAD_ATTEMPTS:-3}"\n', ''),
        ('DOWNLOAD_CONNECT_TIMEOUT="${SBOX_DOWNLOAD_CONNECT_TIMEOUT:-20}"\nDOWNLOAD_STALL_TIME="${SBOX_DOWNLOAD_STALL_TIME:-30}"\n'
         'DOWNLOAD_STALL_SPEED="${SBOX_DOWNLOAD_STALL_SPEED:-1024}"\nDOWNLOAD_MAX_TIME="${SBOX_DOWNLOAD_MAX_TIME:-300}"\n'
         'DOWNLOAD_ATTEMPTS="${SBOX_DOWNLOAD_ATTEMPTS:-2}"\n', '')]),
]
# Private-manager-only sites: removed when present, never required.
OPTIONAL = [
    ('zgo environment', "  validate_download_settings\n  python3 - <<'PYVALIDMGMT'\n", "  python3 - <<'PYVALIDMGMT'\n"),
    ('zgo bounds', '  # Prevent numeric overflow/unbounded custom retry loops before acquiring locks.\n'
     '  [ "$DOWNLOAD_ATTEMPTS" -le 10 ] && [ "$DOWNLOAD_MAX_TIME" -le 3600 ] && \\\n'
     '    [ "$DOWNLOAD_CONNECT_TIMEOUT" -le 300 ] && [ "$DOWNLOAD_STALL_TIME" -le 600 ] || die \'Download limits exceed safe unattended bounds.\'\n', ''),
    ('zgo channel', '  requested="${OPT_core:-${SBOX_ACCOUNTING_CORE_SOURCE:-1.13.14}}"\n'
     '  case "$requested" in latest|stable) channel=stable ;; beta|prerelease) channel=beta ;; *) channel=fixed ;; esac\n',
     '  requested="${OPT_core:-pinned}"\n  channel=fixed\n'),
    ('zgo core', '  zgo_stage core-download\n  download_binary "$requested" "$region" "$binary"\n',
     '  zgo_stage core-download\n  obtain_core "$requested" "$binary" "${OPT_core_sha256:-}"\n'),
]
INSTALL_DEFAULTS = [
    ('''    requested="$(choose_core_request "$([ -s "$existing" ] && jq -r '.sing_box.version' "$existing" || echo 1.13.14)")"''',
     '''    requested="$(choose_core_request pinned)"'''),
    ('''    requested="$(choose_core_request "$([ -s "$existing" ] && jq -r '.sing_box.version' "$existing" || echo latest)")"''',
     '''    requested="$(choose_core_request pinned)"'''),
]


def migrate(text):
    """Return text with the current shared local core source; fail closed."""
    if text.count('@@CORE_SOURCE@@') == 1:
        text = text.replace('@@CORE_SOURCE@@', include())
    elif text.count(BEGIN) == 1 and text.count(END) == 1:
        i = text.index(BEGIN)
        j = text.index(END) + len(END)
        text = text[:i] + include() + text[j:]
    else:
        start = text.find('release_api_url() {\n')
        if start < 0:
            raise MigrationError('Core-source block not recognised')
        match = re.search(r'^choose_core_request\(\) \{\n.*?^\}\n', text[start:], re.M | re.S)
        if not match:
            raise MigrationError('Core-source block end not recognised')
        block = text[start:start + match.end()]
        if re.findall(r'^([a-z_]+)\(\) \{', block, re.M) != LEGACY_BLOCK:
            raise MigrationError('Core-source block contents not recognised')
        text = text[:start] + include() + '\n' + text[start + match.end():]
        for label, old, new in SITES:
            text = _replace(text, old, new, label)
        text = _replace_any(text, INSTALL_DEFAULTS, 'install default')
        for label, pairs in ALTERNATIVES:
            text = _replace_any(text, pairs, label)
        for label, old, new in OPTIONAL:
            text = _replace(text, old, new, label, required=False)
        if 'DOWNLOAD_' in text or 'validate_download_settings' in text:
            raise MigrationError('Residual download settings not recognised')
    for fragment in FORBIDDEN:
        if fragment in text:
            raise MigrationError('Removed network core source still present')
    return text
