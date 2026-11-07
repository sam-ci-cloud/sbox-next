# BEGIN SBOX LOCAL CORE SOURCE
# Shared by the Universal and ZgoCloud managers (inserted by tools/build.py).
#
# Bundled cores install without repository access. Explicit latest/stable/beta
# requests build an upstream module with the accounting patch and real Go tests.
# Failed compatibility resolution leaves the running core untouched.
ACCOUNTING_CORE_CANDIDATE="/usr/local/lib/sbox-accounting/core-candidate"
ACCOUNTING_CORE_MANIFEST="/usr/local/lib/sbox-accounting/current/core_manifest.json"
CORE_HELP_TEXT="Use sbox update latest|stable|beta|VERSION for a tested patched source build, pinned for the bundled core, or a verified local file with --sha256 HEX."

core_resolve_build() {
  local request="$1" output="$2" resolver stage=''
  resolver="${SBOX_CORE_RESOLVER:-/usr/local/lib/sbox-webui/current/backend/core_resolver.py}"
  if [ ! -f "$resolver" ] && declare -F write_webui_assets >/dev/null; then
    stage="$(exec_mktemp_dir resolver-assets)"
    write_webui_assets "$stage"
    resolver="$stage/backend/core_resolver.py"
  fi
  [ -f "$resolver" ] || die "The compatible accounting resolver is not installed. Upgrade SBOX first."
  if ! python3 -B "$resolver" "$request" --output "$output"; then
    [ -z "$stage" ] || rm -rf -- "$stage"
    die "No compatible accounting update was applied; the current core is retained."
  fi
  [ -z "$stage" ] || rm -rf -- "$stage"
}

valid_sha256() { [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]; }

# Prints the explicit digest for a local core file, or fails when none is given.
core_expected_sha256() {
  local path="$1" explicit="${2:-${SBOX_CORE_SHA256:-}}" sidecar value
  if [ -n "$explicit" ]; then
    explicit="${explicit,,}"
    valid_sha256 "$explicit" || die "Core SHA-256 must be exactly 64 hexadecimal characters."
    printf '%s\n' "$explicit"; return 0
  fi
  for sidecar in "$path.sha256" "$path.sha256sum"; do
    [ -e "$sidecar" ] || continue
    [ -f "$sidecar" ] && [ ! -L "$sidecar" ] || die "Unsafe SHA-256 sidecar (not a regular file): $sidecar"
    value="$(head -c 4096 -- "$sidecar" | awk 'NF {print tolower($1); exit}')"
    valid_sha256 "$value" || die "Invalid SHA-256 sidecar: $sidecar"
    printf '%s\n' "$value"; return 0
  done
  return 1
}

# Prints the path of the verified pinned core, or fails.
pinned_core_file() {
  local expected
  if [ -n "${SBOX_ACCOUNTING_CORE_SOURCE:-}" ]; then
    # The all-in-one installer authenticated this file against its embedded
    # manifest before exporting the path.
    [ -f "$SBOX_ACCOUNTING_CORE_SOURCE" ] && [ ! -L "$SBOX_ACCOUNTING_CORE_SOURCE" ] || return 1
    printf '%s\n' "$SBOX_ACCOUNTING_CORE_SOURCE"; return 0
  fi
  [ -f "$ACCOUNTING_CORE_CANDIDATE" ] && [ ! -L "$ACCOUNTING_CORE_CANDIDATE" ] && [ -s "$ACCOUNTING_CORE_MANIFEST" ] || return 1
  expected="$(jq -r '.sha256 // empty' "$ACCOUNTING_CORE_MANIFEST" 2>/dev/null || true)"
  valid_sha256 "$expected" || return 1
  [ "$(sha256sum "$ACCOUNTING_CORE_CANDIDATE" | awk '{print $1}')" = "$expected" ] || return 1
  printf '%s\n' "$ACCOUNTING_CORE_CANDIDATE"
}

validate_tarball() {
  local archive="$1" version="$2" arch="$3" expected
  expected="sing-box-${version}-linux-${arch}/sing-box"
  [ -s "$archive" ] || return 1
  local size
  size="$(wc -c < "$archive")"
  [ "$size" -gt 1000000 ] && [ "$size" -le 268435456 ] || return 1
  gzip -t "$archive" >/dev/null 2>&1 || return 1
  python3 - "$archive" "$expected" <<'PY' >/dev/null 2>&1
import resource, sys, tarfile
resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024, 768*1024*1024))
archive, expected = sys.argv[1:3]
with tarfile.open(archive, 'r:gz') as tf:
    matches=[]; count=0; total=0
    for m in tf:
        count+=1
        total+=m.size if m.isfile() else 0
        if count>10000 or total>1073741824:raise SystemExit(1)
        if m.name.startswith('/') or '..' in m.name.split('/'): raise SystemExit(1)
        if m.name==expected: matches.append(m)
    if len(matches)!=1 or not matches[0].isfile() or not 1000000 <= matches[0].size <= 200000000: raise SystemExit(1)
PY
}

# Version encoded in an upstream archive file name; prints nothing if absent.
core_archive_version() {
  local name="${1##*/}" arch="$2"
  [[ "$name" =~ ^sing-box-([0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.-]*)?)-linux-${arch}\.tar\.gz$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

# obtain_core SOURCE OUTPUT [SHA256]: copy a verified core to OUTPUT, writing
# OUTPUT.version. Never uses the network.
obtain_core() {
  local requested="${1:-}" output="$2" digest_arg="${3:-}" path='' pinned='' version='' arch expected actual tmpdir='' observed version_output resolver
  case "$requested" in
    ''|pinned|embedded|bundled)
      pinned="$(pinned_core_file)" || die "No verified pinned core is available on this host. $CORE_HELP_TEXT"
      path="$pinned" ;;
    latest|stable|beta|prerelease)
      core_resolve_build "$requested" "$output"
      return 0 ;;
    file://*) path="${requested#file://}" ;;
    /*) path="$requested" ;;
    *)
      valid_version "${requested#v}" || die "Core source must be 'pinned', the exact pinned x.y.z version, or an absolute local path. $CORE_HELP_TEXT"
      pinned="$(pinned_core_file || true)"
      if [ -n "$pinned" ] && [ "$(binary_version "$pinned")" = "${requested#v}" ]; then
        version="${requested#v}"; path="$pinned"
      else
        core_resolve_build "${requested#v}" "$output"
        return 0
      fi ;;
  esac
  case "$path" in /*) ;; *) die "Core path must be absolute: $path" ;; esac
  if [ -z "$pinned" ] && [ -n "${SBOX_ACCOUNTING_CORE_SOURCE:-}" ] && [ "$path" = "$SBOX_ACCOUNTING_CORE_SOURCE" ]; then
    pinned="$(pinned_core_file)" || die "The installer-supplied core is unavailable."
  fi
  if [ -z "$pinned" ]; then
    [ -e "$path" ] || die "Local core file does not exist: $path"
    path="$(readlink -f -- "$path")" || die "Cannot resolve local core path."
    [ -f "$path" ] || die "Local core source is not a regular file: $path"
    actual="$(sha256sum -- "$path" | awk '{print $1}')"
    if expected="$(core_expected_sha256 "$path" "$digest_arg")"; then
      [ "$actual" = "$expected" ] || die "SHA-256 mismatch for $path: expected $expected, observed $actual. The file was rejected."
      log "Local core file SHA-256 verified: $actual"
    else
      if gzip -t -- "$path" >/dev/null 2>&1; then
        die "A core archive must be authenticated: pass --sha256 HEX, set SBOX_CORE_SHA256 or place $path.sha256 next to it."
      fi
      warn "No SHA-256 was supplied for $path. Observed SHA-256: $actual"
      warn "Compare it with a digest from a trusted channel before accepting (--sha256 HEX makes this unattended)."
      [ "$ASSUME_DEFAULTS" != true ] || [ "$ASSUME_FORCE" = true ] || die "Unattended use of a local core requires --sha256 HEX (or --force to accept the printed digest)."
      [ "$(yes_no 'Trust this unauthenticated local core binary?' no)" = true ] || die "Unauthenticated local core rejected."
    fi
    if gzip -t -- "$path" >/dev/null 2>&1; then
      arch="$(detect_arch)"
      version="$(core_archive_version "$path" "$arch")" || die "Core archive name must be sing-box-X.Y.Z-linux-$arch.tar.gz."
      validate_tarball "$path" "$version" "$arch" || die "Core archive structure is invalid or unsafe: $path"
      tmpdir="$(exec_mktemp_dir core-import)"
      tar --no-same-owner --no-same-permissions -xzf "$path" -C "$tmpdir" -- "sing-box-${version}-linux-${arch}/sing-box" || { rm -rf -- "$tmpdir"; die "Core archive extraction failed."; }
      path="$tmpdir/sing-box-${version}-linux-${arch}/sing-box"
    fi
  fi
  install -m 0755 -- "$path" "$output"
  [ -z "$tmpdir" ] || rm -rf -- "$tmpdir"
  if ! version_output="$("$output" version 2>&1)"; then
    rm -f -- "$output"
    die "The core binary cannot execute here: ${version_output:-unknown execution error}"
  fi
  observed="$(awk '/sing-box version/{print $3; exit}' <<< "$version_output")"
  valid_version "$observed" || { rm -f -- "$output"; die "Cannot read the core version."; }
  [ -z "$version" ] || [ "$observed" = "$version" ] || { rm -f -- "$output"; die "Core version mismatch: expected $version, binary reports $observed."; }
  core_minimum_ok "$observed" || { rm -f -- "$output"; die "sing-box $observed is older than the required minimum ($MIN_SINGBOX_VERSION)."; }
  echo "$observed" > "$output.version"
  if [ -n "$pinned" ]; then
    jq -n --arg sha "$(sha256sum "$output" | cut -d' ' -f1)" --arg version "$observed" \
      '{origin:"bundled",sha256:$sha,version:$version,coverage:{reality:true,vmess:true,hy2:true,tuic:true,anytls:true}}' > "$output.provenance.json"
  fi
}

choose_core_request() {
  local current="${1:-pinned}" choice value default=1
  case "$current" in /*|file://*) default=2 ;; esac
  echo >&2
  echo "sing-box accounting core:" >&2
  echo "  1) Verified pinned core from this SBOX package (enables user accounting)" >&2
  echo "  2) Local file: sing-box binary or upstream archive, verified by SHA-256" >&2
  echo "  3) Latest compatible stable: build and test the accounting patch" >&2
  echo "  4) Exact upstream version: build and test the accounting patch" >&2
  echo "  5) Preview channel: build and test the accounting patch" >&2
  choice="$(prompt_choice 'Select source' "$default" '1 2 3 4 5')"
  case "$choice" in
    1) echo pinned ;;
    3) echo latest ;;
    4) value="$(ask 'Exact engine version' '')"; valid_version "${value#v}" || die 'Invalid version'; echo "${value#v}" ;;
    5) echo beta ;;
    2)
      value="$(ask 'Absolute path to the binary or archive' '/root/sing-box')"
      case "$value" in /*|file:///*) echo "$value" ;; *) die "Core path must be absolute." ;; esac ;;
  esac
}
# END SBOX LOCAL CORE SOURCE
