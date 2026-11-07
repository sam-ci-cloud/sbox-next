#!/usr/bin/env bash
# SBOX public bootstrap. A fixed content-addressed URL and its full SHA-256 are the download trust anchor.
set -Eeuo pipefail
umask 077
[ "$(id -u)" -eq 0 ] || { echo 'Run this installer as root (sudo bash).' >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'SBOX requires Linux amd64 (x86_64).' >&2; exit 1; }
for SBOX_CMD in sha256sum tar df awk mktemp rm env cp stat chmod; do
  command -v "$SBOX_CMD" >/dev/null || { echo "Missing prerequisite: $SBOX_CMD" >&2; exit 1; }
done
SBOX_USE_TTY=false
if { : </dev/tty; } 2>/dev/null; then SBOX_USE_TTY=true; fi
if [ "$#" -eq 0 ] && [ "$SBOX_USE_TTY" != true ]; then
  echo 'No controlling terminal. Run from interactive SSH, or pass complete unattended arguments with bash -s -- install generic --yes ...' >&2
  exit 1
fi
SBOX_URL='https://github.com/sam-ci-cloud/sbox-next/releases/download/pkg-d31888f10a3fc6d0/SING-BOX.tar.gz'
SBOX_SHA256='d31888f10a3fc6d03ea810933a881f3faa6a2bce43e5a093bb957ccd520f362d'
SBOX_STAGE_ROOT="${SBOX_BOOTSTRAP_TMPDIR:-/var/tmp}"
[ -d "$SBOX_STAGE_ROOT" ] && [ -w "$SBOX_STAGE_ROOT" ] || { echo 'A writable bootstrap staging directory is required.' >&2; exit 1; }
SBOX_FREE_KIB="$(df -Pk "$SBOX_STAGE_ROOT" | awk 'NR==2 {print $4}')"
[ "${SBOX_FREE_KIB:-0}" -ge 262144 ] || { echo 'Bootstrap needs 256 MiB free staging space; set SBOX_BOOTSTRAP_TMPDIR to a disk-backed directory.' >&2; exit 1; }
SBOX_STAGE="$(mktemp -d "$SBOX_STAGE_ROOT/singbox-bootstrap.XXXXXXXX")"
trap 'rm -rf -- "$SBOX_STAGE"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -n "${SBOX_INSTALL_ARCHIVE:-}" ]; then
  [ -f "$SBOX_INSTALL_ARCHIVE" ] && [ ! -L "$SBOX_INSTALL_ARCHIVE" ] || { echo 'SBOX_INSTALL_ARCHIVE must name a regular staged archive.' >&2; exit 1; }
  [ "$(stat -c %s -- "$SBOX_INSTALL_ARCHIVE")" -le 268435456 ] || { echo 'Staged archive exceeds the package size bound.' >&2; exit 1; }
  cp -- "$SBOX_INSTALL_ARCHIVE" "$SBOX_STAGE/SING-BOX.tar.gz"
  chmod 600 "$SBOX_STAGE/SING-BOX.tar.gz"
  echo 'Using staged archive; the embedded fixed SHA-256 is still mandatory.' >&2
else
  command -v curl >/dev/null || { echo 'curl is required for online installation; use the verified staged package on offline/IPv6-only networks.' >&2; exit 1; }
  if ! curl -q --proto '=https' --proto-redir '=https' -fL --connect-timeout 15 --max-time 300 --retry 2 --max-filesize 268435456 "$SBOX_URL" -o "$SBOX_STAGE/SING-BOX.tar.gz"; then
    echo 'Release download failed. Check DNS/routes. On IPv6-only networks use a trusted staged archive (SBOX_INSTALL_ARCHIVE), an explicitly configured HTTPS_PROXY, or operator-provided NAT64/DNS64. No mirrors or checksum bypass are used.' >&2
    exit 1
  fi
fi
printf '%s  %s\n' "$SBOX_SHA256" "$SBOX_STAGE/SING-BOX.tar.gz" | sha256sum -c -
if ! command -v python3 >/dev/null; then
  command -v apt-get >/dev/null || { echo 'Python 3 or apt-get is required.' >&2; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=2 update
  apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends python3
fi
python3 - "$SBOX_STAGE/SING-BOX.tar.gz" <<'SBOX_VALIDATE'
import sys,tarfile
from pathlib import PurePosixPath
seen=set();size=0;entry=False
with tarfile.open(sys.argv[1],'r:gz') as tf:
 for m in tf:
  p=PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='SING-BOX' or '\\' in m.name:
   raise SystemExit('Unsafe release archive path')
  if not(m.isfile() or m.isdir()) or m.mode&0o7022 or m.name in seen:
   raise SystemExit('Unsafe release archive member')
  seen.add(m.name);size+=m.size
  if len(seen)>10000 or size>1073741824:raise SystemExit('Oversized release archive')
  if m.name=='SING-BOX/install.sh' and m.isfile():entry=True
if not entry:raise SystemExit('Release entrypoint missing')
SBOX_VALIDATE
tar --no-same-owner --no-same-permissions -xzf "$SBOX_STAGE/SING-BOX.tar.gz" -C "$SBOX_STAGE"
echo 'Verified SBOX package (SHA-256 pinned). Starting the local installer.'
# Keep the terminal reader as sudo's direct command. A nested Bash can stop
# on SIGTTIN while its parent waits, leaving sudo unable to observe that stop.
# The verified entrypoint owns stage cleanup after this exec handoff.
export SBOX_BOOTSTRAP_STAGE="$SBOX_STAGE"
# Never let a child prompt consume unread bytes from a piped Bash script.
if [ "$SBOX_USE_TTY" = true ]; then
  exec env --default-signal=INT,QUIT,TSTP,TTIN,TTOU TMPDIR="$SBOX_STAGE_ROOT" bash "$SBOX_STAGE/SING-BOX/install.sh" "$@" </dev/tty
else
  exec env --default-signal=INT,QUIT,TSTP,TTIN,TTOU TMPDIR="$SBOX_STAGE_ROOT" bash "$SBOX_STAGE/SING-BOX/install.sh" "$@" </dev/null
fi
