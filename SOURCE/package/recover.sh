#!/usr/bin/env bash
# SING-BOX: same as 'bash install.sh recover [ARGS]'. See install.sh help.
set -Eeuo pipefail
exec bash "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/install.sh" recover "$@"
