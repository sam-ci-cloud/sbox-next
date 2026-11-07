"""Synthetic protected hooks for builder-only tests; no real owner material."""
def protected_template(text):
    hooks = """# [ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = 24.04 ] && [ "$(uname -m)" = x86_64 ]
synthetic_protected_hooks() {
  cat <<'SBOX_SYNTHETIC_GUARDS'
.protocols == $e[0].protocols and .firewall.enabled == true and
($actual.protocols.reality == $e.protocols.reality)
.certificate=$live[0].certificate | .managed_users=($live[0].managed_users // []) | if $live[0].accounting then .accounting=$live[0].accounting else . end
SBOX_SYNTHETIC_GUARDS
}
"""
    return text.replace('@@WEBUI_INTEGRATION@@',hooks+'@@WEBUI_INTEGRATION@@')
