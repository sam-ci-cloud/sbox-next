"""Fixed credential-free journal events; the socket peer is the only address input."""
import ipaddress
EVENTS={'login','rate-limit','portal'}
def auth_failure(peer,event):
 if event not in EVENTS:return False
 try:
  addr=ipaddress.ip_address(peer)
  if getattr(addr,'ipv4_mapped',None):addr=addr.ipv4_mapped
 except (ValueError,TypeError):return False
 try:print('SBOX_WEBUI_AUTH_FAILED ip='+str(addr)+' event='+event,flush=True)
 except (OSError,ValueError):return False
 return True
