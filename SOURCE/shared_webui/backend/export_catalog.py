"""Single source of truth for the Connect & Export Center.

The admin console, the personal portal and the subscription landing page all render
the same choices from this catalog with the same shared component
(frontend-src/shared/export-center.js). Labels are bilingual; availability is stated
here once, so a page can never offer a format a client cannot run.
"""
import urllib.parse

PROFILES = ('global', 'cn', 'internal')
FORMATS = ('yaml', 'singbox', 'json', 'links')
FILE_NAMES = {'yaml': 'sbox-{profile}.yaml', 'singbox': 'sbox-{profile}-sing-box.json',
              'json': 'sbox-{profile}-socks.json', 'links': 'sbox-nodes.txt'}


def _t(en, zh):
    return {'en': en, 'zh': zh}


CLIENTS = [
    {'id': 'mihomo', 'label': _t('Mihomo / Clash-compatible app', 'Mihomo／Clash 相容 app'),
     'hint': _t('Clash Verge Rev, FlClash, Clash Mi and other Mihomo apps', 'Clash Verge Rev、FlClash、Clash Mi 等 Mihomo app'),
     'formats': [{'id': 'yaml', 'label': _t('Complete profile (YAML)', '完整設定檔（YAML）'),
                  'hint': _t('Routing, DNS and automatic server choice. Turn on TUN or system proxy in your app', '包含路由、DNS 及自動選擇伺服器。請在 app 內開啟 TUN 或系統代理')}]},
    {'id': 'singbox', 'label': _t('sing-box app', 'sing-box app'),
     'hint': _t('sing-box for Android, Apple platforms or the command line', 'Android、Apple 平台或命令列的 sing-box'),
     'formats': [{'id': 'singbox', 'label': _t('Complete profile (JSON, recommended)', '完整設定檔（JSON，建議）'),
                  'hint': _t('Routing, DNS, Smart Auto and a whole-device VPN (TUN). Needs sing-box 1.12 or newer', '包含路由、DNS、Smart Auto 及全機 VPN（TUN），需要 sing-box 1.12 或以上')},
                 {'id': 'json', 'label': _t('Basic local proxy (JSON)', '基本本機代理（JSON）'),
                  'hint': _t('Only a SOCKS proxy on 127.0.0.1:1080, without routing or DNS rules', '只有 127.0.0.1:1080 的 SOCKS 代理，不含路由及 DNS 規則')}]},
]

# Routing profiles a format cannot provide (see export_json.convert_full).
UNAVAILABLE = {}  # every format offers every routing profile (cn for sing-box: offline rule snapshot)

PROFILE_TEXT = {
    'global': (_t('General browsing', '一般上網'),
               _t('Websites and apps use the VPN. Private addresses and .lan/.local names (router, printer, NAS) connect directly. Your administrator\'s custom rules apply',
                  '網站及 app 經 VPN。私人位址及 .lan／.local 名稱（路由器、印表機、NAS）直接連線，並套用管理員的自訂規則')),
    'cn': (_t('Mainland China direct', '中國大陸直連'),
           _t('Like general browsing, but mainland China sites and addresses connect directly', '與一般上網相同，但中國大陸網站及位址直接連線')),
    'internal': (_t('All destinations, including private addresses', '所有目的地，包括私人位址'),
                 _t('No direct rules: websites and private addresses (10.x, 172.16–31.x, 192.168.x, .lan) are sent to the VPN, for example to reach networks behind the server. Custom rules do not apply',
                    '沒有直連規則：網站及私人位址（10.x、172.16–31.x、192.168.x、.lan）都送往 VPN，例如用於連接伺服器後方的網路。不套用自訂規則')),
}

ENDPOINT_TEXT = {
    'auto': _t('Automatic (saved setting)', '自動（已儲存設定）'),
    'domain': _t('Domain name', '網域名稱'),
    'ipv4': _t('IPv4 address', 'IPv4 位址'),
    'ipv6': _t('IPv6 address', 'IPv6 位址'),
}

METHODS = [
    {'id': 'subscription', 'label': _t('Subscription URL (recommended)', '訂閱網址（建議）'),
     'hint': _t('Your app updates the profile automatically', 'app 會自動更新設定檔')},
    {'id': 'file', 'label': _t('Static configuration file', '靜態設定檔'),
     'hint': _t('Download once. It does not update; download it again after changes', '下載一次。不會自動更新；有變更時需重新下載')},
    {'id': 'nodes', 'label': _t('Single-server links (node URI) and QR codes', '單一伺服器連結（節點 URI）及 QR 碼'),
     'hint': _t('One protocol per link, for apps that cannot import a subscription', '每條連結一個協定，供無法匯入訂閱的 app 使用')},
]

TEXT = {
    'title': _t('Connect & export', '連線與匯出'),
    'step_client': _t('Which app will you use?', '你會使用哪個 app？'),
    'step_format': _t('Configuration type', '設定檔類型'),
    'step_profile': _t('Which traffic should use the VPN?', '哪些流量經 VPN？'),
    'routing_note_title': _t('What always connects directly?', '哪些連線一律直接連線？'),
    'routing_note': _t('Whatever you choose: the connection to the VPN server itself is always direct. In whole-device (TUN) mode the network your device is directly attached to, such as your home router, usually stays reachable directly. In system-proxy mode only apps that use the system proxy are covered',
                       '無論選擇哪一項：連往 VPN 伺服器本身的連線一律直接連線。全機（TUN）模式下，裝置直接連接的網路（例如家中路由器）通常仍可直接連線。系統代理模式只涵蓋使用系統代理的 app'),
    'profile_unavailable': _t('Not available in the sing-box complete profile; use the Mihomo profile for this option', 'sing-box 完整設定檔不提供此選項；如需使用，請選 Mihomo 設定檔'),
    'step_profile_basic': _t('The basic local proxy has no routing rules; choose the complete profile for these options', '基本本機代理不含路由規則；如需這些選項，請選完整設定檔'),
    'step_endpoint': _t('VPN server address', 'VPN 伺服器位址'),
    'endpoint_hint': _t('The address your app connects to. It does not change the subscription website or the TLS name', '這是 app 連線的伺服器位址，不會更改訂閱網站或 TLS 名稱'),
    'endpoint_change': _t('Use a different server address', '使用其他伺服器位址'),
    'step_method': _t('How do you want to connect?', '你想如何連線？'),
    'summary': _t('Your selection', '你的選擇'),
    'secret': _t('Treat these links and QR codes like a password: anyone who has them can use this VPN access', '請把這些連結及 QR 碼當作密碼：任何取得的人都可使用此 VPN 存取權'),
    'copy_url': _t('Copy subscription URL', '複製訂閱網址'),
    'show_qr': _t('Show subscription QR code', '顯示訂閱 QR 碼'),
    'qr_sub_caption': _t('This QR code contains your subscription URL', '此 QR 碼包含你的訂閱網址'),
    'download': _t('Download static file', '下載靜態檔案'),
    'show_nodes': _t('Show single-server links', '顯示單一伺服器連結'),
    'copy_uri': _t('Copy link', '複製連結'),
    'node_qr': _t('Show this server\'s QR code', '顯示此伺服器的 QR 碼'),
    'qr_node_caption': _t('This QR code contains one server link only and does not update', '此 QR 碼只包含一條伺服器連結，不會自動更新'),
    'no_subscription': _t('No subscription link is active for this user. Create one, or download a file instead', '此使用者沒有有效的訂閱連結。請建立連結，或改為下載檔案'),
    'not_recoverable': _t('The active link cannot be shown again. Replace it to get a new URL, or download a file instead', '目前連結無法再次顯示。請更換連結以取得新網址，或改為下載檔案'),
    'copied': _t('Copied', '已複製'),
    'file_note': _t('A downloaded file never updates itself', '已下載的檔案不會自行更新'),
    'import_steps': [_t('In your app, add a subscription (remote profile) and paste the URL, or scan the QR code', '在 app 內新增訂閱（遠端設定檔），貼上網址或掃描 QR 碼'),
                     _t('Update the profile, choose Smart Auto or a server, then connect', '更新設定檔，選擇 Smart Auto 或伺服器，然後連線'),
                     _t('Allow the VPN or system proxy permission only when your app asks for it', '只在 app 要求時批准 VPN 或系統代理權限')],
    'nodes_note': _t('Each link contains one protocol and server only; routing and DNS choices do not apply', '每條連結只包含一個協定及伺服器；路由及 DNS 選項不適用'),
}


def endpoint_choices(endpoints):
    """Bridge endpoint options -> labelled choices; the saved default is listed first."""
    out = []
    for choice in (endpoints or {}).get('choices') or [{'id': 'auto'}]:
        if choice.get('id') not in ENDPOINT_TEXT:
            continue
        out.append({'id': choice['id'], 'label': ENDPOINT_TEXT[choice['id']], 'address': choice.get('address') or ''})
    return out or [{'id': 'auto', 'label': ENDPOINT_TEXT['auto'], 'address': ''}]


def subscription_urls(base):
    """base = <origin>/sub/<token>/ -> {profile: {format: url}}; links are profile independent."""
    return {p: {f: base + (p + '.' + f) for f in FORMATS if p not in UNAVAILABLE.get(f, ())} for p in PROFILES}


def with_endpoint(url, endpoint):
    if not url or endpoint in (None, '', 'auto'):
        return url
    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query))
    query['endpoint'] = endpoint
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


def catalog(endpoints, urls=None, state='ready', user_name=''):
    """Everything a page needs to render the Export Center. `urls` is None when no
    recoverable subscription exists; file and node exports still work then."""
    return {'schema': 1, 'user': user_name, 'clients': CLIENTS,
            'profiles': [{'id': p, 'label': PROFILE_TEXT[p][0], 'hint': PROFILE_TEXT[p][1]} for p in PROFILES],
            'endpoints': endpoint_choices(endpoints), 'methods': METHODS, 'text': TEXT,
            'files': FILE_NAMES, 'unavailable': {f: list(v) for f, v in UNAVAILABLE.items()}, 'urls': urls, 'subscription_state': state if urls else ('missing' if state in ('ready', 'none') else state)}
