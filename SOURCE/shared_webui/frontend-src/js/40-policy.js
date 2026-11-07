/* Client policy: what each profile does, the editable overrides, and a local
   rule tester for the custom rules (template GEOSITE/GEOIP rules are decided
   by the client's geo data and are reported as such, not guessed). */
pages.policy = async function () {
  const d = await api('policy');
  state.policy = d;
  const ro = !isAdmin();
  return `
    <p class="page-intro">${esc(bi('These settings shape the client profiles (GLOBAL, CN, INTERNAL). They do not restart the VPN. Subscriptions pick up changes on their next refresh; downloaded files must be imported again.', '這些設定決定客戶端設定檔（GLOBAL、CN、INTERNAL），不會重新啟動 VPN。訂閱會在下次更新時取得變更；下載的檔案須重新匯入。'))}${state.caps.variant === 'zgocloud' ? ' ' + esc(bi('The original ZgoCloud.yaml is never rewritten.', '原始 ZgoCloud.yaml 永不改寫。')) : ''}</p>
    <div class="grid cols-3">
      <section class="panel"><h2>GLOBAL</h2><p class="muted">${esc(bi('Local network and LAN addresses connect directly. Everything else goes through the VPN.', '本地網路及區網位址直接連線，其餘經 VPN。'))}</p></section>
      <section class="panel"><h2>CN</h2><p class="muted">${esc(bi('Like GLOBAL, and mainland China sites and IPs (GEOSITE/GEOIP CN) connect directly.', '與 GLOBAL 相同，並讓中國大陸網站與 IP（GEOSITE/GEOIP CN）直接連線。'))}</p></section>
      <section class="panel"><h2>INTERNAL</h2><p class="muted">${esc(bi('Every destination goes through the VPN. Private destinations depend on the server access policy.', '所有目的地都經 VPN。私有目的地是否可用，取決於伺服器存取政策。'))}</p></section>
    </div>
    <div class="grid cols-2 mt">
      <section class="panel"><h2>${esc(bi('Transport selection groups', '傳輸選擇群組'))}</h2>
        <dl class="kv"><dt>Anti-Block Auto</dt><dd>${esc(bi('Uses the first healthy transport in your priority order (60-second health checks). It does not compare speed. Applies to new connections; an open connection is not moved.', '依你的優先順序使用第一個健康的傳輸（每 60 秒健康檢查），不比較速度。適用於新連線，不會移動已開啟的連線。'))}</dd>
        <dt>Smart Auto</dt><dd>${esc(bi('Prefers a faster measured node when the improvement exceeds its switching tolerance. A smaller tolerance switches sooner; it cannot reduce route RTT or guarantee stability.', '當量測改善超過切換容差時，優先使用更快節點。較小容差可更早切換，但無法降低路由往返時間或保證穩定。'))}</dd>
        <dt>LOCK</dt><dd>${esc(bi('The user picks one transport manually in the app.', '使用者在應用程式中手動選擇一種傳輸。'))}</dd></dl></section>
      <section class="panel"><h2>${esc(bi('Test a destination', '測試目的地'))}</h2>
        <form id="rule-test-form" class="toolbar" novalidate>${field('target', bi('Domain or IP address', '網域或 IP 位址'), '', 'text', 'autocomplete="off" placeholder="example.com"')}<button type="submit">${esc(bi('Check', '檢查'))}</button></form>
        <div id="rule-test-out" aria-live="polite"></div></section>
    </div>
    <section class="panel mt"><h2>${esc(bi('Profile settings', '設定檔設定'))}</h2>
      <form id="policy-form" novalidate>
        <div class="form-row">
          ${select('default_group', bi('Group devices start on', '裝置預設使用的群組'), [['anti_block', bi('Anti-Block Auto (priority order)', 'Anti-Block Auto（依優先順序）')], ['smart', bi('Smart Auto (measured speed)', 'Smart Auto（依量測速度）')]], d.default_group || 'anti_block', ro ? 'disabled' : '')}
          ${select('primary', bi('First transport tried by Anti-Block Auto', 'Anti-Block Auto 優先嘗試的傳輸'), ['tuic', 'hy2', 'reality', 'anytls', 'vmess'].map(x => [x, PROTOCOL_NAMES[x]]), d.primary || 'tuic', ro ? 'disabled' : '')}
          ${field('probe_url', bi('Health-check URL (HTTPS)', '健康檢查網址（HTTPS）'), d.probe_url || 'https://www.gstatic.com/generate_204', 'url', ro ? 'disabled' : 'required')}
        </div>
        <div class="form-row">
          ${select('expected_status', bi('Successful HTTP status', '成功 HTTP 狀態'), [['204','204'],['200','200'],['200/204',bi('200 or 204','200 或 204')]], d.expected_status || '204', ro ? 'disabled' : '')}
          ${field('smart_tolerance_ms', bi('Smart Auto switching tolerance (ms)', 'Smart Auto 切換容差（毫秒）'), d.smart_tolerance_ms ?? 120, 'number', ro ? 'disabled' : 'min="10" max="300" step="1" required')}
        </div>
        <p class="muted small">${esc(bi('Use a public HTTPS HEAD endpoint without login, query tokens or redirects. All nodes use the same target/status. Tolerance: 10–300 ms; 120 ms preserves existing behavior; 50 ms is a more responsive opt-in. Fallback priority is independent. Choose Smart Auto as the starting group when some transports take a slower route for your users (for example, UDP slower than TCP). sing-box JSON has no Anti-Block group and always starts on Smart Auto. Client implementations, stored choices and manual pins can affect selection.', '請使用無登入、查詢權杖或重新導向的公開 HTTPS HEAD 網址。所有節點使用相同目標與狀態。容差10–300毫秒；120毫秒保留既有行為，50毫秒可選擇更敏捷切換。備援優先順序獨立。若部分傳輸對你的使用者走較慢路由（例如 UDP 比 TCP 慢），可將預設群組設為 Smart Auto。sing-box JSON 沒有 Anti-Block 群組，一律從 Smart Auto 開始。客戶端實作、已儲存選擇與手動固定選擇會影響結果。'))}</p>
        ${checkbox('smart_lazy', bi('Only probe Smart Auto while it is selected (saves mobile data)', '僅在選用 Smart Auto 時探測（節省行動數據）'), d.smart_lazy, ro ? 'disabled' : '')}
        <fieldset class="mt"><legend>${esc(bi('Health checks (Anti-Block Auto and Smart Auto)', '健康檢查（Anti-Block Auto 與 Smart Auto）'))}</legend>
          <div class="form-row">
            ${field('health_interval_s', bi('Check every (seconds)', '檢查間隔（秒）'), d.health_interval_s ?? 60, 'number', ro ? 'disabled' : 'min="30" max="600" step="1" required')}
            ${field('health_timeout_ms', bi('Probe timeout (ms)', '探測逾時（毫秒）'), d.health_timeout_ms ?? 5000, 'number', ro ? 'disabled' : 'min="1000" max="10000" step="100" required')}
            ${field('health_max_failed', bi('Failed connections before an immediate re-check', '觸發立即重新檢查的連線失敗次數'), d.health_max_failed ?? 2, 'number', ro ? 'disabled' : 'min="1" max="5" step="1" required')}
          </div>
          <p class="muted small" id="health-detect" aria-live="polite">${esc(healthDetectText(d.health_interval_s ?? 60, d.health_timeout_ms ?? 5000))}</p>
          <p class="muted small">${esc(bi('Defaults 60 s / 5000 ms / 2 keep the 1.7.1 behaviour. Shorter intervals find a dead transport sooner but send more probes (mobile data, battery). These settings apply to new connections only. sing-box JSON uses the interval; it has no timeout or failure-count setting.', '預設 60 秒／5000 毫秒／2 保留 1.7.1 行為。較短間隔可更快發現失效傳輸，但會發出更多探測（耗用行動數據與電量）。僅適用於新連線。sing-box JSON 只使用檢查間隔，沒有逾時或失敗次數設定。'))}</p>
        </fieldset>
        <details class="disclosure" id="policy-advanced"><summary>${esc(bi('DNS and custom rules', 'DNS 與自訂規則'))}</summary><div class="body">
          <p class="muted small">${esc(bi('Leave empty to keep the built-in templates. One resolver or rule per line. Custom rules apply to GLOBAL and CN only; INTERNAL has no direct rules: websites and private addresses go to the VPN (the VPN server connection and, in TUN mode, the device\'s own attached network stay direct).', '留空即使用內建範本。每行一個解析器或規則。自訂規則僅套用於 GLOBAL 與 CN；INTERNAL 沒有直連規則：網站及私人位址都送往 VPN（連往 VPN 伺服器的連線，以及 TUN 模式下裝置直接連接的網路，仍會直接連線）。'))}</p>
          ${['global', 'cn', 'bootstrap', 'proxy'].map(scope => `<label class="field"><span>DNS · ${esc(scope)}</span><textarea name="dns-${scope}" rows="2" ${ro ? 'disabled' : ''} placeholder="${scope === 'bootstrap' ? '1.1.1.1' : 'https://dns.example/dns-query'}">${esc(((d.dns || {})[scope] || []).join('\n'))}</textarea></label>`).join('')}
          ${select('rule_precedence', bi('Local network devices (printers, router, NAS)', '本地網絡裝置（打印機、路由器、NAS）'), [['lan_first', bi('Always connect directly (recommended)', '一律直接連線（建議）')], ['custom_first', bi('My custom rules can override this', '自訂規則可以覆蓋')]], d.rule_precedence || 'custom_first')}
          <label class="field"><span>${esc(bi('Custom rules', '自訂規則'))}</span><textarea name="rules" rows="5" ${ro ? 'disabled' : ''} placeholder="DOMAIN-SUFFIX,example.com,DIRECT">${esc((d.rules || []).join('\n'))}</textarea>
            <span class="hint">${esc(bi('Allowed: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6 with DIRECT, REJECT or 🚀 VPN. The server validates every line.', '允許：DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6，搭配 DIRECT、REJECT 或 🚀 VPN。伺服器會驗證每一行。'))}</span></label>
        </div></details>
        ${ro ? '' : `<div class="actions end mt" data-admin><button type="submit" class="primary">${esc(bi('Review change', '檢視變更'))}</button></div>`}
      </form></section>`;
};

function ipToInt(ip) { const p = ip.split('.').map(Number); return p.length === 4 && p.every(x => x >= 0 && x <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; }
// Strict IPv6 literal -> BigInt (handles :: compression and an embedded IPv4 tail).
function ipv6ToBigInt(ip) {
  let s = String(ip).toLowerCase();
  if (!s.includes(':') || !/^[0-9a-f:.]+$/.test(s)) return null;
  const v4 = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) { const n = ipToInt(v4[2]); if (n === null) return null; s = v4[1] + (n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16); }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n);
}
// Host part of a typed target: URL, host:port, [IPv6]:port, bare IPv6 or a name.
function targetHost(target) {
  let s = String(target).trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  s = s.split(/[/?#]/)[0];
  s = s.slice(s.lastIndexOf('@') + 1);
  if (s.startsWith('[')) { const end = s.indexOf(']'); return end > 0 ? s.slice(1, end) : ''; }
  if ((s.match(/:/g) || []).length > 1) return s;
  return s.split(':')[0];
}
function inCidr6(addr, cidr) {
  const [net, bits] = cidr.split('/'); const n = ipv6ToBigInt(net), b = Number(bits);
  if (n === null || !Number.isInteger(b) || b < 0 || b > 128) return false;
  const shift = BigInt(128 - b);
  return (addr >> shift) === (n >> shift);
}
function testRule(target) {
  const rules = (state.policy && state.policy.rules) || [];
  const host = targetHost(target);
  if (!host) return null;
  const ip = ipToInt(host);
  const ip6 = ip === null ? ipv6ToBigInt(host) : null;
  for (const rule of rules) {
    const [kind, value, action] = rule.split(',');
    const v = (value || '').toLowerCase();
    let hit = false;
    if (kind === 'DOMAIN') hit = host === v;
    else if (kind === 'DOMAIN-SUFFIX') hit = host === v || host.endsWith('.' + v);
    else if (kind === 'DOMAIN-KEYWORD') hit = host.includes(v);
    else if (kind === 'IP-CIDR' && ip !== null) { const [net, bits] = v.split('/'); const n = ipToInt(net); const b = Number(bits); if (n !== null && Number.isInteger(b) && b >= 0 && b <= 32) hit = b === 0 || ((ip ^ n) >>> (32 - b)) === 0; }
    else if (kind === 'IP-CIDR6' && ip6 !== null) hit = inCidr6(ip6, v);
    if (hit) return {rule, action};
  }
  return {rule: null, host};
}

/* Periodic worst case for noticing a transport that died right after a check:
   the next check plus its probe timeout. Failed real connections can trigger a
   re-check sooner, so this is an upper bound, not a typical value. */
function healthDetectText(intervalS, timeoutMs) {
  const i = Number(intervalS), t = Number(timeoutMs);
  if (!Number.isFinite(i) || !Number.isFinite(t)) return '';
  const worst = Math.round((i + t / 1000) * 10) / 10;
  return bi(`A transport that stops working is noticed within about ${worst} s (next check + timeout), or sooner when connections through it fail.`, `傳輸失效後約 ${worst} 秒內會被發現（下次檢查加逾時）；若經它的連線失敗，會更早發現。`);
}
