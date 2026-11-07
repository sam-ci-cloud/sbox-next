/* Alerts, protocol health, host traffic and diagnostics. */
const SEV = {critical: ['error', 'Critical', '嚴重'], warning: ['warning', 'Warning', '警告'], info: ['info', 'Info', '資訊'], ok: ['ok', 'Recovered', '已恢復']};
const sevStatus = s => { const x = SEV[s] || SEV.info; return status(x[0], bi(x[1], x[2])); };

pages.alerts = async function () {
  const d = await api('alerts');
  const open = d.alerts.filter(a => !a.resolved_at), resolved = d.alerts.filter(a => a.resolved_at);
  state.alertsOpen = open.length; state.alertsWorst = open.some(a => a.severity === 'critical') ? 'critical' : open.length ? 'warning' : null; renderNav();
  const silenced = d.silenced_until && d.silenced_until * 1000 > Date.now();
  const card = a => `<li>${a.resolved_at ? status('ok', bi('Resolved', '已解決')) : sevStatus(a.severity)}<div class="what"><strong>${esc(a.title)}</strong><p>${esc(a.detail)}</p>
      <p class="source">${esc(a.source)}</p><p class="muted small">${esc(bi('First seen', '首次發現'))} ${esc(when(a.first_seen))} · ${esc(bi('last seen', '最後發現'))} ${esc(when(a.last_seen))} · ${esc(bi(`${a.count} checks`, `${a.count} 次檢查`))}${a.resolved_at ? ' · ' + esc(bi('resolved', '解決於')) + ' ' + esc(when(a.resolved_at)) : ''}</p></div><span class="when">${esc(ago(a.resolved_at || a.first_seen))}</span></li>`;
  return `
    <p class="page-intro">${esc(bi('Alerts are evaluated on this server every 30 seconds (Doctor checks hourly). Each problem opens one alert, which is updated while it lasts and closed when it recovers.', '警示每 30 秒在本伺服器評估（Doctor 每小時檢查）。每個問題只開啟一個警示，持續期間更新，恢復後關閉。'))}</p>
    <div class="actions">${isAdmin() ? `<span data-admin>${btn('alerts-check', bi('Check now', '立即檢查'), 'primary')} ${btn('alerts-check-doctor', bi('Check now, including Doctor', '立即檢查（含 Doctor）'))}</span>` : ''}
      <span class="meta">${d.notifications ? status('ok', bi('Notifications on', '通知已開啟')) : status('off', bi('Notifications off', '通知已關閉'))} ${silenced ? status('warning', bi('Silenced until ', '靜音至 ') + when(d.silenced_until, {short: true})) : ''}</span></div>
    ${d.notification_outbox?.pending?`<p class="notice warning" role="status">${esc(bi('Queued notifications','排程中的通知'))}: ${d.notification_outbox.pending} · ${esc(bi('Next retry','下次重試'))} ${esc(when(d.notification_outbox.next_retry_at))} · ${esc(d.notification_outbox.last_error||'')}</p>`:''}
    <div class="section-title"><h2>${esc(bi('Open', '未解決'))} (${open.length})</h2></div>
    <section class="panel">${open.length ? `<ul class="plain attention">${open.map(card).join('')}</ul>` : `<p>${status('ok', bi('No open alerts', '沒有未解決警示'))}</p>`}</section>
    <div class="section-title"><h2>${esc(bi('Resolved in the last 7 days', '最近 7 天已解決'))} (${resolved.length})</h2></div>
    <section class="panel">${resolved.length ? `<ul class="plain attention">${resolved.slice(0, 30).map(card).join('')}</ul>` : `<p class="muted">${esc(bi('None.', '無。'))}</p>`}</section>
    <div class="grid cols-2 mt">
      <section class="panel"><h2>${esc(bi('Timeline', '時間軸'))}</h2>${d.timeline.length ? `<ol class="timeline">${d.timeline.slice(0, 60).map(e => `<li class="${esc(e.severity)}"><time>${esc(when(e.time))}</time> <strong>${esc(e.title)}</strong>${e.detail ? `<p>${esc(e.detail)}</p>` : ''}<p class="source">${esc(e.source)}</p></li>`).join('')}</ol>` : `<p class="muted">${esc(bi('Nothing recorded yet.', '尚無紀錄。'))}</p>`}</section>
      <section class="panel"><h2>${esc(bi('Rules and notifications', '規則與通知'))}</h2><p class="muted small">${esc(d.rules)}</p>
        <p class="muted small">${esc(bi('Notifications are sent only when an alert opens, escalates or recovers, never for every check. Configure the destination under System → Accounts & notifications.', '通知只在警示開啟、升級或恢復時發送，不會每次檢查都發送。請在「系統 → 帳戶與通知」設定目的地。'))}</p>
        ${isAdmin() ? `<form id="silence-form" class="toolbar" data-admin novalidate>${select('minutes', bi('Silence notifications (maintenance)', '靜音通知（維護）'), [[0, bi('Not silenced', '不靜音')], [30, bi('30 minutes', '30 分鐘')], [120, bi('2 hours', '2 小時')], [720, bi('12 hours', '12 小時')], [1440, bi('24 hours', '24 小時')]], silenced ? 30 : 0)}<button type="submit">${esc(bi('Save', '儲存'))}</button></form>` : ''}</section>
    </div>`;
};

pages.health = async function () {
  const d = await api('protocols/health');
  const probeWord = p => ({ok: status('ok', bi('Passed', '通過')), warning: status('warning', bi('Warning', '警告')), error: status('error', bi('Failed', '失敗')), 'not-probed': status('info', bi('Not probed', '未探測')), 'not-run': status('unknown', bi('Not run', '未執行'))}[p.status] || status('unknown'));
  return `
    <p class="page-intro">${esc(bi('Each protocol is checked in layers. Local checks run on this server only. "External" stays Not tested until a real client on another network has connected; this panel never claims it.', '每種協定分層檢查。本機檢查只在本伺服器執行。「外部」在其他網路的真實客戶端連線前一律顯示未測試，面板不會自行宣稱。'))}</p>
    <div class="actions">${isAdmin() ? btn('run-probe', bi('Check on this server', '在伺服器上檢查'), 'primary') : ''}<span class="meta">${esc(bi('Results are cached for 30 seconds; probes only use the loopback interface.', '結果快取 30 秒；探測只使用本機回送介面。'))}</span></div>
    <div class="table-wrap mt"><table><caption class="sr">${esc(bi('Protocol health matrix', '協定健康矩陣'))}</caption>
      <thead><tr><th scope="col">${esc(bi('Protocol', '協定'))}</th><th scope="col">${esc(bi('Port', '連接埠'))}</th><th scope="col">${esc(bi('Listening', '監聽'))}</th><th scope="col">${esc(bi('Local probe', '本機探測'))}</th><th scope="col">${esc(bi('Certificate', '憑證'))}</th><th scope="col">${esc(bi('External', '外部'))}</th></tr></thead>
      <tbody>${d.protocols.map(p => `<tr><td><strong>${esc(PROTOCOL_NAMES[{vless: 'reality', vmess: 'vmess', hysteria2: 'hy2', tuic: 'tuic', anytls: 'anytls'}[p.type]] || p.type)}</strong><br><span class="muted small">${esc(p.tls)}</span></td>
        <td class="nowrap"><code>${esc(p.port)}/${esc(p.network)}</code></td>
        <td>${p.listening ? status('ok', bi('Yes', '是')) : status('error', bi('No', '否'))}</td>
        <td>${probeWord(p.local_probe)}<br><span class="muted small">${esc(p.local_probe.detail || '')}${p.local_probe.latency_ms !== undefined ? ' (' + esc(p.local_probe.latency_ms) + ' ms)' : ''}</span></td>
        <td>${p.certificate === null ? `<span class="muted small">${esc(bi('REALITY uses no certificate', 'REALITY 不使用憑證'))}</span>` : p.certificate === 'valid' ? status('ok', bi('Valid', '有效')) : status('warning', bi('Check', '請檢查'))}</td>
        <td>${status('unknown', bi('Not tested', '未測試'))}</td></tr>`).join('')}</tbody></table></div>
    <div class="section-title"><h2>${esc(bi('Port-hopping aliases', '跳埠別名'))}</h2></div>
    <section class="panel">${d.aliases.length ? d.aliases.map(a => `<p><code>${esc(a.range)}/udp</code> → <code>${esc(a.target_port)}/udp</code> ${a.target_listening ? status('ok', bi('target listening', '目標監聽中')) : status('error', bi('target not listening', '目標未監聽'))}</p><p class="muted small">${esc(a.note)}</p>`).join('') : `<p class="muted">${esc(bi('No hopping ranges configured.', '尚未設定跳埠範圍。'))}</p>`}${source(d.source)}</section>`;
};

function chartSvg(series, height = 240) {
  return adaptiveChart({kind: 'network', points: series.points || [], keys: ['rx_bps', 'tx_bps'],
    start: series.start, end: series.end, window_seconds: series.window_seconds, height,
    label: bi('Server receive and send rates over the selected range. Gaps mean measurements are missing.', '所選範圍的伺服器接收與傳送速率。斷開位置代表缺少測量記錄。')});
}

const HOST_WINDOWS = ['1h', '6h', '24h', '7d', '30d', 'custom'];
function hostRange(key) {
  const now = Math.floor(Date.now()/1000);
  return state[key+'Range'] || {start: now-3600, end: now};
}
function hostRangeQuery(key) {
  const window = state[key+'Window'] || '1h';
  return new URLSearchParams(window === 'custom' ? {window, ...hostRange(key)} : {window}).toString();
}
function hostRangeControls(key) {
  const window = state[key+'Window'] || '1h', range = hostRange(key);
  const local = value => {const date=new Date(value*1000); return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);};
  return `<div class="host-range-controls"><div class="segmented" role="group" aria-label="${esc(bi('Time window','時間範圍'))}">${HOST_WINDOWS.map(w=>btn('host-window',w==='custom'?bi('Custom','自訂'):w,'',`data-key="${key}" data-window="${w}" aria-pressed="${window===w}"`)).join('')}</div>${window==='custom'?`<form id="host-range-form" class="toolbar"><input type="hidden" name="key" value="${key}">${field('start',bi('From (browser local time)','開始（瀏覽器本地時間）'),local(range.start),'datetime-local','required')}${field('end',bi('To (browser local time)','結束（瀏覽器本地時間）'),local(range.end),'datetime-local','required')}<button type="submit">${esc(bi('Apply range','套用範圍'))}</button></form>`:''}</div>`;
}

pages.traffic = async function () {
  const w = state.trafficWindow;
  const d = await api('traffic?' + hostRangeQuery('traffic'));
  const s = d.stats || {};
  const chart = chartSvg(d);
  const rows = (d.points || []).filter(p => !p.gap).slice(-50);
  return `
    <p class="page-intro">${esc(bi('Receive and transmit rates of this host, calculated from Linux interface counters sampled every 30 seconds. They include all services on the server and are not per-user VPN accounting. A counter reset or reboot drops that interval instead of drawing a false spike; a sampling gap is shown as a break, not a flat line.', '本主機的接收與傳送速率，由每 30 秒採樣的 Linux 介面計數器計算。包含伺服器所有服務，並非個別使用者 VPN 計量。計數器重設或重新開機時會捨棄該區間，不會畫出假尖峰；採樣中斷顯示為斷線，而非平線。'))}</p>
    <div class="actions">${hostRangeControls('traffic')}
      <span class="legend"><span><span class="swatch"></span>${esc(bi('Receive (in)', '接收（入）'))}</span><span><span class="swatch tx"></span>${esc(bi('Transmit (out)', '傳送（出）'))}</span></span></div>
    <section class="panel mt">${chart || `<div class="empty"><strong>${esc(bi('No rate data in this window yet', '此時間範圍尚無速率資料'))}</strong>${esc(bi('Rates need at least two consecutive samples. Samples are kept for 24 hours in full, for 7 days at 10-minute resolution and for 30 days hourly.', '速率至少需要兩個連續採樣。採樣完整保留 24 小時、以 10 分鐘解析度保留 7 天、每小時解析度保留 30 天。'))}</div>`}</section>
    <div class="grid cols-3 mt">
      <section class="panel"><h3>${esc(bi('Receive', '接收'))}</h3><dl class="kv"><dt>p50</dt><dd>${esc(bitrate(s.rx_p50))}</dd><dt>p95</dt><dd>${esc(bitrate(s.rx_p95))}</dd><dt>${esc(bi('max', '最大'))}</dt><dd>${esc(bitrate(s.rx_max))}</dd></dl></section>
      <section class="panel"><h3>${esc(bi('Transmit', '傳送'))}</h3><dl class="kv"><dt>p50</dt><dd>${esc(bitrate(s.tx_p50))}</dd><dt>p95</dt><dd>${esc(bitrate(s.tx_p95))}</dd><dt>${esc(bi('max', '最大'))}</dt><dd>${esc(bitrate(s.tx_max))}</dd></dl></section>
      <section class="panel"><h3>${esc(bi('Data quality', '資料品質'))}</h3><dl class="kv"><dt>${esc(bi('Samples', '採樣'))}</dt><dd>${esc(d.sample_count)}</dd><dt>${esc(bi('Gaps', '中斷'))}</dt><dd>${esc(d.gaps)}</dd><dt>${esc(bi('Resets dropped', '捨棄的重設'))}</dt><dd>${esc(d.resets_dropped)}</dd><dt>${esc(bi('Interfaces', '介面'))}</dt><dd>${esc((d.interfaces || []).join(', ') || '—')}</dd></dl></section>
    </div>
    <details class="disclosure mt" id="traffic-table"><summary>${esc(bi('Show the data as a table', '以表格顯示資料'))}</summary><div class="body"><div class="table-wrap"><table><caption>${esc(bi('Latest 50 points, bit/s', '最近 50 個點，bit/s'))}</caption><thead><tr><th scope="col">${esc(bi('Time', '時間'))}</th><th scope="col">${esc(bi('Receive', '接收'))}</th><th scope="col">${esc(bi('Transmit', '傳送'))}</th></tr></thead>
      <tbody>${rows.map(p => `<tr><td>${esc(when(p.t))}</td><td>${esc(bitrate(p.rx_bps))}</td><td>${esc(bitrate(p.tx_bps))}</td></tr>`).join('')}</tbody></table></div></div></details>
    ${source(d.source)}`;
};

pages.logs = async function () {
  return `
    <p class="page-intro">${esc(bi('Doctor reads the server state layer by layer and suggests the next step. It never changes SSH, the firewall or the VPN core.', 'Doctor 會逐層讀取伺服器狀態並建議下一步，永不變更 SSH、防火牆或 VPN 核心。'))}</p>
    <div class="actions">${btn('run-doctor', bi('Run doctor', '執行 Doctor'), 'primary')}${btn('copy-report', bi('Copy redacted report', '複製已遮蔽報告'))}${btn('download-report', bi('Download report', '下載報告'), 'ghost')}</div>
    <div id="doctor-out" class="mt" aria-live="polite"></div>
    <div class="section-title"><h2>${esc(bi('VPN core log', 'VPN 核心日誌'))}</h2><span class="meta">${esc(bi('Latest 200 entries; credentials and URLs are removed before they reach the browser', '最近 200 筆；憑證與網址在傳至瀏覽器前已移除'))}</span></div>
    <form id="logs-form" class="toolbar" role="search" novalidate>${field('search', bi('Filter text', '篩選文字'), '', 'search', 'autocomplete="off"')}<button type="submit">${esc(bi('Load log', '載入日誌'))}</button></form>
    <div id="log-out"></div>
    <details class="disclosure mt" id="perf-inventory"><summary>${esc(bi('Advanced: performance inventory (raw)', '進階：效能盤點（原始）'))}</summary><div class="body">${btn('perf-inventory', bi('Load inventory', '載入盤點'))}<div id="perf-out" class="mt"></div></div></details>`;
};

function doctorHtml(d) {
  const st = s => s === 'error' ? status('error', bi('Failing', '失敗')) : s === 'warning' ? status('warning', bi('Warning', '警告')) : s === 'unknown' ? status('unknown', bi('Not checked here', '此處未檢查')) : status('ok', bi('OK', '正常'));
  const glyph = s => ({ok: status('ok', 'OK'), fail: status('error', bi('Fail', '失敗')), warn: status('warning', bi('Warn', '警告')), info: status('info', bi('Info', '資訊'))}[s] || status('info'));
  return `<p>${d.failures ? status('error', bi(`${d.failures} failing checks`, `${d.failures} 項失敗`)) : status('ok', bi('No failing checks', '沒有失敗的檢查'))} ${d.warnings ? status('warning', bi(`${d.warnings} warnings`, `${d.warnings} 項警告`)) : ''} <span class="meta">${esc(when(d.sampled_at))}</span></p>
    ${d.layers.map((l, i) => `<details class="layer" id="layer-${i}" ${l.status === 'error' || l.status === 'warning' ? 'open' : ''}><summary>${st(l.status)} <span class="name">${esc(l.layer)}</span><span class="count">${esc(bi(`${l.checks.length} checks`, `${l.checks.length} 項`))}</span></summary><div class="body">
      ${l.likely_cause ? `<div class="advice"><p><strong>${esc(bi('Likely cause', '可能原因'))}:</strong> ${esc(l.likely_cause)}</p><p><strong>${esc(bi('Next step', '下一步'))}:</strong> ${esc(l.next_action)}</p>${l.cli ? `<p class="small">${esc(bi('CLI equivalent', 'CLI 對應指令'))}: <code>${esc(l.cli)}</code></p>` : ''}</div>` : (l.next_action ? `<p class="muted small">${esc(l.next_action)}</p>` : '')}
      <ul class="plain checks">${l.checks.map(c => `<li>${glyph(c.status)} <span>${esc(c.label)}</span></li>`).join('')}</ul></div></details>`).join('')}
    ${d.required_ports ? `<details class="disclosure" id="doctor-ports"><summary>${esc(bi('Ports that must be open in the provider firewall', '供應商防火牆必須開放的連接埠'))}</summary><div class="body">${pre(d.required_ports)}</div></details>` : ''}`;
}
