/* Overview: one health strip, what needs attention, resources, details.
   Raw systemd/procfs JSON is kept under "Advanced data". */
const TILE_WORDS = {
  network: ['Network mode', '網路模式'], accounting: ['Usage tracking', '用量追蹤'], core: ['VPN core', 'VPN 核心'], panel: ['Admin panel', '管理面板'], certificate: ['Certificate', '憑證'],
  listeners: ['Listeners', '監聽'], external: ['Internet reachability', '網際網路可達性']
};
function tileValue(t) {
  if (t.key === 'network') return ({advanced: bi('Advanced policies', '進階政策'), ipv4: bi('IPv4 only', '僅 IPv4'), ipv6: bi('IPv6 only', '僅 IPv6'), dual: bi('IPv4 + IPv6', 'IPv4 + IPv6'), preserve: bi('Existing policy', '保留現有政策')})[t.value] || bi('Unknown', '未知');
  if (t.key === 'core') return t.status === 'ok' ? bi('Running', '運作中') : t.status === 'unknown' ? bi('No fresh sample', '沒有最新採樣') : (t.value + ' ' + bi('(not running)', '（未運作）'));
  if (t.key === 'accounting') return t.status === 'ok' ? bi('Collecting', '正在收集') : bi('Needs attention', '需要留意');
  if (t.key === 'panel') return bi('Serving', '服務中');
  if (t.key === 'certificate') {
    const d = t.detail.days_left;
    if (d === null || d === undefined) return t.detail.mode === 'none' || !t.detail.mode ? bi('Not used', '未使用') : bi('Unknown', '未知');
    return d < 0 ? bi('Expired', '已過期') : bi(Math.floor(d) + ' days left', '剩 ' + Math.floor(d) + ' 天');
  }
  if (t.key === 'listeners') { const m = /(\d+) of (\d+)/.exec(t.value); return m ? bi(`${m[1]} of ${m[2]} listening`, `${m[2]} 個中 ${m[1]} 個監聽中`) : t.value; }
  if (t.key === 'external') return bi('Not tested', '未測試');
  return t.value;
}
function tileDetail(t) {
  const d = t.detail || {};
  if (t.key === 'network' && d.policies) {
    const p = d.policies, words = {ipv4:'IPv4',ipv6:'IPv6',dual:'IPv4 + IPv6',prefer_ipv4:bi('Prefer IPv4','優先 IPv4'),prefer_ipv6:bi('Prefer IPv6','優先 IPv6')};
    return `${bi('Listener','監聽')}: ${words[p.inbound] || '?'} · ${bi('Outbound','連出')}: ${words[p.egress] || '?'} · DNS: ${p.dns === 'ipv4' ? 'A' : p.dns === 'ipv6' ? 'AAAA' : p.dns === 'dual' ? 'A + AAAA' : words[p.dns] || '?'} · ${bi('Device dialing','裝置連線')}: ${words[p.client] || '?'}`;
  }
  if (t.key === 'network') return d.mode === 'preserve' ? bi('Listener choice alone does not restrict outbound traffic or DNS. Existing behavior is preserved.', '監聽選項不會限制連出流量或 DNS，現有行為已保留。') : bi('Listener, DNS and outbound policy follow this mode. Change it with the guided CLI during a maintenance window.', '監聽、DNS 及連出政策依此模式運作。請於維護時段使用命令列精靈變更。');
  if (t.key === 'accounting') return t.status === 'ok' ? bi('Periodic quota checks are active.', '定期配額檢查運作中。') : bi('Usage or quota checks may be delayed. Open Users for details.', '用量或配額檢查可能延遲，請到使用者頁面查看。');
  if (t.key === 'core') return [d.version ? 'sing-box ' + d.version : bi('version unknown', '版本未知'), d.version_matches === false ? bi('expected ' + d.expected_version, '應為 ' + d.expected_version) : '', d.pid && d.pid !== '0' ? 'PID ' + d.pid : ''].filter(Boolean).join(', ');
  if (t.key === 'panel') return bi('Separate from the VPN. Up ', '與 VPN 分開。已運作 ') + duration(d.uptime_seconds);
  if (t.key === 'certificate') return d.expires_at ? bi('Expires ', '到期 ') + when(d.expires_at) + (d.renewal === 'unavailable' ? bi('; renewal timer not active', '；續期計時器未啟用') : d.renewal === 'scheduled' ? bi('; renewal scheduled', '；已排程續期') : '') : (d.domain || '');
  if (t.key === 'listeners') return d.missing && d.missing.length ? bi('Missing: ', '缺少：') + d.missing.join(', ') : bi('Local sockets only', '僅本機 socket');
  if (t.key === 'external') return bi('Test from a real client on mobile data and home broadband.', '請用真實客戶端於行動網路及家用寬頻測試。');
  return '';
}

function sparkline(points, label) {
  const values = points.filter(p => !p.gap);
  if (values.length < 2) return `<p class="muted small">${esc(bi('Not enough samples yet for a trend (needs two samples, 30 s apart).', '採樣不足，尚無法顯示趨勢（需要相隔 30 秒的兩個採樣）。'))}</p>`;
  const w = 300, h = 48, t0 = points[0].t, t1 = points[points.length - 1].t || t0 + 1;
  const max = Math.max(...values.map(p => p.rx_bps + p.tx_bps), 1);
  const segs = []; let cur = [];
  points.forEach(p => { if (p.gap) { if (cur.length) segs.push(cur); cur = []; } else cur.push(((p.t - t0) / Math.max(1, t1 - t0) * w).toFixed(1) + ',' + (h - 3 - (p.rx_bps + p.tx_bps) / max * (h - 6)).toFixed(1)); });
  if (cur.length) segs.push(cur);
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="${esc(label)}">${segs.map(s => `<polyline class="rx" points="${s.join(' ')}"/>`).join('')}</svg>`;
}

pages.overview = async function () {
  const d = await api('dashboard');
  state.alertsOpen = d.alert_count; state.alertsWorst = d.alerts.some(a => a.severity === 'critical') ? 'critical' : d.alert_count ? 'warning' : null; renderNav();
  const sampledAge = d.sampled_at ? Date.now() / 1000 - d.sampled_at : null;
  const summary = {ok: bi('Everything checked locally is healthy', '本機檢查項目全部正常'), warning: bi('Something needs attention', '有項目需要留意'), error: bi('There is a problem', '發現問題')}[d.status] || '';
  const r = d.resources, tr = d.traffic || {};
  const people=d.people,counts=people?.counts||{};
  const memKind = r.memory.total_bytes && r.memory.available_bytes / r.memory.total_bytes < 0.1 ? 'error' : '';
  const diskKind = r.disk.total_bytes && r.disk.available_bytes / r.disk.total_bytes < 0.1 ? 'error' : '';
  const latest = tr.latest;
  const compact = window.matchMedia("(max-width: 560px)").matches;
  const attention = d.alerts.length ? `<ul class="plain attention">${d.alerts.map(a => `<li>${status(a.severity === 'critical' ? 'error' : a.severity === 'info' ? 'info' : 'warning', a.severity === 'critical' ? bi('Critical', '嚴重') : a.severity === 'info' ? bi('Info', '資訊') : bi('Warning', '警告'))}
      <div class="what"><strong>${esc(a.title)}</strong><p>${esc(a.detail)}</p><p class="source">${esc(a.source)}</p></div><span class="when">${esc(ago(a.first_seen))}</span></li>`).join('')}</ul>
      ${d.alert_count > d.alerts.length ? `<p><a href="#alerts">${esc(bi(`All ${d.alert_count} open alerts`, `全部 ${d.alert_count} 個未解決警示`))}</a></p>` : ''}`
    : `<p>${status('ok', bi('Nothing needs attention', '沒有需要處理的項目'))}</p><p class="muted small">${esc(bi('Alert rules run every 30 seconds on this server.', '警示規則每 30 秒在本伺服器執行。'))} <a href="#alerts">${esc(bi('Alerts & timeline', '警示與時間軸'))}</a></p>`;
  const cert = d.tiles.find(t => t.key === 'certificate') || {detail: {}};
  return `
  ${d.fixture ? `<div class="notice warning"><strong>FIXTURE</strong><span>${esc(bi('This panel is connected to a test fixture, not a real VPN server.', '此面板連接測試夾具，而非真實 VPN 伺服器。'))}</span></div>` : ''}
  <div class="overview-head">
    ${status(d.status === 'ok' ? 'ok' : d.status === 'error' ? 'error' : 'warning', summary)}
    <span class="meta" id="sampled">${esc(bi('Updated', '更新於'))} ${esc(when(d.sampled_at, {short: true}))} (${esc(ago(d.sampled_at))})${sampledAge > 120 ? ' · ' + status('stale', bi('stale', '過時')) : ''}</span>
  </div>
  ${people?.available?`<div class="people-summary" aria-label="${esc(bi('Managed users','受管理使用者'))}">${[[people.total,bi('Total users','使用者總數')],[counts.active,bi('Access active','可用狀態')],[counts.manually_disabled,bi('Paused','已暫停')],[counts.expired,bi('Expired','已到期')],[counts.quota_exceeded,bi('Data used up','數據已用完')]].map(([count,label])=>`<a href="#users"><span>${esc(label)}</span><strong>${esc(number(count))}</strong></a>`).join('')}</div>`:''}
  <section class="health-strip" aria-label="${esc(bi('Service health', '服務健康'))}">
    ${d.tiles.map(t => `<div class="health-cell ${esc(t.status)}" data-health="${esc(t.key)}"><div class="label">${esc(bi(...(TILE_WORDS[t.key] || [t.label, t.label])))}</div>
      <div class="value">${esc(tileValue(t))} <span class="sr">${esc(bi(...(STATUS_WORDS[t.status] || [t.status, t.status])))}</span></div><div class="detail">${esc(tileDetail(t))}</div></div>`).join('')}
  </section>
  <div class="actions overview-actions" aria-label="${esc(bi('Quick actions', '快速操作'))}">${isAdmin()?btn('user-create',bi('Create user','新增使用者'),'primary'):''}<a class="btn" href="#users">${esc(bi('Manage users', '管理使用者'))}</a>${btn('run-doctor-overview', bi('Run doctor', '執行 Doctor'))}<a class="btn ghost" href="#certificates">${esc(bi('Certificates', '憑證'))}</a></div>
  ${d.pending_transaction ? `<div class="notice error" role="alert"><strong>${esc(bi('An interrupted change is waiting for recovery', '有中斷的變更等待復原'))}</strong><span>${esc(bi('New changes are blocked until it is recovered.', '復原前會封鎖新變更。'))}</span><div class="actions"><a class="btn" href="#updates">${esc(bi('Open recovery', '開啟復原'))}</a></div></div>` : ''}
  <div class="section-title"><h2>${esc(bi('Needs attention', '需要留意'))}</h2></div>
  <div class="grid cols-2"><section class="panel">${attention}</section><section class="panel"><h2>${esc(bi('Upcoming in 7 days','未來 7 日'))}</h2>${people?.available?(people.upcoming.length?`<ul class="plain upcoming-events">${people.upcoming.map(e=>`<li><div><strong>${esc(e.name)}</strong><span class="small">${esc(e.kind==='reset'?bi('Usage resets','用量重設'):bi('Access expires','存取到期'))} · ${esc(when(e.time))}</span></div>${btn('user-detail',bi('View','查看'),'',`data-id="${esc(e.id)}"`)}</li>`).join('')}</ul>`:`<p class="muted">${esc(bi('No usage resets or service end dates in this period.','此期間沒有用量重設或服務到期。'))}</p>`):`<p class="muted">${esc(bi('Usage figures are not available right now. Open Users to check usage tracking.','暫時未有用量數字，請到「使用者」查看用量追蹤狀態。'))}</p>`}<p class="source">${esc(bi('Scheduled account events. They do not indicate who is online.','帳戶排程事件，不代表使用者是否在線。'))}</p><a class="target-link" href="#updates">${esc(bi('Backup, upgrade and recovery','備份、升級同復原'))}</a></section></div>
  <details class="disclosure mt" id="overview-resources" ${compact ? '' : 'open'}><summary>${esc(bi('Server resources & recent changes', '伺服器資源與最近變更'))}</summary><div class="body">
  <div class="section-title"><h2>${esc(bi('Server resources', '伺服器資源'))}</h2><span class="meta">${esc(bi('Host-wide, measured on this server', '整台主機，於本伺服器量測'))}</span></div>
  <div class="grid cols-4">
    <section class="panel resource"><h3>${esc(bi('CPU', 'CPU'))}</h3><div class="big">${r.cpu.percent === null || r.cpu.percent === undefined ? '—' : number(r.cpu.percent, 1) + '<small>%</small>'}</div>
      <p class="muted small">${r.cpu.load_average ? esc(bi('Load', '負載')) + ' ' + r.cpu.load_average.map(x => number(x, 2)).join(' / ') : ''}${r.cpu.cpus ? ' · ' + esc(bi(r.cpu.cpus + ' CPUs', r.cpu.cpus + ' 顆 CPU')) : ''}</p>
      ${r.cpu.percent === null || r.cpu.percent === undefined ? `<p class="muted small">${esc(bi('Needs a second sample (30 s).', '需要第二次採樣（30 秒）。'))}</p>` : ''}</section>
    <section class="panel resource"><h3>${esc(bi('Memory', '記憶體'))}</h3><div class="big">${esc(bytes(r.memory.used_bytes))}</div>${meter(r.memory.used_bytes, r.memory.total_bytes, memKind)}
      <p class="muted small">${esc(bi('of', '共'))} ${esc(bytes(r.memory.total_bytes))} · ${esc(bi('VPN core', 'VPN 核心'))} ${esc(bytes(r.memory.core_rss_bytes))}</p></section>
    <section class="panel resource"><h3>${esc(bi('Disk', '磁碟'))}</h3><div class="big">${esc(bytes(r.disk.used_bytes))}</div>${meter(r.disk.used_bytes, r.disk.total_bytes, diskKind)}
      <p class="muted small">${esc(bytes(r.disk.available_bytes))} ${esc(bi('free of', '可用，共'))} ${esc(bytes(r.disk.total_bytes))}</p></section>
    <section class="panel resource"><h3>${esc(bi('Host traffic now', '目前主機流量'))}</h3>
      <div class="big">${latest ? esc(bitrate(latest.rx_bps + latest.tx_bps)) : '—'}</div>
      <p class="muted small">${latest ? esc(bi('in', '入')) + ' ' + esc(bitrate(latest.rx_bps)) + ' · ' + esc(bi('out', '出')) + ' ' + esc(bitrate(latest.tx_bps)) : esc(bi('No rate yet: needs two samples.', '尚無速率：需要兩次採樣。'))}</p>
      ${sparkline(tr.points || [], bi('Host traffic over the last hour', '最近一小時主機流量'))}
      <p class="muted small"><a href="#traffic">${esc(bi('Traffic history', '流量歷史'))}</a></p></section>
  </div>
  <div class="grid cols-3 mt">
    <section class="panel"><h3>${esc(bi('Certificate', '憑證'))}</h3>
      <dl class="kv"><dt>${esc(bi('Domain', '網域'))}</dt><dd>${esc(cert.detail.domain || '—')}</dd><dt>${esc(bi('Issuer', '簽發者'))}</dt><dd>${esc(cert.detail.issuer || '—')}</dd>
      <dt>${esc(bi('Expires', '到期'))}</dt><dd>${esc(when(cert.detail.expires_at))}</dd><dt>${esc(bi('Renewal', '續期'))}</dt><dd>${esc({scheduled: bi('Automatic (timer active)', '自動（計時器啟用）'), unavailable: bi('Timer not active', '計時器未啟用'), 'not-required': bi('Not managed by ACME', '非 ACME 管理')}[cert.detail.renewal] || '—')}</dd></dl>
      ${source(cert.source)}</section>
    <section class="panel"><h3>${esc(bi('Last change', '最近變更'))}</h3>
      ${d.last_change ? `<p><strong>${esc(d.last_change.target || d.last_change.event)}</strong> ${esc(bi('by', '由'))} ${esc(d.last_change.actor)}</p><p class="muted small">${esc(when(d.last_change.time))} (${esc(d.last_change.origin || '—')})</p>` : `<p class="muted">${esc(bi('No changes recorded by the panel yet. CLI changes appear in the timeline as "changed outside the panel".', '面板尚未記錄變更。CLI 變更會以「在面板外變更」顯示於時間軸。'))}</p>`}
      <p class="small"><a href="#audit">${esc(bi('Audit log', '稽核紀錄'))}</a></p></section>
    <section class="panel"><h3>${esc(bi('Last validation', '最近驗證'))}</h3>
      ${d.last_validation ? `<p>${d.last_validation.failures ? status('error', bi(d.last_validation.failures + ' failing checks', d.last_validation.failures + ' 項檢查失敗')) : status('ok', bi('All checks passed', '所有檢查通過'))}</p><p class="muted small">${esc(when(d.last_validation.sampled_at))}</p>` : `<p class="muted">${esc(bi('Doctor has not run since the panel started.', '面板啟動後尚未執行 Doctor。'))}</p>`}
      <p class="muted small">${esc(bi('VPN core errors in the last hour', '最近一小時 VPN 核心錯誤'))}: ${esc(number(d.recent_errors ? d.recent_errors.count : null))}</p>
      </section>
  </div>
  </div></details>
  <div class="notice mt"><span>${esc(bi('Server traffic includes every service on this server, not just VPN users. Checks on this server cannot prove that devices on other networks can connect.','伺服器流量包括此伺服器上所有服務，不只是 VPN 使用者。此檢查在伺服器本機進行，未能證明其他網路的裝置可以連線。'))}</span></div>
  <div class="actions">${btn('copy-report', bi('Copy redacted health report', '複製已遮蔽健康報告'))}${btn('download-report', bi('Download report', '下載報告'), 'ghost')}</div>
  <details class="disclosure mt" id="overview-advanced"><summary>${esc(bi('Advanced data (raw JSON from the bridge)', '進階資料（橋接器原始 JSON）'))}</summary><div class="body">${pre(d.advanced)}</div></details>`;
};
