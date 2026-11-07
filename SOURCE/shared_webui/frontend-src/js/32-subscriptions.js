pages.subscriptions = async function () {
  const d = await api('subscriptions');
  const rows = d.users.map(u => `<tr>
      <td class="name-cell"><strong>${esc(u.name)}</strong>${u.protected ? `<span class="muted small">${esc(bi('original identity', '原始身分'))}</span>` : ''}</td>
      <td>${!u.enabled ? status('off', bi('User disabled', '使用者已停用')) : u.subscription_active ? status('ok', bi('Link active', '連結有效')) : status('info', bi('No link', '沒有連結'))}</td>
      <td class="muted small">${u.subscription_active ? esc(when(u.subscription_created)) : '—'}</td>
      <td class="actions-cell">${isAdmin() ? btn('user-share', u.subscription_active ? bi('Manage link', '管理連結') : bi('Create link', '建立連結'), '', `data-id="${esc(u.id)}" ${u.enabled ? '' : 'disabled'}`) : '—'}</td></tr>`).join('');
  return `
    <p class="page-intro">${esc(bi('A subscription link lets a client app download its profile and refresh it automatically. Links are personal: each one maps to exactly one user, can be viewed again when created with this release, and stops working the moment you replace or revoke it.', '訂閱連結讓客戶端下載設定檔並自動更新。連結屬個人：每條只對應一位使用者，此版本建立的連結可再次取得，更換或撤銷後立即失效。'))}</p>
    <div class="grid cols-2">
      <section class="panel"><h2>${esc(bi('Static file or subscription?', '靜態檔案還是訂閱？'))}</h2>
        <dl class="kv"><dt>${esc(bi('Subscription link', '訂閱連結'))}</dt><dd>${esc(bi('The app re-downloads the profile (this server suggests every 24 h). Policy and credential changes arrive automatically.', '應用程式會重新下載設定檔（本伺服器建議每 24 小時），策略與憑證變更會自動送達。'))}</dd>
        <dt>${esc(bi('Downloaded file', '下載的檔案'))}</dt><dd>${esc(bi('A fixed copy. It never changes by itself; import it again after you change policies.', '固定副本，不會自行變更；變更策略後須重新匯入。'))}</dd>
        ${state.caps.variant === 'zgocloud' ? `<dt>${esc(bi('Original ZgoCloud.yaml', '原始 ZgoCloud.yaml'))}</dt><dd>${esc(bi('Already-distributed static file. The panel never edits it; it keeps working unchanged.', '已分發的靜態檔案。面板永不修改它，維持原樣可用。'))}</dd>` : ''}</dl></section>
      <section class="panel"><h2>${esc(bi('Personal setup page', '個人設定頁'))}</h2>
        <p>${d.landing_page ? status('ok', bi('On', '開啟')) : status('off', bi('Off', '關閉'))}</p>
        <p class="muted small">${esc(bi('When on, each new link also gets a simple page for the user: profile choice, QR codes, import steps and update notes. It shows nothing about the server, other users or the admin panel. Off by default.', '開啟後，每條新連結都附有簡單的使用者頁面：設定檔選擇、QR 碼、匯入步驟及更新說明。不顯示伺服器、其他使用者或管理面板的任何資料。預設關閉。'))}</p>
        ${isAdmin() ? `<div class="actions" data-admin>${btn('toggle-landing', d.landing_page ? bi('Turn off', '關閉') : bi('Turn on', '開啟'), '', `data-value="${d.landing_page ? '0' : '1'}"`)}</div>` : ''}</section>
    </div>
    <div class="section-title"><h2>${esc(bi('Links by user', '各使用者連結'))}</h2></div>
    <div class="table-wrap subscriptions-table"><table><caption class="sr">${esc(bi('Subscription link status per user', '各使用者訂閱連結狀態'))}</caption>
      <thead><tr><th scope="col">${esc(bi('User', '使用者'))}</th><th scope="col">${esc(bi('Link', '連結'))}</th><th scope="col">${esc(bi('Created', '建立時間'))}</th><th scope="col" class="actions-cell">${esc(bi('Actions', '操作'))}</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
};

pages.inbounds = async function () {
  const d = await api('inbounds');
  state.inbounds = d;
  const editable = state.caps.variant === 'universal' && isAdmin();
  return `
    <p class="page-intro">${esc(bi('Listeners read from the live sing-box configuration. UDP hopping ranges are NAT aliases that forward to the listed UDP port; they are not separate listeners.', '從實際 sing-box 設定讀取的監聽。UDP 跳埠範圍是轉發至對應 UDP 連接埠的 NAT 別名，不是獨立監聽。'))}</p>
    ${state.caps.variant === 'zgocloud' ? `<div class="notice"><strong>${status('locked', bi('Protected', '受保護'))}</strong><span>${esc(bi('ZgoCloud ports, keys and hopping ranges match the distributed client file and cannot be changed from the panel.', 'ZgoCloud 連接埠、金鑰及跳埠範圍與已分發的客戶端檔案一致，無法在面板變更。'))}</span></div>` : ''}
    <div class="table-wrap"><table><caption class="sr">${esc(bi('Inbound listeners', '入站監聽'))}</caption>
      <thead><tr><th scope="col">${esc(bi('Protocol', '協定'))}</th><th scope="col">${esc(bi('Port', '連接埠'))}</th><th scope="col">${esc(bi('Security / transport', '安全／傳輸'))}</th><th scope="col">${esc(bi('Local socket', '本機 socket'))}</th><th scope="col">${esc(bi('Users', '使用者'))}</th></tr></thead>
      <tbody>${d.inbounds.map(i => `<tr><td><strong>${esc(PROTOCOL_NAMES[{vless: 'reality', vmess: 'vmess', hysteria2: 'hy2', tuic: 'tuic', anytls: 'anytls'}[i.type]] || i.type)}</strong><br><code>${esc(i.id)}</code></td>
        <td class="nowrap"><code>${esc(i.port)}/${esc(i.network)}</code></td><td>${esc(i.type === 'vless' ? 'REALITY' : i.tls ? 'TLS' : bi('none', '無'))} · ${esc(i.transport)}</td>
        <td>${i.listening ? status('ok', bi('Listening', '監聽中')) : status('error', bi('Not listening', '未監聽'))}</td><td>${esc(i.user_count)}</td></tr>`).join('')}</tbody></table></div>
    <div class="section-title"><h2>${esc(bi('UDP hopping aliases', 'UDP 跳埠別名'))}</h2></div>
    <section class="panel">${d.aliases.length ? `<ul class="plain">${d.aliases.map(a => `<li class="check"><code>${esc(a.range)}/udp</code> → <code>${esc(a.target_port)}/udp</code> ${chip(a.protocol)}</li>`).join('')}</ul>` : `<p class="muted">${esc(bi('No hopping ranges configured.', '尚未設定跳埠範圍。'))}</p>`}${source(d.source)}</section>
    ${editable ? `<div class="actions" data-admin>${btn('edit-inbounds', bi('Change ports or enable/disable protocols…', '變更連接埠或啟用／停用協定…'))}</div>` : ''}`;
};

function inboundForm() {
  const p = state.inbounds.protocols;
  return `<form id="inbounds-form" novalidate>
    <p class="muted small">${esc(bi('Existing client files contain the old ports. Changing a port requires every user to re-import or refresh their subscription.', '現有客戶端檔案使用舊連接埠。變更連接埠後，每位使用者都須重新匯入或更新訂閱。'))}</p>
    ${Object.entries(p).map(([name, v]) => `<fieldset class="panel flat"><legend>${esc(PROTOCOL_NAMES[name] || name)}</legend><div class="form-row">
      ${field(name + '-port', bi('Port', '連接埠'), v.port, 'number', 'min="1" max="65535" required')}${checkbox(name + '-enabled', bi('Enabled', '啟用'), v.enabled)}</div>${name === 'vmess' && 'multiplex' in v ? `<div class="form-row">${checkbox('vmess-multiplex', bi('Connection reuse (sing-mux + WebSocket early data)', '連線重用（sing-mux + WebSocket 早期資料）'), v.multiplex)}</div><p class="muted small">${esc(bi('Reuses one VMess connection for new requests in YAML/JSON profiles; links and QR codes are unchanged. Older client files keep working; users get the faster mode after refreshing their subscription.', '在 YAML/JSON 設定檔中重用同一 VMess 連線；連結及 QR 碼不變。舊客戶端檔案仍可使用；使用者更新訂閱後即採用較快模式。'))}</p>` : ''}</fieldset>`).join('')}
    <div class="actions end"><button type="button" data-close>${esc(bi('Cancel', '取消'))}</button><button type="submit" class="primary">${esc(bi('Review change', '檢視變更'))}</button></div></form>`;
}
