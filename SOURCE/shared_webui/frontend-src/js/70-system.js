/* Versions & recovery, accounts & notifications, audit, advanced/API. */
pages.updates = async function () {
  const v = await api('system/version');
  const m = v.manager || {};
  const integ = v.panel_integrity || {};
  return `
    <p class="page-intro">${esc(bi('The VPN keeps running while the panel is stopped, upgraded or removed. The CLI (sudo sbox) always remains available.', '面板停止、升級或移除時 VPN 持續運作。CLI（sudo sbox）一直可用。'))}</p>
    <div class="grid cols-2">
      <section class="panel"><h2>${esc(bi('Versions', '版本'))}</h2><dl class="kv">
        <dt>${esc(bi('Panel', '面板'))}</dt><dd>${esc(v.panel_version)} · API ${esc(v.api_schema)}</dd>
        <dt>${esc(bi('Panel files', '面板檔案'))}</dt><dd>${status(integ.status === 'ok' ? 'ok' : integ.status === 'error' ? 'error' : 'unknown', integ.status === 'ok' ? bi('Match build manifest', '與建置清單一致') : integ.status === 'error' ? bi('Modified', '已被修改') : bi('Unknown', '未知'))}<br><span class="muted small">${esc(integ.detail || '')}${integ.manifest_sha256 ? ' · ' + esc(integ.manifest_sha256) : ''}</span></dd>
        <dt>${esc(bi('Manager', '管理器'))}</dt><dd>${esc(m.manager_version || m.error || '—')}<br><span class="muted small">${esc(m.manager_build_id || '')}</span></dd>
        <dt>${esc(bi('VPN core running', '運作中的 VPN 核心'))}</dt><dd>sing-box ${esc(m.core_version || '—')}</dd>
        <dt>${esc(bi('VPN core expected', '預期的 VPN 核心'))}</dt><dd>sing-box ${esc(m.expected_core_version || state.caps.core_version)}${m.core_version && m.expected_core_version && m.core_version !== m.expected_core_version ? ' ' + status('warning', bi('Differs', '不一致')) : ''}</dd>
        <dt>${esc(bi('Edition', '版本類型'))}</dt><dd>${esc(v.variant === 'zgocloud' ? 'ZgoCloud' : bi('Universal', '通用版'))}</dd></dl></section>
      <section class="panel"><h2>${esc(bi('Update the VPN core', '更新 VPN 核心'))}</h2>
        <p class="muted small">${esc(state.caps.variant === 'zgocloud' ? bi('ZgoCloud stays on its tested core by default. Only update after the original client file has been tested against the new version.', 'ZgoCloud 預設維持已測試的核心。請在原始客戶端檔案以新版本測試後才更新。') : bi('Choose latest stable, a preview channel or an exact version. The accounting patch is verified and tested before a recoverable update. Source builds need additional time, disk and memory.', '可選最新穩定版、預覽頻道或指定版本。更新前會驗證並測試計量修補，失敗可回復。原始碼建置需要額外時間、磁碟與記憶體。'))}</p>
        ${isAdmin() ? `<form id="core-form" data-admin novalidate>${field('version', bi('Version or channel', '版本或頻道'), 'latest', 'text', 'pattern="(?:latest|stable|beta|prerelease|[0-9]+\\.[0-9]+\\.[0-9]+)" required placeholder="latest" autocomplete="off"')}<button type="submit">${esc(bi('Review core…', '檢視核心…'))}</button></form>` : ''}</section>
    </div>
    <div class="section-title"><h2>${esc(bi('Backups and recovery', '備份與復原'))}</h2></div>
    <section class="panel"><p class="muted small">${esc(bi('Backups stay on this server, readable by root only. An interrupted change can be finished or rolled back from its journal.', '備份留在本伺服器，僅 root 可讀。中斷的變更可依日誌完成或回復。'))}</p>
      ${isAdmin() ? `<div class="actions" data-admin>${btn('backup', bi('Create backup', '建立備份'))}${btn('backups-list', bi('Restore a backup…', '還原備份…'))}${btn('recover', bi('Recover interrupted change…', '復原中斷的變更…'))}${btn('restart', bi('Restart VPN core…', '重新啟動 VPN 核心…'), 'danger')}</div>` : ''}
      <div id="update-out" class="mt"></div></section>
    <details class="disclosure mt" id="panel-lifecycle"><summary>${esc(bi('Panel maintenance commands (root shell)', '面板維護指令（root shell）'))}</summary><div class="body">
      <p class="muted small">${esc(bi('None of these restart the VPN or SSH. Upgrade the panel by running the newer standalone installer; it keeps settings, accounts and two-factor enrollment.', '這些指令都不會重新啟動 VPN 或 SSH。執行較新的獨立安裝器即可升級面板，並保留設定、帳戶與雙因素驗證。'))}</p>
      ${pre('sudo sbox webui status\nsudo sbox webui doctor\nsudo sbox webui stop | start\nsudo sbox webui upgrade\nsudo sbox webui rollback\nsudo sbox webui reset-admin\nsudo sbox webui uninstall')}</div></details>`;
};

pages.settings = async function () {
  if (!isAdmin()) return `<p class="page-intro">${esc(bi('Operator accounts and notifications are managed by administrators.', '操作員帳戶與通知由管理員管理。'))}</p>`;
  const [n, a] = await Promise.all([api('notifications'), api('accounts')]);
  return `
    <div class="grid cols-2">
      <section class="panel"><h2>${esc(bi('Operator accounts', '操作員帳戶'))}</h2>
        <div class="table-wrap"><table><thead><tr><th scope="col">${esc(bi('Name', '名稱'))}</th><th scope="col">${esc(bi('Role', '角色'))}</th><th scope="col">${esc(bi('Status', '狀態'))}</th><th scope="col" class="actions-cell">${esc(bi('Action', '操作'))}</th></tr></thead>
          <tbody>${a.accounts.map(x => `<tr><td>${esc(x.name)}${x.mfa ? ' ' + chip('2FA') : ''}</td><td>${esc(x.role === 'admin' ? bi('Administrator', '管理員') : bi('Read-only', '唯讀'))}</td><td>${x.enabled ? status('ok', bi('Enabled', '已啟用')) : status('off', bi('Disabled', '已停用'))}</td>
            <td class="actions-cell">${x.name === state.me.name ? `<span class="muted small">${esc(bi('you', '你'))}</span>` : btn('account-toggle', x.enabled ? bi('Disable', '停用') : bi('Enable', '啟用'), '', `data-name="${esc(x.name)}" data-enabled="${x.enabled ? '0' : '1'}"`)}</td></tr>`).join('')}</tbody></table></div>
        <h3 class="mt">${esc(bi('Add an account', '新增帳戶'))}</h3>
        <form id="account-form" novalidate>${field('name', bi('Name', '名稱'), '', 'text', 'required pattern="[A-Za-z0-9._\\-]{1,64}" autocomplete="off"')}${field('password', bi('Initial password (12+ characters; they must change it)', '初始密碼（至少 12 字元；需由對方更改）'), '', 'password', 'required minlength="12" autocomplete="new-password"')}
          ${select('role', bi('Role', '角色'), [['reader', bi('Read-only: can view everything except secrets', '唯讀：可檢視秘密以外的所有內容')], ['admin', bi('Administrator: can change everything', '管理員：可變更所有內容')]], 'reader')}<button type="submit" class="primary">${esc(bi('Add account', '新增帳戶'))}</button></form></section>
      <section class="panel"><h2>${esc(bi('Notifications', '通知'))}</h2>
        <p>${n.enabled ? status('ok', bi('On', '開啟')) : status('off', bi('Off', '關閉'))} ${n.configured ? chip(n.kind) : ''}</p>
        <p class="muted small">${esc(bi('Alerts are sent when they open, escalate or recover. Only public HTTPS destinations on port 443 are allowed; private, metadata and redirected destinations are refused. The stored address is never shown again; enter it again to change it.', '警示在開啟、升級或恢復時發送。只允許 443 埠的公開 HTTPS 目的地；私有、中繼資料及重新導向的目的地會被拒絕。已儲存的位址不會再顯示，變更時請重新輸入。'))}</p>
        <form id="notifications-form" novalidate>${select('kind', bi('Service', '服務'), [['webhook', 'Webhook'], ['discord', 'Discord'], ['telegram', 'Telegram']], n.kind || 'webhook')}
          ${field('url', bi('Destination URL', '目的地網址'), '', 'url', 'autocomplete="off" placeholder="https://"')}${field('chat_id', bi('Telegram chat ID (Telegram only)', 'Telegram 聊天 ID（僅 Telegram）'), '', 'text', 'autocomplete="off"')}
          ${checkbox('enabled', bi('Send notifications', '發送通知'), n.enabled)}<div class="actions"><button type="submit" class="primary">${esc(bi('Save', '儲存'))}</button>${n.configured ? btn('notify-test', bi('Send a test', '傳送測試')) : ''}</div></form></section>
    </div>`;
};

pages.audit = async function () {
  if (!isAdmin()) return `<p class="page-intro">${esc(bi('The audit log is available to administrators.', '稽核紀錄僅供管理員檢視。'))}</p>`;
  const f = state.auditFilter;
  const q = new URLSearchParams({limit: '50', offset: String(state.auditOffset)});
  ['actor', 'outcome', 'event', 'text'].forEach(k => { if (f[k]) q.set(k, f[k]); });
  if (f.since) q.set('since', String(Date.parse(f.since) / 1000));
  const d = await api('audit?' + q.toString());
  const outcome = o => o === 'ok' || !o ? status('ok', bi('OK', '成功')) : o === 'denied' ? status('warning', bi('Denied', '拒絕')) : status('error', o === 'failed' ? bi('Failed', '失敗') : o);
  return `
    <p class="page-intro">${esc(bi('Every sign-in, change, action and security setting is recorded with who, where from and the result. Secrets and subscription tokens are never stored here. The latest 10,000 events are kept.', '每次登入、變更、操作及安全設定都會記錄執行者、來源與結果。此處永不儲存秘密或訂閱權杖。保留最近 10,000 筆。'))}</p>
    <form id="audit-form" class="toolbar" role="search" novalidate>
      ${select('actor', bi('Who', '執行者'), [['', bi('Anyone', '任何人')], ...d.actors.map(x => [x, x])], f.actor || '')}
      ${select('outcome', bi('Result', '結果'), [['', bi('Any', '全部')], ['ok', bi('OK', '成功')], ['denied', bi('Denied', '拒絕')], ['failed', bi('Failed', '失敗')]], f.outcome || '')}
      ${select('event', bi('Event', '事件'), [['', bi('Any', '全部')], ['login', bi('Sign-in', '登入')], ['change-', bi('Changes', '變更')], ['action', bi('Actions', '操作')], ['subscription', bi('Subscriptions', '訂閱')], ['account', bi('Accounts', '帳戶')], ['api-token', bi('API tokens', 'API 權杖')], ['sessions', bi('Sessions', '工作階段')]], f.event || '')}
      ${field('text', bi('Contains', '包含'), f.text || '', 'search', 'autocomplete="off"')}
      ${field('since', bi('Since', '起始'), f.since || '', 'date')}
      <button type="submit">${esc(bi('Apply filters', '套用篩選'))}</button>
    </form>
    <div class="table-wrap"><table><caption>${esc(bi(`${d.total} matching events`, `${d.total} 筆符合事件`))}</caption>
      <thead><tr><th scope="col">${esc(bi('Time', '時間'))}</th><th scope="col">${esc(bi('Who', '執行者'))}</th><th scope="col">${esc(bi('Event', '事件'))}</th><th scope="col">${esc(bi('Target', '對象'))}</th><th scope="col">${esc(bi('Result', '結果'))}</th><th scope="col">${esc(bi('Via', '來源'))}</th><th scope="col">${esc(bi('Detail', '詳情'))}</th></tr></thead>
      <tbody>${d.events.map(e => `<tr><td class="nowrap">${esc(when(e.time))}</td><td>${esc(e.actor)}</td><td><code>${esc(e.event)}</code></td><td>${esc(e.target || '—')}</td><td>${outcome(e.outcome)}</td><td>${esc(e.origin || '—')}</td><td class="small">${esc(e.detail || '')}</td></tr>`).join('') || `<tr><td colspan="7" class="empty">${esc(bi('No events match.', '沒有符合的事件。'))}</td></tr>`}</tbody></table></div>
    <nav class="pager" aria-label="${esc(bi('Audit pages', '稽核分頁'))}"><span class="meta">${esc(bi(`${state.auditOffset + 1}–${Math.min(state.auditOffset + 50, d.total)} of ${d.total}`, `第 ${state.auditOffset + 1}–${Math.min(state.auditOffset + 50, d.total)} 筆，共 ${d.total} 筆`))}</span>
      <div class="actions">${btn('audit-prev', bi('Newer', '較新'), '', state.auditOffset ? '' : 'disabled')}${btn('audit-next', bi('Older', '較舊'), '', state.auditOffset + 50 < d.total ? '' : 'disabled')}</div></nav>`;
};

pages.api = async function () {
  const tokens = isAdmin() ? await api('api-tokens') : {tokens: []};
  const caps = state.caps;
  const missing = [['per_user_traffic', bi('Per-user traffic counters', '個別使用者流量')], ['quotas', bi('Data allowances','數據用量')], ['online_sessions', bi('Online sessions per user', '個別線上工作階段')], ['expiry', bi('Timed user expiry', '使用者定時到期')], ['multi_vps', bi('Multi-server management', '多伺服器管理')]];
  return `
    <p class="page-intro">${esc(bi('Tools for automation and troubleshooting. Raw data shown here is the same data the friendly pages use.', '自動化與疑難排解工具。此處的原始資料與其他頁面使用的資料相同。'))}</p>
    <section class="panel"><h2>${esc(bi('Not available with this core adapter', '此核心介接器不支援'))}</h2>
      <ul class="plain">${missing.map(([k, label]) => `<li class="check">${caps[k] ? status('ok', bi('Available', '可用')) : status('off', bi('Unavailable', '不可用'))} ${esc(label)}</li>`).join('')}</ul>
      <p class="muted small">${esc(caps.reason)}</p></section>
    ${isAdmin() ? `<div class="section-title" data-admin><h2>${esc(bi('API tokens', 'API 權杖'))}</h2></div>
    <section class="panel" data-admin>
      <p class="muted small">${esc(bi('Use as "Authorization: Bearer TOKEN". Read tokens cannot change anything. Write tokens can prepare and commit changes but cannot manage accounts, tokens or security settings. A token is shown once.', '以「Authorization: Bearer TOKEN」使用。唯讀權杖無法變更任何內容。寫入權杖可預覽及提交變更，但無法管理帳戶、權杖或安全設定。權杖只顯示一次。'))}</p>
      <form id="token-form" class="toolbar" novalidate>${field('name', bi('Name', '名稱'), '', 'text', 'required pattern="[A-Za-z0-9._\\-]{1,64}" autocomplete="off"')}${select('scope', bi('Scope', '範圍'), [['read', bi('Read only', '唯讀')], ['write', bi('Write', '寫入')]], 'read')}${field('hours', bi('Lifetime (hours, 1–720)', '有效期（小時，1–720）'), 24, 'number', 'min="1" max="720" required')}<button type="submit" class="primary">${esc(bi('Create token', '建立權杖'))}</button></form>
      <div id="token-out"></div>
      <div class="table-wrap mt"><table><thead><tr><th scope="col">${esc(bi('Name', '名稱'))}</th><th scope="col">${esc(bi('Scope', '範圍'))}</th><th scope="col">${esc(bi('Expires', '到期'))}</th><th scope="col">${esc(bi('Last used', '最後使用'))}</th><th scope="col" class="actions-cell">${esc(bi('Action', '操作'))}</th></tr></thead>
        <tbody>${tokens.tokens.map(t => `<tr><td>${esc(t.name)}</td><td>${esc(t.scope)}</td><td>${t.expired ? status('off', bi('Expired', '已過期')) : esc(when(t.expires))}</td><td>${esc(t.last_used ? ago(t.last_used) : bi('never', '從未'))}</td><td class="actions-cell">${btn('token-revoke', bi('Revoke', '撤銷'), '', `data-id="${esc(t.id)}"`)}</td></tr>`).join('') || `<tr><td colspan="5" class="empty">${esc(bi('No tokens.', '沒有權杖。'))}</td></tr>`}</tbody></table></div>
    </section>` : ''}
    <div class="section-title"><h2>${esc(bi('Raw data', '原始資料'))}</h2></div>
    <div class="actions">${btn('raw', bi('System status', '系統狀態'), '', 'data-path="system/status"')}${btn('raw', bi('Capabilities', '功能'), '', 'data-path="system/capabilities"')}${btn('raw', bi('Inbounds', '入站'), '', 'data-path="inbounds"')}${btn('raw', bi('Performance inventory', '效能盤點'), '', 'data-path="system/performance"')}${btn('raw', bi('API contract (OpenAPI)', 'API 契約（OpenAPI）'), '', 'data-path="api-docs"')}</div>
    <div id="raw-out" class="mt"></div>`;
};
