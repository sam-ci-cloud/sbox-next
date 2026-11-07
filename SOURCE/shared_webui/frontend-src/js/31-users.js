/* Users: search/filter/sort/page, bulk actions with exact previews, per-user
   share/export. The protected original identity is visibly locked. */
const PROTOCOL_NAMES = {reality: 'VLESS REALITY', vmess: 'VMess WS', hy2: 'Hysteria2', tuic: 'TUIC v5', anytls: 'AnyTLS'};

function filteredUsers() {
  const v = state.userView;
  const q = v.q.trim().toLowerCase();
  let rows = state.users.filter(u => {
    if (q && !(u.name + ' ' + (u.tags || []).join(' ')).toLowerCase().includes(q)) return false;
    if (v.status === 'enabled' && !u.enabled) return false;
    if (v.status === 'disabled' && u.enabled) return false;
    if (['quota_exceeded','expired','manually_disabled'].includes(v.status)&&u.usage?.status!==v.status)return false;
    if (v.protocol !== 'all' && !u.protocols.includes(v.protocol)) return false;
    return true;
  });
  const protectedRows = rows.filter(u => u.protected);
  rows = rows.filter(u => !u.protected);
  const cmp = {name: (a, b) => a.name.localeCompare(b.name), '-name': (a, b) => b.name.localeCompare(a.name), remaining:(a,b)=>(a.usage?.remaining_bytes??Infinity)-(b.usage?.remaining_bytes??Infinity)||a.name.localeCompare(b.name),status: (a, b) => (a.enabled - b.enabled) || a.name.localeCompare(b.name)}[v.sort];
  rows.sort(cmp);
  return {protectedRows, rows};
}

function userRow(u) {
  const sel = state.userView.selected.has(u.id);
  const protos = u.protocols.length;
  const protoText = protos === 5 ? bi('All 5 protocols', '全部 5 種協定') : bi(`${protos} protocols`, `${protos} 種協定`);
  if (u.protected) {
    return `<tr class="protected"><td class="select-col"><span class="sr">${esc(bi('Not selectable', '不可選取'))}</span></td>
      <td class="name-cell"><strong>${esc(u.name)}</strong><span class="muted small">${esc(state.caps.variant === 'zgocloud' ? bi('Original shared identity used by the already-distributed client file. Cannot be edited, disabled, rotated or revoked here.', '已分發客戶端檔案使用的原始共用身分，無法在此編輯、停用、輪替或撤銷。') : bi('Identity created by the installer. Change it with the CLI.', '安裝器建立的身分，請以 CLI 變更。'))}</span></td>
      <td class="proto-cell"><span class="proto-summary" title="${esc(u.protocols.map(p => PROTOCOL_NAMES[p] || p).join(', '))}">${esc(protoText)}</span></td>
      <td class="status-cell">${status('locked', bi('Protected', '受保護'))}</td>
      <td class="actions-cell">${isAdmin() ? btn('user-share', bi('Connect & export', '連線與匯出'), '', `data-id="${esc(u.id)}" aria-label="${esc(bi('Connect & export for ', '連線與匯出：') + u.name)}"`) : ''}</td></tr>`;
  }
  return `<tr>
    <td class="select-col">${isAdmin() ? `<input type="checkbox" data-select="${esc(u.id)}" ${sel ? 'checked' : ''} aria-label="${esc(bi('Select ', '選取 ') + u.name)}">` : ''}</td>
    <td class="name-cell"><strong>${esc(u.name)}</strong>${(u.tags || []).length ? `<span class="tags">${u.tags.map(chip).join('')}</span>` : ''}</td>
    <td class="proto-cell"><span class="proto-summary" title="${esc(u.protocols.map(p => PROTOCOL_NAMES[p] || p).join(', '))}">${esc(protoText)}</span></td>
    <td class="status-cell">${quotaLabel(u.usage)}<br><span class="small muted">${esc(quotaBytes(u.usage?.used_bytes,u.usage?.quota_bytes))} / ${u.usage?.unlimited?esc(bi('No limit','無上限')):esc(quotaBytes(u.usage?.quota_bytes,u.usage?.quota_bytes))}</span>${u.usage&&!u.usage.unlimited&&u.usage.quota_bytes?meter(u.usage.used_bytes||0,u.usage.quota_bytes,(u.usage.used_bytes||0)>=u.usage.quota_bytes?'error':(u.usage.used_bytes||0)>=.9*u.usage.quota_bytes?'warning':''):''}</td>
    <td class="actions-cell">${isAdmin() ? `${btn('user-detail',bi('Manage','管理'),'primary',`data-id="${esc(u.id)}"`)}${btn('user-share', bi('Connect & export', '連線與匯出'), '', `data-id="${esc(u.id)}" ${u.enabled ? '' : 'disabled'} aria-label="${esc(bi('Connect & export for ', '連線與匯出：') + u.name)}"`)}
      <details class="menu"><summary aria-label="${esc(bi('More actions for ', '更多操作：') + u.name)}">${esc(bi('More', '更多'))}</summary><div class="menu-list" popover="manual">
        ${btn('user-edit', bi('Edit name and tags', '編輯名稱與標籤'), '', `data-id="${esc(u.id)}"`)}
        ${btn('user-toggle', u.enabled ? bi('Disable', '停用') : bi('Enable', '啟用'), '', `data-id="${esc(u.id)}"`)}
        <hr>${btn('user-revoke', bi('Revoke permanently…', '永久撤銷…'), 'danger', `data-id="${esc(u.id)}"`)}
      </div></details>` : '—'}</td></tr>`;
}

function renderUserTable() {
  const v = state.userView;
  const {protectedRows, rows} = filteredUsers();
  const pagesTotal = Math.max(1, Math.ceil(rows.length / v.size));
  v.page = Math.min(v.page, pagesTotal - 1);
  const start = v.page * v.size;
  const pageRows = rows.slice(start, start + v.size);
  const allOnPage = pageRows.length > 0 && pageRows.every(u => v.selected.has(u.id));
  const total = state.users.filter(u => !u.protected).length;
  const body = (v.page === 0 ? protectedRows : []).concat(pageRows).map(userRow).join('');
  const empty = !rows.length && !protectedRows.length;
  const selectedCount = v.selected.size;
  return `
    ${selectedCount ? `<div class="bulkbar" role="region" aria-label="${esc(bi('Bulk actions', '批次操作'))}"><strong>${esc(bi(`${selectedCount} selected`, `已選取 ${selectedCount} 個`))}</strong>
      ${state.accounting?.enabled?btn('bulk-quota',bi('Set data allowance…','設定數據用量…')):''}${btn('bulk-disable', bi('Disable', '停用'))}${btn('bulk-enable', bi('Enable', '啟用'))}${btn('bulk-revoke', bi('Revoke…', '撤銷…'), 'danger')}${btn('bulk-clear', bi('Clear selection', '清除選取'), 'ghost')}</div>` : ''}
    <div class="table-wrap users-table"><table>
      <caption>${esc(bi(rows.length === total ? `${total} users` : `Showing ${rows.length} of ${total} users`, rows.length === total ? `共 ${total} 個使用者` : `顯示 ${rows.length} 個（共 ${total} 個使用者）`))}${v.q || v.status !== 'all' || v.protocol !== 'all' ? ' · ' + esc(bi('filtered', '已篩選')) : ''}</caption>
      <thead><tr><th class="select-col" scope="col">${isAdmin() && pageRows.length ? `<input type="checkbox" data-select-page ${allOnPage ? 'checked' : ''} aria-label="${esc(bi('Select all on this page', '選取此頁全部'))}">` : '<span class="sr">' + esc(bi('Select', '選取')) + '</span>'}</th>
        <th scope="col">${esc(bi('Name', '名稱'))}</th><th scope="col">${esc(bi('Protocols', '協定'))}</th><th scope="col">${esc(bi('Status', '狀態'))}</th><th scope="col" class="actions-cell">${esc(bi('Actions', '操作'))}</th></tr></thead>
      <tbody>${body}</tbody></table></div>
    ${empty ? `<div class="empty"><strong>${esc(bi('No users match these filters', '沒有符合篩選的使用者'))}</strong>${btn('users-reset-filters', bi('Clear filters', '清除篩選'))}</div>` : ''}
    ${!total ? `<div class="empty"><strong>${esc(bi('No additional users yet', '尚無額外使用者'))}</strong><p>${esc(bi('Each user you add gets independent credentials on every protocol, so you can disable one person without affecting anyone else.', '每個新增的使用者在所有協定都有獨立憑證，停用某人不會影響其他人。'))}</p>${isAdmin() ? btn('user-create', bi('Create the first user', '新增第一個使用者'), 'primary') : ''}</div>` : ''}
    <nav class="pager" aria-label="${esc(bi('Pages', '分頁'))}">
      <span class="meta" id="user-page-status" aria-live="polite">${rows.length ? esc(bi(`Showing ${start + 1}–${Math.min(start + v.size, rows.length)} of ${rows.length}`, `顯示第 ${start + 1}–${Math.min(start + v.size, rows.length)} 個，共 ${rows.length} 個`)) : ''}</span>
      <div class="actions">${btn('users-prev', bi('Previous', '上一頁'), '', v.page === 0 ? 'disabled' : '')}
        <span class="meta">${esc(bi(`Page ${v.page + 1} of ${pagesTotal}`, `第 ${v.page + 1} / ${pagesTotal} 頁`))}</span>
        ${btn('users-next', bi('Next', '下一頁'), '', v.page >= pagesTotal - 1 ? 'disabled' : '')}</div>
    </nav>`;
}
function refreshUserTable() {
  const host = $('#user-table'); if (!host) return;
  const focused = document.activeElement && host.contains(document.activeElement) ? (document.activeElement.dataset.action || document.activeElement.dataset.select || null) : null;
  host.innerHTML = renderUserTable();
  if (state.me.role === 'reader') applyReadOnly($('#content'));
  if (focused) { const el = host.querySelector(`[data-action="${focused}"], [data-select="${focused}"]`); if (el && !el.disabled) el.focus(); }
}

pages.users = async function () {
  const [users,accounting]=await Promise.all([api('users'),api('accounting')]);
  state.accounting=accounting;state.users=users;
  users.forEach(u=>{const row=accounting.users.find(x=>x.id===u.id);if(row)Object.assign(u,row);else if(u.protected)u.usage=accounting.legacy;});
  const known = new Set(state.users.map(u => u.id));
  state.userView.selected.forEach(id => { if (!known.has(id)) state.userView.selected.delete(id); });
  const v = state.userView;
  const protocols = [...new Set(state.users.flatMap(u => u.protocols))];
  return `
    <p class="page-intro">${esc(bi('Each user has their own private connection details for every connection type. Pausing or removing one user affects only that user. Usage counts the data each user sends and receives through the VPN (upload plus download). Whole-server traffic is shown under Monitoring.','每位使用者在每種連線類型都有自己的私人連線資料。暫停或移除一位使用者只會影響該使用者。用量計算每位使用者經 VPN 傳送及接收的數據（上傳加下載）。整部伺服器的流量在「監控」顯示。'))}</p>
    <div class="toolbar" role="search">
      <label class="field search"><span>${esc(bi('Search name or tag', '搜尋名稱或標籤'))}</span><input id="user-search" type="search" value="${esc(v.q)}" autocomplete="off"></label>
      ${select('status', bi('Status', '狀態'), [['all', bi('All', '全部')], ['enabled', bi('Enabled', '已啟用')], ['disabled', bi('Disabled', '已停用')],['quota_exceeded',bi('Data used up','數據已用完')],['expired',bi('Expired','已到期')],['manually_disabled',bi('Paused','已暫停')]], v.status, 'id="user-status"')}
      ${select('protocol', bi('Protocol', '協定'), [['all', bi('All protocols', '全部協定')], ...protocols.map(p => [p, PROTOCOL_NAMES[p] || p])], v.protocol, 'id="user-protocol"')}
      ${select('sort', bi('Sort', '排序'), [['name', bi('Name A–Z', '名稱 A–Z')], ['-name', bi('Name Z–A', '名稱 Z–A')], ['status', bi('Disabled first', '停用優先')],['remaining',bi('Least data remaining','剩餘數據最少')]], v.sort, 'id="user-sort"')}
      ${select('size', bi('Per page', '每頁'), [[25, '25'], [100, '100']], v.size, 'id="user-size"')}
      ${isAdmin() ? `<div class="actions" data-admin>${btn('user-create', bi('Create user', '新增使用者'), 'primary')}${btn('users-batch', bi('Create several', '批次新增'))}</div>` : ''}
    </div>
    <div id="user-table">${renderUserTable()}</div>`;
};

function userById(id) { return state.users.find(u => u.id === id); }
function userForm(u) {
  return `<form id="user-form" ${u ? `data-id="${esc(u.id)}"` : ''} novalidate>
    ${field('name', bi('Name', '名稱'), u ? u.name : '', 'text', 'required maxlength="64" pattern="[A-Za-z0-9._\\-]{1,64}" autocomplete="off" autofocus', bi('Letters, digits, dot, underscore or hyphen. Shown in client apps.', '英文字母、數字、點、底線或連字號，會顯示於客戶端。'))}
    ${field('tags', bi('Tags (comma separated, optional)', '標籤（以逗號分隔，可選）'), u ? (u.tags || []).join(', ') : '', 'text', 'autocomplete="off"')}
    ${u ? '' : `<p class="muted small">${esc(bi('New credentials are generated for every enabled protocol.', '會為每個已啟用協定產生新憑證。'))}</p>`}
    <div class="actions end"><button type="button" data-close>${esc(bi('Cancel', '取消'))}</button><button type="submit" class="primary">${esc(bi('Review change', '檢視變更'))}</button></div></form>`;
}

async function shareUser(id) {
  const version = ++modalGeneration;
  // The Subscriptions page is reachable before Users has populated state.users.
  // Always resolve the current user from the API, so direct navigation and
  // changes made in another tab do not depend on stale frontend state.
  const [users, subs] = await Promise.all([api('users'), api('subscriptions')]);
  if (!Array.isArray(users) || !subs || !Array.isArray(subs.users)) {
    throw new ApiError(503, bi('Could not load the current users and links. Refresh and try again.', '無法載入目前的使用者及訂閱連結，請重新整理後再試。'));
  }
  const u = users.find(x => x.id === id);
  if (!u) throw new ApiError(404, bi('This user no longer exists.', '此使用者已不存在。'));
  const row = subs.users.find(x => x.id === id);
  const link = await api('subscriptions/reveal', {id});
  if(version !== modalGeneration)return;
  state.users = users;
  modal(bi('Connect & export · ', '連線與匯出 · ') + u.name, `
    ${u.protected ? `<div class="notice warning"><strong>${esc(bi('This shares the original identity', '這會分享原始身分'))}</strong><span>${esc(bi('Anyone with this link gets the same credentials as every existing original client. Prefer creating a separate user.', '取得此連結的人會使用與所有現有原始客戶端相同的憑證。建議改為建立獨立使用者。'))}</span></div>` : ''}
    ${link.state === 'legacy' ? `<p class="notice warning">${esc(bi('This older link is active but cannot be shown again. Replace it after warning this user.', '此舊連結仍有效，但無法再次顯示。通知使用者後可更換。'))}</p>` : link.state === 'key_unavailable' ? `<p class="notice warning">${esc(bi('The link is active, but its recovery key is unavailable. Restore the matching private backup to show it.', '連結仍有效，但復原金鑰無法使用。請還原相符的私人備份。'))}</p>` : ''}
    <div id="share-result"></div>${manageSubscription(id, !!(row && row.subscription_active), !!link.active)}`,
    `<button type="button" data-close>${esc(bi('Close', '關閉'))}</button>`);
  showLinks(link, '#share-result', id);
}

// Link lifecycle is kept apart from the connect/copy/QR actions: a labelled, collapsed
// section that states the consequences; replace and revoke always ask for confirmation.
function manageSubscription(id, active, existing) {
  const create = btn('sub-rotate', bi('Create subscription link', '建立訂閱連結'), 'primary', `data-id="${esc(id)}" data-existing="0"`);
  return `<details class="disclosure mt manage-subscription"${active ? '' : ' open'}><summary>${esc(bi('Manage subscription link', '管理訂閱連結'))}</summary><div class="body">
    ${active ? `<dl class="consequences">
      <dt>${esc(bi('Replace link', '更換連結'))}</dt><dd>${esc(bi('Creates a new subscription URL. The current URL and its QR code stop working at once; every device must import the new URL.', '建立新的訂閱網址。目前網址及其 QR 碼立即失效，每部裝置都要匯入新網址。'))}</dd>
      <dt>${esc(bi('Revoke link', '撤銷連結'))}</dt><dd>${esc(bi('Stops all subscription URLs for this user. No new link exists until you create one.', '停用此使用者的所有訂閱網址。在你建立新連結前不會有任何連結。'))}</dd>
      </dl><p class="muted small">${esc(bi('Neither changes the VPN credentials: static files and single-server links already imported keep working. To stop VPN access, disable the user instead.', '兩者都不會更改 VPN 憑證：已匯入的靜態檔案及單一伺服器連結仍可使用。如要停止 VPN 存取，請改為停用使用者。'))}</p>
      <div class="actions">${btn('sub-rotate', bi('Replace link…', '更換連結…'), '', `data-id="${esc(id)}" data-existing="${existing ? 1 : 0}"`)}${btn('sub-revoke', bi('Revoke link…', '撤銷連結…'), 'danger', `data-id="${esc(id)}"`)}</div>`
    : `<p class="muted small">${esc(bi('This user has no active subscription link. Creating one does not change the VPN credentials.', '此使用者沒有有效的訂閱連結。建立連結不會更改 VPN 憑證。'))}</p><div class="actions">${create}</div>`}
  </div></details>`;
}

// The ONE export implementation lives in frontend-src/shared/export-center.js and is
// shared with the personal portal and the subscription landing page.
function adminExportAdapter(userId) {
  const exportAs = (sel, format) => api('client-profiles/export', {id: userId, profile: sel.profile, format, endpoint: sel.endpoint});
  return {
    qrSubscription: async (sel, url) => (await api('qr', {text: url})).svg,
    qrNode: async (sel, index, uri) => (await api('qr', {text: uri})).svg,
    nodes: async sel => String((await exportAs(sel, 'links')).content).split(/\r?\n/).map(x => x.trim()).filter(Boolean),
    download: async sel => (await exportAs(sel, sel.format)).content,
  };
}
function showLinks(result, target, userId=result.user_id) {
  const host = $(target); if (!host) return;
  host.innerHTML = `<div class="export-center-host"></div>${result.page ? `<details class="disclosure mt"><summary>${esc(bi('Personal setup page', '個人設定頁'))}</summary><div class="body"><p class="small">${esc(bi('A page for this user with the same choices. Treat it like a password.', '提供相同選項的個人頁面，請當作密碼保管。'))}</p><div class="copy-field"><input id="link-page" readonly value="${esc(result.page)}" aria-label="${esc(bi('Personal setup page', '個人設定頁'))}">${btn('copy', bi('Copy', '複製'), '', 'data-copy="link-page"')}</div></div></details>` : ''}`;
  state.connectionExport = SBOXExportCenter.mount(host.querySelector('.export-center-host'), {catalog: result.catalog, lang: () => state.lang, adapter: adminExportAdapter(userId)});
}

function confirmSubscription(operation, id) {
  const replace = operation === 'replace';
  modal(replace ? bi('Replace subscription link?', '更換訂閱連結？') : bi('Revoke subscription link?', '撤銷訂閱連結？'), `<p class="notice warning">${esc(replace
      ? bi('The current subscription URL and its QR code stop working immediately. Send the new URL to the user; every device must import it again.', '目前的訂閱網址及其 QR 碼會立即失效。請把新網址交給使用者，每部裝置都要重新匯入。')
      : bi('All subscription URLs and QR codes for this user stop working immediately, and their apps can no longer update the profile.', '此使用者的所有訂閱網址及 QR 碼會立即失效，app 將無法再更新設定檔。'))}</p>
    <p class="muted small">${esc(bi('VPN credentials are unchanged: imported static files and single-server links keep working.', 'VPN 憑證不變：已匯入的靜態檔案及單一伺服器連結仍可使用。'))}</p>`,
    `${btn('user-share', bi('Back', '返回'), '', `data-id="${esc(id)}"`)}${btn('sub-confirm', replace ? bi('Replace link', '更換連結') : bi('Revoke link', '撤銷連結'), 'danger', `data-id="${esc(id)}" data-operation="${esc(operation)}"`)}`);
}
