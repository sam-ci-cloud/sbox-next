/* Event wiring: one delegated handler per event type. */
const DISRUPTIVE = {
  restart: [['Restart the VPN core', '重新啟動 VPN 核心'], ['All active VPN connections drop for a few seconds and reconnect.', '所有現有 VPN 連線會中斷數秒後重新連線。']],
  recover: [['Recover an interrupted change', '復原中斷的變更'], ['Finishes or rolls back the journalled transaction. The VPN core may restart.', '完成或回復日誌中的交易，VPN 核心可能重新啟動。']],
  restore: [['Restore a backup', '還原備份'], ['Replaces the current VPN configuration with the backup and restarts the core. Users created after the backup lose access.', '以備份取代目前 VPN 設定並重新啟動核心。備份後建立的使用者會失去存取。']],
  'certificate-renew': [['Renew the certificate now', '立即續期憑證'], ['Contacts the public CA. Needs correct DNS and inbound TCP 80 (HTTP-01) or the DNS provider token. The VPN reloads with the new certificate; client files stay the same.', '會連線公開 CA，需要正確 DNS 及入站 TCP 80（HTTP-01）或 DNS 供應商權杖。VPN 會以新憑證重新載入，客戶端檔案不變。']],
  'core-update': [['Update the accounting VPN core', '更新計量 VPN 核心'], ['Resolves a compatible patched core, verifies its build and configuration, then restarts the VPN transactionally. Incompatible builds keep the current core.', '解析相容的已修補核心，驗證建置與設定後以可回復交易重新啟動 VPN。不相容時保留目前核心。']],
  'firewall-apply': [['Reconcile VPN firewall rules', '修復 VPN 防火牆規則'], ['Re-applies only the manager-owned table for the VPN ports listed on this page. SSH, UFW and default chains are not changed.', '只重新套用此頁所列 VPN 連接埠的管理器專屬表，不變更 SSH、UFW 或預設鏈。']],
  'security-repair': [['Repair the SSH guard', '修復 SSH 防護'], ['Re-applies the Fail2Ban jail and early guard owned by the manager. SSH is not restarted.', '重新套用管理器擁有的 Fail2Ban 規則與早期防護，不會重新啟動 SSH。']]
};
const NEEDS_CONFIRM_RESTART = ['restart', 'core-update', 'recover', 'restore', 'certificate-renew'];

function confirmAction(name, args, target, extraHtml = '') {
  const [title, text] = DISRUPTIVE[name];
  state.action = {name, args, target};
  modal(bi(...title), `<div class="notice ${NEEDS_CONFIRM_RESTART.includes(name) ? 'warning' : ''}"><strong>${esc(bi('What happens', '會發生什麼'))}</strong><span>${esc(bi(...text))}</span></div>${extraHtml}`,
    `<button type="button" data-close>${esc(bi('Cancel', '取消'))}</button>${btn('confirm-action', bi('Continue', '繼續'), NEEDS_CONFIRM_RESTART.includes(name) ? 'danger' : 'primary')}`);
}
async function runAction(name, args, target) {
  const payload = {action: name, arguments: {...args}};
  if (NEEDS_CONFIRM_RESTART.includes(name)) payload.arguments.confirm_restart = true;
  const d = await api('actions', payload);
  toast(bi('Finished: ', '完成：') + name, bi('The server reported completion at ', '伺服器回報完成於 ') + when(d.completed_at, {short: true}) + '.');
  const out = target && $(target);
  if (out) out.innerHTML = pre(d.result && d.result.text ? d.result.text : d.result);
}
async function copyText(text, label) {
  try { await navigator.clipboard.writeText(text); toast(bi('Copied', '已複製'), label || ''); }
  catch { toast(bi('Copy failed', '複製失敗'), bi('Select the text and copy it manually.', '請手動選取文字並複製。'), 'error'); }
}
function download(name, content, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([content], {type}));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
async function fetchReport() {
  const r = await fetch('/api/v1/diagnostics/report', {credentials: 'same-origin', cache: 'no-store'});
  if (!r.ok) throw new ApiError(r.status, bi('Report unavailable', '無法取得報告'));
  return r.text();
}

const actions = {
  'refresh-page': () => render({keep: true}),
  'commit-change': el => commitChange(el),
  'user-create': () => modal(bi('Create user', '新增使用者'), userForm(null)),
  'users-batch': () => modal(bi('Create several users', '批次新增使用者'), `<form id="batch-form" novalidate><label class="field"><span>${esc(bi('One name per line, up to 100', '每行一個名稱，最多 100 個'))}</span><textarea name="names" rows="10" required autofocus></textarea></label>${field('tags', bi('Tags for all of them (optional)', '共同標籤（可選）'))}<div class="actions end"><button type="button" data-close>${esc(bi('Cancel', '取消'))}</button><button type="submit" class="primary">${esc(bi('Review change', '檢視變更'))}</button></div></form>`),
  'user-edit': el => modal(bi('Edit user', '編輯使用者'), userForm(userById(el.dataset.id))),
  'user-toggle': el => { const u = userById(el.dataset.id); return prepareChange({kind: 'user-edit', id: u.id, data: {enabled: !u.enabled}}); },
  'user-revoke': el => prepareChange({kind: 'user-revoke', id: el.dataset.id, data: {}}),
  'user-share': el => shareUser(el.dataset.id),
  'bulk-disable': () => prepareChange({kind: 'users-bulk', data: {action: 'disable', ids: [...state.userView.selected]}}),
  'bulk-enable': () => prepareChange({kind: 'users-bulk', data: {action: 'enable', ids: [...state.userView.selected]}}),
  'bulk-revoke': () => prepareChange({kind: 'users-bulk', data: {action: 'revoke', ids: [...state.userView.selected]}}),
  'bulk-clear': () => { state.userView.selected.clear(); refreshUserTable(); },
  'users-prev': () => { state.userView.page = Math.max(0, state.userView.page - 1); refreshUserTable(); },
  'users-next': () => { state.userView.page += 1; refreshUserTable(); },
  'users-reset-filters': () => { Object.assign(state.userView, {q: '', status: 'all', protocol: 'all', page: 0}); render({keep: true}); },
  'sub-rotate': async el => { if (el.dataset.existing === '1') return confirmSubscription('replace', el.dataset.id); await api('subscriptions/rotate-token', {id: el.dataset.id}); return shareUser(el.dataset.id); },
  'sub-revoke': el => confirmSubscription('revoke', el.dataset.id),
  'sub-confirm': async el => { await api(el.dataset.operation === 'replace' ? 'subscriptions/rotate-token' : 'subscriptions/revoke', {id: el.dataset.id}); await shareUser(el.dataset.id); toast(bi('Link updated', '連結已更新'), bi('VPN identities are unchanged. Previous subscription URLs no longer work.', 'VPN 身分保持不變，舊訂閱網址已失效。')); },
  'copy': el => { const input = document.getElementById(el.dataset.copy); return copyText(input.value, bi('Keep it private.', '請保密。')); },
  'qr': async el => {
    const text = state.urls?.[el.dataset.profile], output = $('#qr-out'), version = modalGeneration;
    if (!text || !output) return;
    const d = await api('qr', {text});
    if (version !== modalGeneration || !output.isConnected || state.urls?.[el.dataset.profile] !== text) return;
    modalBlobURLs.forEach(url => URL.revokeObjectURL(url)); modalBlobURLs.clear();
    const url = URL.createObjectURL(new Blob([d.svg], {type: 'image/svg+xml'}));
    modalBlobURLs.add(url);
    output.innerHTML = `<div class="qr-box"><img src="${esc(url)}" alt="${esc(bi('QR code for the ', '以下設定檔網址的 QR 碼：') + el.dataset.profile.toUpperCase() + bi(' subscription URL', ''))}"></div><p class="muted small">${esc(bi('Subscription QR · contains the selected subscription URL. Treat it like a password.', '訂閱 QR · 內容為所選訂閱網址。請視同密碼。'))}</p>`;
  },
  'toggle-landing': async el => { await api('subscriptions/settings', {landing_page: el.dataset.value === '1'}); toast(el.dataset.value === '1' ? bi('Setup pages turned on', '設定頁已開啟') : bi('Setup pages turned off', '設定頁已關閉'), bi('Applies to every existing and new link.', '套用於所有現有及新連結。')); render({keep: true}); },
  'edit-inbounds': () => modal(bi('Change listeners', '變更監聽'), inboundForm()),
  'alerts-check': async () => { const d = await api('alerts/evaluate', {}); toast(bi('Checked', '已檢查'), bi(`${d.transitions.length} change(s) in alert state.`, `警示狀態有 ${d.transitions.length} 項變化。`)); render({keep: true}); },
  'alerts-check-doctor': async () => { const d = await api('alerts/evaluate', {doctor: true}); toast(bi('Checked with Doctor', '已含 Doctor 檢查'), bi(`${d.transitions.length} change(s) in alert state.`, `警示狀態有 ${d.transitions.length} 項變化。`)); render({keep: true}); },
  'run-probe': async () => { await api('protocols/probe', {}); render({keep: true}); },
  'traffic-window': el => { state.trafficWindow = el.dataset.window; render({keep: true}); },
  'run-doctor': async () => { $('#doctor-out').innerHTML = `<p class="loading" aria-busy="true">${esc(bi('Running doctor… this can take up to a minute.', '正在執行 Doctor… 最多可能需要一分鐘。'))}</p>`; const d = await api('diagnostics/doctor'); $('#doctor-out').innerHTML = doctorHtml(d); },
  'run-doctor-overview': async () => { const d = await api('diagnostics/doctor'); toast(d.failures ? bi('Doctor found problems', 'Doctor 發現問題') : bi('Doctor: all checks passed', 'Doctor：全部通過'), bi('Details are under Diagnostics.', '詳情請見診斷頁。'), d.failures ? 'warning' : 'ok'); render({keep: true}); },
  'copy-report': async () => copyText(await fetchReport(), bi('Credentials and URLs are removed.', '已移除憑證與網址。')),
  'download-report': async () => download('sbox-diagnostics.txt', await fetchReport()),
  'perf-inventory': async () => { $('#perf-out').innerHTML = pre(await api('system/performance')); },
  'firewall-status': async () => { $('#security-out').innerHTML = pre((await api('security/firewall-status')).text || ''); },
  'bans': async () => { $('#security-out').innerHTML = pre((await api('security/bans')).text || ''); },
  'security-status': async () => { $('#security-out').innerHTML = pre((await api('security/status')).text || ''); },
  'firewall-apply': async () => { const d = await api('security/firewall'); const rows = portRows(d) || []; confirmAction('firewall-apply', {}, '#security-out', `<p>${esc(bi('Ports kept open by the owned table:', '專屬表維持開放的連接埠：'))}</p><ul>${rows.map(r => `<li><code>${esc(r.port)}/${esc(r.network)}</code> ${esc(r.purpose)}</li>`).join('')}</ul>`); },
  'security-repair': () => confirmAction('security-repair', {}, '#security-out'),
  'renew-test': () => guardedRun('renew-test', {}, '#cert-out'),
  'certificate-renew': () => confirmAction('certificate-renew', {}, '#cert-out'),
  'backup': () => guardedRun('backup', {}, '#update-out'),
  'backups-list': async () => {
    const d = await api('backups'); state.backups = d.backups;
    modal(bi('Restore a backup', '還原備份'), d.backups.length ? `<ul class="plain">${d.backups.slice().reverse().map((b, i) => `<li class="check"><span><strong>${esc(b.name)}</strong><br><span class="muted small">${esc(when(b.created))} · ${esc(bytes(b.bytes))}</span></span>${btn('backup-restore', bi('Restore…', '還原…'), 'danger', `data-index="${d.backups.length - 1 - i}"`)}</li>`).join('')}</ul>` : `<p>${esc(bi('No backups yet.', '尚無備份。'))}</p>`);
  },
  'backup-restore': el => { const b = state.backups[Number(el.dataset.index)]; confirmAction('restore', {name: b.name, sha256: b.sha256}, '#update-out', `<p>${esc(bi('Backup', '備份'))}: <code>${esc(b.name)}</code></p>`); },
  'recover': () => confirmAction('recover', {}, '#update-out'),
  'restart': () => confirmAction('restart', {}, '#update-out'),
  'confirm-action': async () => { const {name, args, target} = state.action; closeModal(); await runAction(name, args, target); },
  'totp-enroll': async () => { const d = await api('auth/totp/enroll', {}); $('#totp-out').innerHTML = `<p>${esc(bi('Add this key to your authenticator app, then enter the 6-digit code it shows.', '將此金鑰加入驗證器，然後輸入顯示的 6 位數代碼。'))}</p><div class="copy-field"><input id="totp-secret" readonly value="${esc(d.secret)}">${btn('copy', bi('Copy', '複製'), '', 'data-copy="totp-secret"')}</div><form id="totp-form" class="toolbar mt" novalidate>${field('code', bi('6-digit code', '6 位數代碼'), '', 'text', 'inputmode="numeric" pattern="[0-9]{6}" required autocomplete="one-time-code"')}<button type="submit" class="primary">${esc(bi('Verify and turn on', '驗證並開啟'))}</button></form>`; $('#totp-out input[name=code]').focus(); },
  'totp-disable': () => modal(bi('Turn off two-factor authentication', '關閉雙因素驗證'), `<form id="totp-disable-form" novalidate><p>${esc(bi('Enter a current code from your authenticator. Recovery codes are deleted.', '輸入驗證器目前的代碼，復原碼將被刪除。'))}</p>${field('code', bi('6-digit code', '6 位數代碼'), '', 'text', 'inputmode="numeric" pattern="[0-9]{6}" required autocomplete="one-time-code" autofocus')}<div class="actions end"><button type="button" data-close>${esc(bi('Cancel', '取消'))}</button><button type="submit" class="danger">${esc(bi('Turn off', '關閉'))}</button></div></form>`),
  'session-revoke': async el => { await api('auth/sessions/revoke', {id: el.dataset.id}); toast(bi('Session signed out', '工作階段已登出')); render({keep: true}); },
  'sessions-revoke-others': async () => { const d = await api('auth/sessions/revoke', {others: true}); toast(bi('Other sessions signed out', '其他工作階段已登出'), bi(`${d.revoked} session(s) ended.`, `已結束 ${d.revoked} 個工作階段。`)); render({keep: true}); },
  'account-toggle': async el => { await api('accounts', {name: el.dataset.name, enabled: el.dataset.enabled === '1'}); toast(el.dataset.enabled === '1' ? bi('Account enabled', '帳戶已啟用') : bi('Account disabled; its sessions and tokens ended', '帳戶已停用，其工作階段與權杖已結束'), el.dataset.name); render({keep: true}); },
  'notify-test': async () => { await api('notifications/test', {}); toast(bi('Test notification delivered', '測試通知已送達'), bi('The destination accepted it.', '目的地已接受。')); },
  'token-revoke': async el => { await api('api-tokens', {revoke: el.dataset.id}); toast(bi('Token revoked', '權杖已撤銷')); render({keep: true}); },
  'audit-prev': () => { state.auditOffset = Math.max(0, state.auditOffset - 50); render({keep: true}); },
  'audit-next': () => { state.auditOffset += 50; render({keep: true}); },
  'raw': async el => { $('#raw-out').innerHTML = pre(await api(el.dataset.path)); }
};
function guardedRun(name, args, target) { return runAction(name, args, target); }

function required(form) {
  const bad = $$('[required]', form).find(i => !i.value.trim() || (i.pattern && !new RegExp('^(?:' + i.pattern + ')$').test(i.value)) || (i.minLength > 0 && i.value.length < i.minLength));
  if (bad) {
    const label = bad.closest('label') ? bad.closest('label').querySelector('span').textContent : bad.name;
    bad.setAttribute('aria-invalid', 'true'); bad.focus();
    throw new ApiError(422, bi('Check this field: ', '請檢查此欄位：') + label);
  }
  $$('[aria-invalid]', form).forEach(i => i.removeAttribute('aria-invalid'));
}
const values = form => Object.fromEntries(new FormData(form));
/* The confirmation field has no name, so it is never sent to the server. */
function confirmPassword(form, selector) {
  const confirm = $(selector, form), password = form.elements.password;
  if (!confirm || confirm.value === password.value) { if (confirm) confirm.removeAttribute('aria-invalid'); return; }
  confirm.setAttribute('aria-invalid', 'true'); confirm.focus();
  throw new ApiError(422, bi('The two new passwords do not match.', '兩次輸入的新密碼不相同。'));
}

const forms = {
  'network-form': submitNetwork,
  'login-form': async form => {
    const d = values(form);
    if (!d.username || !d.password) { $('#auth-error').textContent = bi('Enter your username and password.', '請輸入帳戶與密碼。'); return; }
    // Retire anonymous startup reads before they can cancel this sign-in.
    const gen = ++state.gen;
    $('#auth-error').textContent = '';
    try {
      const r = await api('auth/login', {username: d.username, password: d.password, code: d.code || ''});
      state.csrf = r.csrf; form.reset(); form.elements.username.value = d.username;
      await initialize();
    } catch (e) {
      if (gen !== state.gen || e.stale || e.handled) return;
      $('#auth-error').textContent = e.status === 401 ? bi('Wrong username, password or code.', '帳戶、密碼或驗證碼錯誤。') : explain(e).text;
    }
  },
  'password-form': async form => {
    try { confirmPassword(form, '#pw-confirm'); } catch (e) { $('#auth-error').textContent = e.message; return; }
    required(form); const d = values(form);
    try { const r = await api('auth/change-password', d); state.csrf = r.csrf; form.reset(); await initialize(); toast(bi('Password changed', '密碼已更改')); }
    catch (e) { $('#auth-error').textContent = explain(e).text; }
  },
  'reauth-form': async form => {
    required(form); const d = values(form);
    try { await api('auth/reauthenticate', {password: d.password, code: d.code || ''}); }
    catch (e) { if (e.status === 401) throw new ApiError(422, bi('Wrong password or code.', '密碼或驗證碼錯誤。')); throw e; }
    const retry = state.pending; state.pending = null; closeModal();
    if (retry) await retry();
  },
  'settings-password': async form => { required(form); confirmPassword(form, '#settings-password-confirm'); const r = await api('auth/change-password', values(form)); state.csrf = r.csrf; form.reset(); toast(bi('Password changed', '密碼已更改'), bi('Other sessions were signed out and your API tokens revoked.', '其他工作階段已登出，API 權杖已撤銷。')); },
  'user-form': form => {
    required(form); const d = values(form);
    const data = {name: d.name.trim(), tags: d.tags.split(',').map(x => x.trim()).filter(Boolean)};
    return prepareChange(form.dataset.id ? {kind: 'user-edit', id: form.dataset.id, data} : {kind: 'user-create', data});
  },
  'batch-form': form => {
    required(form); const d = values(form);
    const names = d.names.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
    const tags = d.tags.split(',').map(x => x.trim()).filter(Boolean);
    return prepareChange({kind: 'users-import', data: tags.length ? {names, tags} : {names}});
  },
  'inbounds-form': form => {
    const data = {};
    for (const p of Object.keys(state.inbounds.protocols)) data[p] = {enabled: form.elements[p + '-enabled'].checked, port: Number(form.elements[p + '-port'].value)};
    if (form.elements['vmess-multiplex']) data.vmess.multiplex = form.elements['vmess-multiplex'].checked;
    return prepareChange({kind: 'inbounds', data});
  },
  'policy-form': form => {
    const d = values(form); const dns = {};
    for (const scope of ['global', 'cn', 'bootstrap', 'proxy']) { const lines = (d['dns-' + scope] || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean); if (lines.length) dns[scope] = lines; }
    return prepareChange({kind: 'policy', data: {default_group: d.default_group, primary: d.primary, probe_url: d.probe_url, expected_status: d.expected_status, smart_tolerance_ms: Number(d.smart_tolerance_ms), health_interval_s: Number(d.health_interval_s), health_timeout_ms: Number(d.health_timeout_ms), health_max_failed: Number(d.health_max_failed), smart_lazy: form.elements.smart_lazy.checked, dns, rule_precedence: d.rule_precedence, rules: (d.rules || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean)}});
  },
  'rule-test-form': form => {
    const target = values(form).target;
    const r = testRule(target);
    const out = $('#rule-test-out');
    if (!r) { out.innerHTML = ''; return; }
    out.innerHTML = r.rule ? `<p>${status('info', r.action)} ${esc(bi('Matched custom rule', '符合自訂規則'))} <code>${esc(r.rule)}</code> ${esc(bi('in GLOBAL and CN. INTERNAL still sends it through the VPN.', '（GLOBAL 與 CN）。INTERNAL 仍經 VPN。'))}</p>`
      : `<p>${esc(bi('No custom rule matches. GLOBAL: VPN unless it is a local/LAN address. CN: decided by the client\'s GEOSITE/GEOIP CN data. INTERNAL: VPN.', '沒有自訂規則符合。GLOBAL：除本地／區網位址外經 VPN。CN：由客戶端 GEOSITE/GEOIP CN 資料決定。INTERNAL：經 VPN。'))}</p>`;
  },
  'logs-form': async form => { const d = await api('logs?search=' + encodeURIComponent(values(form).search || '')); $('#log-out').innerHTML = pre(d.text || bi('No matching entries.', '沒有符合的紀錄。')) + `<p class="source">journalctl -u sing-box · ${esc(when(d.sampled_at))}</p>`; },
  'unban-form': form => { required(form); return runAction('unban', {ip: values(form).ip.trim()}, '#security-out'); },
  'core-form': async form => {
    required(form); const d = values(form);
    let preview = '';
    try { const p = await api('actions', {action: 'update-preview', arguments: {version: d.version}}); const r = p.result || p; preview = `<p>${esc(bi('Core', '核心'))}: <strong>sing-box ${esc(r.version)}</strong></p><p class="muted small">${esc(r.source || '')}<br>SHA-256 ${esc(r.sha256 || bi('Reported after verified build', '驗證建置後顯示'))}</p>`; }
    catch (e) { if (e.status === 428) throw e; $('#update-out').innerHTML = `<div class="notice warning"><span>${esc(explain(e).text)}</span></div>`; return; }
    confirmAction('core-update', {version: d.version}, '#update-out', preview);
  },
  'account-form': async form => { required(form); const d = values(form); await api('accounts', d); form.reset(); toast(bi('Account added', '帳戶已新增'), bi('They must change the password at first sign-in.', '對方首次登入時須更改密碼。')); render({keep: true}); },
  'notifications-form': async form => {
    const d = values(form); const payload = {enabled: form.elements.enabled.checked};
    if (d.url) { payload.url = d.url; payload.kind = d.kind; if (d.chat_id) payload.chat_id = d.chat_id; }
    await api('notifications', payload); toast(bi('Notifications saved', '通知已儲存')); render({keep: true});
  },
  'totp-form': async form => { required(form); const r = await api('auth/totp/verify', values(form)); state.me.totp = true; $('#totp-out').innerHTML = `<div class="notice ok"><strong>${esc(bi('Two-factor authentication is on', '雙因素驗證已開啟'))}</strong><span>${esc(bi('Save these single-use recovery codes somewhere safe. They are shown only once.', '請將這些一次性復原碼存放在安全處，只顯示一次。'))}</span></div>${pre(r.recovery_codes.join('\n'))}`; },
  'totp-disable-form': async form => { required(form); await api('auth/totp/disable', values(form)); state.me.totp = false; closeModal(); toast(bi('Two-factor authentication turned off', '雙因素驗證已關閉')); render({keep: true}); },
  'token-form': async form => { required(form); const d = values(form); d.hours = Number(d.hours); const r = await api('api-tokens', d); $('#token-out').innerHTML = `<div class="notice ok"><strong>${esc(bi('Copy this token now', '請立即複製此權杖'))}</strong><span>${esc(bi('It is shown only once.', '只顯示一次。'))}</span></div><div class="copy-field"><input id="new-token" readonly value="${esc(r.token)}">${btn('copy', bi('Copy', '複製'), '', 'data-copy="new-token"')}</div>`; form.reset(); },
  'silence-form': async form => { const d = await api('alerts/silence', {minutes: Number(values(form).minutes)}); toast(d.silenced_until ? bi('Notifications silenced', '通知已靜音') : bi('Notifications resumed', '通知已恢復')); render({keep: true}); },
  'audit-form': form => { const d = values(form); state.auditFilter = d; state.auditOffset = 0; return render({keep: true}); }
};

function wire() {
  document.addEventListener('click', e => {
    if (!e.target.closest('.menu')) $$('details.menu[open]').forEach(m => { m.open = false; });
    const close = e.target.closest('[data-close]');
    if (close) { closeModal(); return; }
    const el = e.target.closest('[data-action]');
    if (!el || !actions[el.dataset.action]) return;
    const actionMenu = el.closest('.menu');
    if (actionMenu) { actionMenu.open = false; actionMenu.querySelector('summary').focus({preventScroll: true}); }
    guarded('action:' + el.dataset.action + ':' + (el.dataset.id || el.dataset.profile || ''), el, () => actions[el.dataset.action](el));
  });
  document.addEventListener('submit', e => {
    const fn = forms[e.target.id]; if (!fn) return;
    e.preventDefault();
    const submit = e.submitter || $('button[type=submit]', e.target);
    guarded('form:' + e.target.id, submit, () => fn(e.target));
  });
  document.addEventListener('change', e => {
    const t = e.target;
    if (t.dataset.select) { t.checked ? state.userView.selected.add(t.dataset.select) : state.userView.selected.delete(t.dataset.select); refreshUserTable(); return; }
    if (t.hasAttribute('data-select-page')) {
      const {rows} = filteredUsers(); const v = state.userView; const page = rows.slice(v.page * v.size, v.page * v.size + v.size);
      page.forEach(u => t.checked ? v.selected.add(u.id) : v.selected.delete(u.id)); refreshUserTable(); return;
    }
    const map = {'user-status': 'status', 'user-protocol': 'protocol', 'user-sort': 'sort', 'user-size': 'size'};
    if (map[t.id]) { state.userView[map[t.id]] = t.id === 'user-size' ? Number(t.value) : t.value; state.userView.page = 0; refreshUserTable(); }
  });
  let searchTimer = null;
  document.addEventListener('input', e => {
    if (e.target.name === 'health_interval_s' || e.target.name === 'health_timeout_ms') {
      const f = e.target.form, out = $('#health-detect');
      if (f && out) out.textContent = healthDetectText(f.elements.health_interval_s.value, f.elements.health_timeout_ms.value);
      return;
    }
    if (e.target.id !== 'user-search') return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.userView.q = e.target.value; state.userView.page = 0; refreshUserTable(); }, 120);
  });
  document.addEventListener('keydown', e => {
    // Keep keyboard focus inside an open dialog (WAI-ARIA dialog pattern).
    if (e.key === 'Tab' && $('#modal').open) {
      const items = $$('#modal button, #modal input, #modal select, #modal textarea, #modal summary, #modal a[href]').filter(el => !el.disabled && el.offsetParent !== null);
      if (items.length) {
        const first = items[0], last = items[items.length - 1];
        if (e.shiftKey && (document.activeElement === first || !$('#modal').contains(document.activeElement))) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && (document.activeElement === last || !$('#modal').contains(document.activeElement))) { e.preventDefault(); first.focus(); }
      }
    }
    if (e.key === 'Escape' && document.body.classList.contains('menu-open')) { setMenu(false); $('#menu').focus(); }
    if (e.key === 'Escape') { const m = $('details.menu[open]'); if (m) { m.open = false; m.querySelector('summary').focus(); } }
  });
  document.addEventListener('toggle', e => {
    if (!e.target.matches?.('details.menu')) return;
    if (e.target.open) $$('details.menu[open]').forEach(m => { if (m !== e.target) m.open = false; });
    placeActionMenu(e.target);
  }, true);
  window.addEventListener('resize', refreshActionMenus);
  document.addEventListener('scroll', refreshActionMenus, true);
  $('#modal').addEventListener('close', onModalClosed);
  // In-page skip link must not be treated as a route change by the hash router.
  $('#skip-link').addEventListener('click', e => { e.preventDefault(); const m = $('#main'); m.focus(); m.scrollIntoView({block: 'start'}); });
  $('#lang').value = state.lang;
  $('#lang').addEventListener('change', () => { state.lang = $('#lang').value; writePref('sbox-lang', state.lang); if (state.me) render({keep: true}); else translateAuth(); renderNav(); });
  $('#theme').addEventListener('change', () => setTheme($('#theme').value));
  matchMedia('(prefers-color-scheme: light)').addEventListener('change',()=>{if(state.theme==='system')setTheme('system');});
  $('#menu').addEventListener('click', () => setMenu(!document.body.classList.contains('menu-open')));
  $('#scrim').addEventListener('click', () => setMenu(false));
  $('#nav').addEventListener('click', e => { if (e.target.closest('a')) { setMenu(false); } });
  $('#refresh').addEventListener('click', () => guarded('refresh', $('#refresh'), () => render({keep: true})));
  $('#logout').addEventListener('click', () => guarded('logout', $('#logout'), async () => { try { await api('auth/logout', {}); } finally { showAuth(bi('Signed out.', '已登出。')); } }));
  window.addEventListener('hashchange', () => { render().then(() => $('#title').focus({preventScroll: true})); });
  setInterval(() => {
    if (!state.me || state.me.reset || document.hidden || $('#modal').open) return;
    const every = POLL[state.page];
    if (every && Date.now() - state.lastRender >= every - 500) render({background: true});
  }, 5000);
  setInterval(() => { if (state.me && !document.hidden && state.page !== 'alerts' && state.page !== 'overview') refreshAlertCount(); }, 60000);
}

document.documentElement.dataset.theme = state.theme==='system'?(prefersLight()?'light':'dark'):state.theme;
wire();
translateAuth();
guarded('init', null, initialize);
if (typeof module !== 'undefined') module.exports = {esc, bytes, bitrate, testRule, explain};
