/* Every VPN-affecting change: server-validated preview -> explicit impact ->
   single-use commit -> result reported from the server's own observation. */
function namesList(list, limit = 40) {
  if (!list || !list.length) return '—';
  const shown = list.slice(0, limit).map(n => chip(n)).join('');
  return `<span class="names">${shown}${list.length > limit ? chip(bi(`+${list.length - limit} more`, `另外 ${list.length - limit} 個`)) : ''}</span>`;
}
const KIND_TITLE = {
  'user-create': ['Create user', '新增使用者'], 'users-import': ['Create users', '批次新增使用者'], 'user-edit': ['Edit user', '編輯使用者'],
  'user-disable': ['Disable user', '停用使用者'], 'user-revoke': ['Revoke user', '撤銷使用者'], 'users-bulk': ['Change selected users', '變更所選使用者'],
  'quota-bulk':['Assign quotas','指派配額'],quota:['Change user quota','變更使用者配額'],'portal-account':['Manage portal login','管理入口網站登入'],'accounting-policy':['Accounting policy','計量策略'],
  network:['Change network setup','變更網路設定'],inbounds: ['Change listeners', '變更監聽'], policy: ['Change client policy', '變更客戶端策略']
};

async function prepareChange(request, opener) {
  const d = await api('changes/prepare', request);
  state.change = {token: d.token, request, preview: d};
  const s = d.summary || {};
  const u = s.users || {};
  const rows = [];
  const add = (label, html) => rows.push(`<div class="row"><span>${esc(label)}</span><span>${html}</span></div>`);
  if (u.created && u.created.length) add(bi('New users', '新使用者'), namesList(u.created));
  if (u.disabled && u.disabled.length) add(bi('Will be disabled', '將停用'), namesList(u.disabled));
  if (u.enabled && u.enabled.length) add(bi('Will be enabled', '將啟用'), namesList(u.enabled));
  if (u.removed && u.removed.length) add(bi('Will be revoked (credentials deleted)', '將撤銷（刪除憑證）'), namesList(u.removed));
  if (u.renamed && u.renamed.length) add(bi('Renamed', '重新命名'), namesList(u.renamed));
  if (u.retagged && u.retagged.length) add(bi('Tags changed', '標籤變更'), namesList(u.retagged));
  if (s.listeners && s.listeners.length) add(bi('Listeners', '監聽'), s.listeners.map(l => esc(`${l.protocol} ${l.field}: ${l.before} → ${l.after}`)).join('<br>'));
  if (s.policy_fields && s.policy_fields.length) add(bi('Policy fields', '策略欄位'), namesList(s.policy_fields));
  if (!s.network && s.affected_total === 0 && !(s.listeners || []).length && !(s.policy_fields || []).length) add(bi('Effect', '影響'), esc(bi('No difference from the current configuration.', '與目前設定沒有差異。')));
  add(bi('Services affected', '受影響服務'), s.services && s.services.length ? s.services.map(esc).join('<br>') : esc(bi('None. Clients pick up the new profile on their next subscription refresh.', '無。客戶端會在下次更新訂閱時取得新設定。')));
  add(bi('Protected original identity', '受保護原始身分'), (s.protected_identity === 'unchanged' ? status('locked', bi('Unchanged', '不變')) : status('warning', s.protected_identity || '?')) + `<br><span class="muted small">${esc(s.protected_identity_note || '')}</span>`);
  if (s.unaffected_users !== undefined) add(bi('Other users', '其他使用者'), esc(bi(`${s.unaffected_users} unaffected`, `${s.unaffected_users} 個不受影響`)));
  if(s.network){const n=s.network;add(bi('Network policies','網路策略'),pre(n.before)+' → '+pre(n.after));add(bi('VPN listener','VPN監聽'),esc(n.old_listen)+' → '+esc(n.new_listen));add(bi('Subscription HTTPS access','訂閱HTTPS存取'),esc(n.panel_before)+' → '+esc(n.panel_after));add(bi('Client exports and QR','客戶端設定及QR'),esc(bi('Updated profiles use the new endpoint policy. Subscription identities and credentials stay unchanged; refresh client imports and node QR codes.','更新設定會使用新端點策略。訂閱身分及憑證不變；請更新客戶端匯入及節點QR。')));add(bi('Recovery','復原'),esc(bi('Native backup before apply; automatic rollback on failure. SSH configuration stays unchanged.','套用前建立原生備份；失敗會自動回復。SSH設定不變。')));}
  add(bi('Version', '版本'), `<code>${esc(s.before_fingerprint || '?')}</code> → <code>${esc(s.after_fingerprint || '?')}</code>`);
  const title = bi(...(KIND_TITLE[request.kind] || [s.title || request.kind, s.title || request.kind]));
  modal(bi('Review: ', '檢視：') + title, `
    <div class="notice ${d.restart ? 'warning' : ''}"><strong>${esc(d.restart ? bi('The VPN core will restart', 'VPN 核心將重新啟動') : bi('No VPN restart', '不會重新啟動 VPN'))}</strong>
      <span>${esc(d.restart ? bi('Active connections drop for a few seconds and reconnect. If the new configuration fails its health check, the manager rolls back automatically.', '現有連線會中斷數秒後重新連線。若新設定未通過健康檢查，管理器會自動回復。') : bi('Saved without restarting the VPN. A new data allowance takes effect within a few seconds.','已儲存，毋須重新啟動 VPN。新的數據用量會在數秒內生效。'))}</span></div>
    <div class="impact">${rows.join('')}${s.quota_users?.length?`<p><strong>${esc(bi('Users with a data allowance','有數據用量限制的使用者'))}</strong>: ${namesList(s.quota_users)}</p>`:''}${s.portal_users?.length?`<p><strong>${esc(bi('Portal logins','入口網站登入'))}</strong>: ${namesList(s.portal_users)}</p>`:''}</div>
    <details class="disclosure mt" id="diff-details"><summary>${esc(bi('Redacted configuration diff', '已遮蔽設定差異'))}</summary><div class="body">${pre(d.diff || bi('(no textual difference)', '（無文字差異）'))}</div></details>
    <p class="muted small">${esc(bi('Validated by the server with the real core checker. This preview expires', '已由伺服器以真實核心檢查器驗證。此預覽到期於'))} ${esc(when(d.expires_at, {short: true}))}. ${esc(bi('It is refused if anything changes first (for example a CLI change).', '若在此之前有任何變更（例如 CLI），將被拒絕。'))}</p>`,
    `<button type="button" data-close>${esc(bi('Cancel', '取消'))}</button>${btn('commit-change', d.restart ? bi('Apply and restart VPN', '套用並重新啟動 VPN') : bi('Apply change', '套用變更'), d.restart ? 'danger' : 'primary')}`);
}

async function commitChange(el) {
  const change = state.change;
  if (!change) return;
  let result;
  try {result=await api('changes/commit',{token:change.token});}
  catch(e){if(change.request.kind==='network'&&!e.status){state.change=null;closeModal();toast(bi('Reconnect and verify network settings','請重新連線並核對網路設定'),bi('HTTPS access may have restarted. Reopen this domain and inspect Network setup / backups. Do not replay the consumed preview.','HTTPS存取可能已重新啟動。請重開此網域檢查網路設定及備份，勿重送已使用的預覽。'),'warning');return;}throw e;}
  state.change = null;
  closeModal();
  const title = bi(...(KIND_TITLE[change.request.kind] || [change.request.kind, change.request.kind]));
  const parts = [bi('Committed and verified by the manager.', '已由管理器提交並驗證。')];
  if (result.restarted) parts.push(result.service_active ? bi('VPN core is running after restart', '重新啟動後 VPN 核心運作中') + (result.core_pid ? ' (PID ' + result.core_pid + ')' : '') + '.' : bi('Warning: the VPN core is not active after the change. Open diagnostics.', '警告：變更後 VPN 核心未運作，請開啟診斷。'));
  parts.push(bi('New version ', '新版本 ') + (result.state_fingerprint || '?') + '.');
  toast(title + ': ' + bi('done', '完成'), parts.join(' '), result.restarted && !result.service_active ? 'warning' : 'ok');
  state.userView.selected.clear();
  await render({keep: true});
  if(result.onboarding){
    modal(bi('User ready · copy the private links','使用者已就緒 · 請複製私人連結'),`<p>${esc(bi('Credentials, quota and subscription were validated together. Keep these links private. Return to this user’s Connection page to view them again.','憑證、配額及訂閱已一併驗證。請保密，日後可在此使用者的連線頁再次取得。'))}</p><div id="onboarding-links"></div><p>${esc(bi('Personal portal','個人入口網站'))}: <a href="${esc(result.onboarding.portal_url)}" target="_blank" rel="noopener">${esc(result.onboarding.portal_url)}</a></p>`,`<button type="button" data-close>${esc(bi('Done','完成'))}</button>`);
    showLinks(result.onboarding,'#onboarding-links');
  }
}

