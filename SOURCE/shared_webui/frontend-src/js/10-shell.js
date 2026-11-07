/* Navigation, routing, rendering and session lifecycle. */
const GROUPS = [
 ['home',['Overview','總覽'],['overview']],
 ['people',['People & connections','使用者同連線'],['users','subscriptions']],
 ['connection',['VPN configuration','VPN 設定'],['network','inbounds','policy']],
 ['operations',['Operations','日常管理'],['monitor','alerts','health','traffic','certificates','logs','updates']],
 ['administration',['Administration','管理設定'],['access','settings','security','audit','api']]
];
const PAGE_LABELS = {
  overview: ['Overview', '總覽'], users: ['Users & quota', '使用者與配額'],monitor:['VPS monitoring','VPS 監控'], subscriptions: ['Subscriptions', '訂閱'], inbounds: ['Inbounds & ports', '入站與連接埠'],
  network:['Network setup','網路設定'],policy: ['Client policy', '客戶端策略'], alerts: ['Alerts & timeline', '警示與時間軸'], health: ['Protocol health', '協定健康'], traffic: ['Host traffic', '主機流量'],
  logs: ['Diagnostics & logs', '診斷與日誌'], certificates: ['Certificates', '憑證'], security: ['Firewall & SSH guard', '防火牆與 SSH 防護'], access: ['Sign-in & sessions', '登入與工作階段'],
  updates: ['Versions & recovery', '版本與復原'], settings: ['Accounts & notifications', '帳戶與通知'], audit: ['Audit log', '稽核紀錄'], api: ['Advanced & API', '進階與 API']
};
const POLL = {users:30000,monitor:30000,overview: 30000, alerts: 60000, traffic: 60000, health: 60000};
const pageLabel = id => bi(...(PAGE_LABELS[id] || [id, id]));
const groupOf = id => GROUPS.find(g => g[2].includes(id));
const pages = {};  // id -> async render(): returns HTML string

function renderNav() {
  document.documentElement.lang = state.lang === 'zh' ? 'zh-Hant' : 'en';
  const counts = state.alertsOpen ? `<span class="count ${state.alertsWorst === 'critical' ? '' : 'warning'}" aria-label="${esc(bi(state.alertsOpen + ' open alerts', state.alertsOpen + ' 個未解決警示'))}">${state.alertsOpen}</span>` : '';
  state.navGroups = state.navGroups || {};
  $$('#nav details[data-nav-group]').forEach(d => { state.navGroups[d.dataset.navGroup] = d.open; });
  if (state.navPage !== state.page) {
    const current = groupOf(state.page);
    if (current) state.navGroups[current[0]] = true;
    state.navPage = state.page;
  }
  $('#nav').innerHTML = GROUPS.map(([id, label, items]) => {
    const links = items.filter(p=>p!=="network"||isAdmin()).map(p => `<a href="#${p}" ${state.page === p ? 'aria-current="page"' : ''}>${esc(pageLabel(p))}${p === 'alerts' ? counts : ''}</a>`).join('');
    if (items.length === 1 || id === 'people') return `<div class="nav-group">${links}</div>`;
    return `<details class="nav-group" data-nav-group="${id}" ${state.navGroups[id] ? 'open' : ''}>
      <summary id="ng-${id}">${esc(bi(...label))}${id === 'operations' && state.alertsOpen ? counts : ''}</summary>
      <div role="group" aria-labelledby="ng-${id}">${links}</div></details>`;
  }).join('');
  const t = (id, en, zh) => { const el = $(id); if (el) el.textContent = bi(en, zh); };
  t('#logout', 'Sign out', '登出'); t('#theme-label', state.theme === 'dark' ? 'Light' : 'Dark', state.theme === 'dark' ? '淺色' : '深色'); t('#refresh-label', 'Refresh', '重新整理'); t('#skip-link', 'Skip to content', '跳至內容');
  t('#footnote', 'Self-hosted. No telemetry, no external assets.', '自行託管，無遙測，無外部資源。');
  $('#menu').setAttribute('aria-label', bi('Open navigation', '開啟導覽'));
  $('#refresh').setAttribute('aria-label', bi('Refresh this page', '重新整理此頁'));
  $('#theme').setAttribute('aria-label',bi('Appearance','外觀'));
  $('#theme').innerHTML=[['system',bi('System','跟隨系統')],['light',bi('Light','淺色')],['dark',bi('Dark','深色')]].map(([v,label])=>`<option value="${v}" ${state.theme===v?'selected':''}>${esc(label)}</option>`).join('');
}

function translateAuth() {
  document.documentElement.lang = state.lang === 'zh' ? 'zh-Hant' : 'en';
  const t = (id, en, zh) => { const el = $(id); if (el) el.textContent = bi(en, zh); };
  t('#auth-title', 'Sign in', '登入'); t('#auth-intro', 'Server administration for this VPS.', '此 VPS 的伺服器管理。');
  t('#l-user', 'Username', '帳戶'); t('#l-pass', 'Password', '密碼'); t('#l-code', 'Authenticator or recovery code (if enabled)', '驗證碼或復原碼（如已啟用）');
  t('#login-submit', 'Sign in', '登入'); t('#pw-intro', 'Change the initial password before continuing.', '繼續前請先更改初始密碼。');
  t('#l-old', 'Current password', '目前密碼'); t('#l-new', 'New password (12 or more characters)', '新密碼（至少 12 個字元）'); t('#pw-submit', 'Save password', '儲存密碼'); t('#l-confirm', 'Confirm new password', '再輸入新密碼');
  const rec = $('#auth-recovery'); if (rec) rec.innerHTML = esc(bi('Locked out? On the server run', '無法登入？請在伺服器執行')) + ' <code>sudo sbox webui reset-admin</code>';
}

function routeFromHash() {
  const id = decodeURIComponent(location.hash.slice(1).split('?')[0]) || 'overview';
  return Object.prototype.hasOwnProperty.call(PAGE_LABELS, id) ? id : null;
}

/* Render the latest requested route. A slow response for an earlier route is
   discarded rather than shown (navigation race). Background refreshes keep
   scroll position, focus and open <details>. */
async function render(opts = {}) {
  if (!state.me || state.me.reset) return;
  let id = routeFromHash();
  const unknown = id === null;
  if (unknown) id = 'overview';
  state.wanted = id;
  const token = {};
  state.rendering = token;
  const gen = state.gen;
  const background = Boolean(opts.background);
  if (!background) {
    state.page = id; renderNav();
    $('#title').textContent = pageLabel(id);
    const g = groupOf(id); $('#crumb').textContent = g && g[0] !== 'home' ? bi(...g[1]) : '';
    document.title = pageLabel(id) + ' · SBOX';
    if (!opts.keep) $('#content').innerHTML = `<div class="loading" aria-busy="true">${esc(bi('Loading current state…', '正在讀取目前狀態…'))}</div>`;
  }
  let html;
  try {
    html = await pages[id]();
  } catch (e) {
    if (state.rendering !== token || gen !== state.gen || e.stale || e.handled) return;
    if (background) return;  // keep the last good view; the next poll retries
    if (e.status === 428) { reauth(() => render()); html = ''; }
    else {
      const x = explain(e);
      html = `<div class="notice error" role="alert"><strong>${esc(x.title)}</strong><span>${esc(x.text)}</span><div class="actions">${btn('refresh-page', bi('Try again', '重試'))}${x.doctor && id !== 'logs' ? `<a class="btn" href="#logs">${esc(bi('Open diagnostics', '開啟診斷'))}</a>` : ''}</div></div>`;
    }
  }
  if (state.rendering !== token || gen !== state.gen || state.wanted !== id) return;
  const content = $('#content');
  const keep = background || opts.keep;
  const scroll = keep ? window.scrollY : 0;
  const openDetails = keep ? $$('details[open][id]', content).map(d => d.id) : [];
  const focusedId = keep && content.contains(document.activeElement) ? document.activeElement.id : null;
  if (background && content.contains(document.activeElement) && !focusedId && document.activeElement !== content) return; // do not yank an unnamed focused control
  content.innerHTML = (unknown ? `<div class="notice warning" role="status"><strong>${esc(bi('Page not found', '找不到頁面'))}</strong><span>${esc(bi('That address does not exist. Showing the overview instead.', '此網址不存在，改為顯示總覽。'))}</span></div>` : '') + html;
  if (state.me.role === 'reader') applyReadOnly(content);
  applyWidths(content);
  observeAdaptiveCharts(content);
  openDetails.forEach(i => { const d = document.getElementById(i); if (d) d.open = true; });
  if (focusedId && document.getElementById(focusedId)) document.getElementById(focusedId).focus({preventScroll: true});
  if (keep) window.scrollTo(0, scroll);
  state.lastRender = Date.now();
  if (pages[id].after) pages[id].after();
  if (unknown) { history.replaceState(null, '', '#overview'); $('#title').focus({preventScroll: true}); }
}

/* Reader accounts see information, not disabled-looking controls. */
function applyReadOnly(root) {
  $$('[data-admin]', root).forEach(el => el.remove());
  if (!$('.notice.readonly', root)) root.insertAdjacentHTML('afterbegin', `<div class="notice readonly" role="note"><strong>${esc(bi('Read-only account', '唯讀帳戶'))}</strong><span>${esc(bi('You can view status. Changes need an administrator.', '你可以檢視狀態，變更需要管理員。'))}</span></div>`);
}
const adminOnly = html => isAdmin() ? html.replace(/^<(\w+)/, '<$1 data-admin') : '';

function showAuth(message = '') {
  state.gen++;
  state.urls = null; state.me = null; state.csrf = ''; state.pending = null; state.change = null; state.users = null; state.alertsOpen = 0;
  state.userView.selected.clear();
  if ($('#modal').open) $('#modal').close();
  $('#modal-body').replaceChildren(); $('#content').replaceChildren(); $('#nav').replaceChildren();
  $$('.toast').forEach(t => t.remove());
  $('#shell').hidden = true; $('#auth').hidden = false; $('#login-form').hidden = false; $('#password-form').hidden = true;
  document.body.classList.remove('menu-open');
  translateAuth();
  $('#auth-error').textContent = message;
  const user = $('#login-form input[name=password]'); if (user) user.focus();
}

async function initialize() {
  const me = await api('auth/me');
  state.me = me; state.csrf = me.csrf;
  if (me.schema !== 1) throw new ApiError(409, bi('Panel and API versions do not match. Reload the page or roll the panel back.', '面板與 API 版本不符。請重新載入或回復面板版本。'));
  if (me.reset) {
    $('#auth').hidden = false; $('#shell').hidden = true; $('#login-form').hidden = true; $('#password-form').hidden = false; translateAuth();
    $('#password-form input[name=old]').focus();
    return;
  }
  $('#auth').hidden = true; $('#shell').hidden = false; $('#auth-error').textContent = '';
  state.caps = await api('system/capabilities');
  $('#variant').textContent = state.caps.variant === 'zgocloud' ? 'ZgoCloud' : bi('Universal', '通用版');
  $('#account').textContent = me.name + ' (' + (me.role === 'admin' ? bi('administrator', '管理員') : bi('read-only', '唯讀')) + ')';
  $('#build').textContent = 'SBOX Control ' + me.version;
  await render();
  // Initial load keeps the document start as focus origin so "Skip to content" is
  // the first Tab stop; route changes move focus to the page heading instead.
  if (document.activeElement && document.activeElement !== document.body && !$('#shell').contains(document.activeElement)) document.activeElement.blur();
  refreshAlertCount();
}

async function refreshAlertCount() {
  if (!state.me || state.me.reset) return;
  try {
    const d = await api('alerts');
    const open = d.alerts.filter(a => !a.resolved_at);
    const changed = open.length !== state.alertsOpen;
    state.alertsOpen = open.length; state.alertsWorst = open.some(a => a.severity === 'critical') ? 'critical' : open.length ? 'warning' : null;
    if (changed) renderNav();
  } catch { /* badge is best-effort */ }
}

function setTheme(theme) {
  state.theme = theme; writePref('sbox-theme', theme);
  document.documentElement.dataset.theme = theme==='system'?(prefersLight()?'light':'dark'):theme;
  $('#theme').value=theme;
  renderNav();
}
function setMenu(open) {
  document.body.classList.toggle('menu-open', open);
  $('#menu').setAttribute('aria-expanded', String(open));
  if (open) { const cur = $('#nav a[aria-current=page]') || $('#nav a'); if (cur) cur.focus(); }
}
