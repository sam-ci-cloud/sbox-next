/* API client with explicit, status-specific errors.
   A response is applied only if it belongs to the current session generation,
   so a request that finishes after sign-out cannot write into the page. */
class ApiError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; Object.assign(this, extra); }
}
const TIMEOUTS = {actions: 920000, 'changes/commit': 240000, 'changes/prepare': 120000, 'diagnostics/doctor': 150000};

async function api(path, data, options = {}) {
  const gen = state.gen;
  const method = options.method || (data !== undefined ? 'POST' : 'GET');
  const init = {method, headers: {}, credentials: 'same-origin', cache: 'no-store'};
  if (data !== undefined) { init.headers['Content-Type'] = 'application/json'; init.headers['X-CSRF-Token'] = state.csrf; init.body = JSON.stringify(data); }
  const key = path.split('?')[0];
  let response;
  try {
    response = await fetch('/api/v1/' + path, {...init, signal: AbortSignal.timeout(TIMEOUTS[key] || 45000)});
  } catch (e) {
    const committing = key === 'changes/commit' || key === 'actions';
    throw new ApiError(0, committing
      ? bi('The connection dropped while the server was working. The change may still have been applied: refresh and check before retrying.', '伺服器處理期間連線中斷，變更可能已套用。請重新整理並確認後再重試。')
      : bi('Could not reach the panel. Check your connection or whether the panel service is running.', '無法連線至面板。請檢查網路或面板服務是否運作。'), {network: true});
  }
  if (gen !== state.gen) throw new ApiError(-1, 'stale session', {stale: true});
  const text = await response.text();
  // Headers can arrive before sign-out/re-login while the body is still pending.
  if (gen !== state.gen) throw new ApiError(-1, 'stale session', {stale: true});
  let body = null;
  if ((response.headers.get('Content-Type') || '').includes('json')) { try { body = JSON.parse(text); } catch { body = null; } } else body = text;
  if (response.ok) return body;
  const message = (body && body.error) || response.statusText || 'Error';
  const retryAfter = Number(response.headers.get('Retry-After')) || null;
  if (response.status === 401 && key !== 'auth/login' && key !== 'auth/reauthenticate') {
    const wasSignedIn = Boolean(state.me);
    showAuth(wasSignedIn ? bi('Your session ended. Sign in again to continue.', '工作階段已結束，請重新登入。') : '');
    throw new ApiError(401, message, {handled: true, wasSignedIn});
  }
  throw new ApiError(response.status, message, {retryAfter, body});
}

/* Plain-language guidance per failure class (used by toasts and inline errors). */
function explain(e) {
  switch (e.status) {
    case 0: return {title: bi('Connection problem', '連線問題'), text: e.message};
    case 400: case 413: case 415: case 422: return {title: bi('Not accepted', '未被接受'), text: e.message};
    case 401: return {title: bi('Not signed in', '未登入'), text: e.message};
    case 403: return {title: bi('Not allowed', '沒有權限'), text: e.message + ' ' + bi('Your account or token cannot do this.', '你的帳戶或權杖無法執行此操作。')};
    case 404: return {title: bi('Not found', '找不到'), text: e.message + ' ' + bi('It may have been removed. Refresh the page.', '可能已被移除，請重新整理。')};
    case 409: return {title: bi('Changed elsewhere', '已在其他地方變更'), text: e.message + ' ' + bi('Another change (CLI or another admin) happened first. Refresh, then prepare the change again.', '有其他變更（CLI 或其他管理員）先完成。請重新整理後再預覽。'), refresh: true};
    case 428: return {title: bi('Confirm it is you', '請確認身分'), text: e.message};
    case 429: return {title: bi('Slow down', '請稍候'), text: bi(`Too many requests. Try again in ${e.retryAfter || 60} seconds.`, `請求過多，請於 ${e.retryAfter || 60} 秒後再試。`)};
    case 503: return {title: bi('Server component unavailable', '伺服器元件無法使用'), text: e.message + ' ' + bi('Run Diagnostics → Doctor or check the service journal.', '請執行「診斷 → Doctor」或檢查服務日誌。'), doctor: true};
    default: return {title: bi('Request failed', '請求失敗'), text: e.message};
  }
}

/* Toasts: success in the polite region, failures in the assertive region. */
function toast(title, text = '', kind = 'ok', extra = '') {
  const region = kind === 'error' ? $('#toast-alert') : $('#toast-status');
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.innerHTML = `<strong>${esc(title)}</strong>${text ? `<p>${esc(text)}</p>` : ''}${extra}`;
  region.appendChild(el);
  while (region.children.length > 3) region.firstChild.remove();
  setTimeout(() => el.remove(), kind === 'error' ? 14000 : 7000);
}
function toastError(e) {
  if (e.stale || e.handled) return;
  const x = explain(e);
  toast(x.title, x.text, 'error', x.refresh ? `<div class="actions">${btn('refresh-page', bi('Refresh', '重新整理'))}</div>` : x.doctor ? `<div class="actions"><a class="btn" href="#logs">${esc(bi('Open diagnostics', '開啟診斷'))}</a></div>` : '');
}

/* Dialog with focus return to the control that opened it. */
let modalOpener = null, modalGeneration = 0;
const modalBlobURLs = new Set();
function clearModalSecrets() {
  state.urls = null;
  modalBlobURLs.forEach(url => URL.revokeObjectURL(url));
  modalBlobURLs.clear();
}
function modal(title, body, foot = '') {
  modalGeneration++; clearModalSecrets();
  const dlg = $('#modal');
  dlg.classList.remove('drawer');
  if (!dlg.open) {
    const active = document.activeElement;
    // A focused action becomes disabled while its request is pending. Browsers
    // blur it to body; guarded() remembers the actual trigger before that blur.
    if (active !== document.body && active !== document.documentElement || !modalOpener || !document.contains(modalOpener)) modalOpener = active;
  }
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = body;
  $('#modal-foot').innerHTML = foot; $('#modal-foot').hidden = !foot;
  applyWidths($('#modal-body'));
  initializePlanFields($('#modal-body'));
  if (!dlg.open) dlg.showModal();
  const first = $('#modal-body [autofocus]') || $('#modal-body input, #modal-body select, #modal-body textarea') || $('#modal-foot button.primary, #modal-foot button.danger') || $('#modal .close');
  if (first) first.focus();
}
function closeModal() {
  modalGeneration++; clearModalSecrets();
  const dlg = $('#modal');
  if (dlg.open) dlg.close();
}
function onModalClosed() {
  // A queued close event may arrive after the dialog has been reopened.
  if ($('#modal').open) return;
  $('#modal-body').replaceChildren(); $('#modal-foot').replaceChildren();
  modalGeneration++; state.change = null; state.detail = null; clearModalSecrets();
  const target = modalOpener && document.contains(modalOpener) ? modalOpener : $('#title');
  modalOpener = null;
  if (target && target.focus) target.focus({preventScroll: true});
}

/* Re-authentication: ask once, then automatically retry the action that needed it. */
function reauth(retry) {
  state.pending = retry || null;
  modal(bi('Confirm it is you', '確認身分'), `
    <p>${esc(bi('This action changes security-sensitive settings or the VPN. Enter your password to continue. You will not be asked again for 5 minutes.', '此操作會變更安全敏感設定或 VPN。請輸入密碼以繼續，5 分鐘內不會再次詢問。'))}</p>
    <form id="reauth-form" novalidate>
      ${field('password', bi('Password', '密碼'), '', 'password', 'autocomplete="current-password" required autofocus')}
      ${state.me && state.me.totp ? field('code', bi('Authenticator or recovery code', '驗證碼或復原碼'), '', 'text', 'autocomplete="one-time-code" inputmode="numeric" required') : ''}
      <div class="actions end"><button type="button" data-close>${esc(bi('Cancel', '取消'))}</button><button type="submit" class="primary">${esc(bi('Confirm and continue', '確認並繼續'))}</button></div>
    </form>`);
}

/* Run a user action once: disable the trigger, show progress, report failure. */
const inflight = new Set();
async function guarded(key, el, fn) {
  if (inflight.has(key)) return;
  inflight.add(key);
  const gen = state.gen;
  const openingGeneration = modalGeneration;
  if (el && !$('#modal').open && document.activeElement === el) modalOpener = el;
  let timer = null;
  if (el) {
    el.disabled = true; el.setAttribute('aria-busy', 'true');
    const original = el.dataset.label || el.textContent; el.dataset.label = original;
    const started = Date.now();
    timer = setInterval(() => { const s = Math.round((Date.now() - started) / 1000); if (s >= 3) el.textContent = original + ' · ' + s + ' s'; }, 1000);
  }
  try {
    await fn();
  } catch (e) {
    if (gen !== state.gen || e.stale || e.handled) return;
    if (e.status === 428) { reauth(() => guarded(key, null, fn)); return; }
    toastError(e);
  } finally {
    inflight.delete(key);
    if (timer) clearInterval(timer);
    if (el && document.contains(el)) { el.disabled = false; el.removeAttribute('aria-busy'); el.textContent = el.dataset.label; }
    if (openingGeneration === modalGeneration && modalOpener === el) modalOpener = null;
  }
}
