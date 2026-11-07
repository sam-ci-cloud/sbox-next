/* Core helpers: escaping, formatting, language, persisted (non-secret) preferences. */
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

function readPref(key, fallback) { try { return localStorage.getItem(key) || fallback; } catch { return fallback; } }
function writePref(key, value) { try { localStorage.setItem(key, value); } catch { /* private mode: keep in memory */ } }
const prefersLight = () => typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches;

const state = {
  lang: readPref('sbox-lang', (navigator.language || '').toLowerCase().startsWith('zh') ? 'zh' : 'en'),
  theme: readPref('sbox-theme', 'system'),
  csrf: '', me: null, caps: null, page: 'overview', gen: 0, rendering: null, wanted: null,
  pending: null, change: null, alertsOpen: 0, alertsWorst: null, lastRender: 0, users: null,
  userView: {q: '', status: 'all', protocol: 'all', sort: 'name', size: 25, page: 0, selected: new Set()},
  trafficWindow: '1h', auditFilter: {}, auditOffset: 0
};

/* bi(en, zh): every visible string is written in both languages at the call site. */
const bi = (en, zh) => state.lang === 'zh' ? zh : en;
const locale = () => state.lang === 'zh' ? 'zh-Hant-HK' : 'en-GB';
const number = (n, digits = 0) => n === null || n === undefined || Number.isNaN(n) ? '—' : Number(n).toLocaleString(locale(), {maximumFractionDigits: digits, minimumFractionDigits: digits});
/* Usage beside a quota: same unit family as that quota (GB vs GiB). */
function quotaBytes(n, limit) { return n === null || n === undefined ? bi('unavailable', '無法取得') : SBOXUsage.quotaSize(n, limit, state.lang); }
function bytes(n) {
  if (n === null || n === undefined) return bi('unavailable', '無法取得');
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; let i = 0; let v = Number(n);
  while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return number(v, i ? 1 : 0) + ' ' + units[i];
}
/* Network rates in bits per second (decimal), the unit providers sell bandwidth in. */
function bitrate(bytesPerSecond) {
  if (bytesPerSecond === null || bytesPerSecond === undefined) return '—';
  const bits = bytesPerSecond * 8; const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s']; let i = 0; let v = bits;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return number(v, v < 10 && i ? 2 : 1) + ' ' + units[i];
}
function when(ts, opts = {}) {
  if (!ts) return bi('never', '從未');
  const d = new Date(ts * 1000);
  const format = opts.short ? {hour: '2-digit', minute: '2-digit'} : {year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'};
  if(opts.timeZone) Object.assign(format,{timeZone:opts.timeZone,timeZoneName:'short'});
  return d.toLocaleString(locale(), format);
}
function ago(ts) {
  if (!ts) return bi('never', '從未');
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return bi(s + ' s ago', s + ' 秒前');
  if (s < 3600) return bi(Math.round(s / 60) + ' min ago', Math.round(s / 60) + ' 分鐘前');
  if (s < 86400) return bi(Math.round(s / 3600) + ' h ago', Math.round(s / 3600) + ' 小時前');
  return bi(Math.round(s / 86400) + ' d ago', Math.round(s / 86400) + ' 天前');
}
function duration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600), m = Math.floor(seconds % 3600 / 60);
  return d ? bi(`${d} d ${h} h`, `${d} 天 ${h} 小時`) : h ? bi(`${h} h ${m} min`, `${h} 小時 ${m} 分`) : bi(`${m} min`, `${m} 分鐘`);
}

/* Status chips: glyph + word + colour (WCAG 1.4.1). */
const STATUS_WORDS = {
  ok: ['Healthy', '正常'], warning: ['Needs attention', '需要留意'], error: ['Problem', '異常'], unknown: ['Not tested', '未測試'],
  info: ['Info', '資訊'], off: ['Disabled', '已停用'], locked: ['Protected', '受保護'], critical: ['Critical', '嚴重'], stale: ['Stale', '過時']
};
function status(kind, word) {
  const k = kind === 'critical' ? 'error' : kind === 'stale' ? 'warning' : kind;
  const w = word || (STATUS_WORDS[kind] ? bi(...STATUS_WORDS[kind]) : kind);
  return `<span class="status ${esc(k)}">${esc(w)}</span>`;
}
const chip = text => `<span class="chip">${esc(text)}</span>`;
const source = text => text ? `<p class="source">${esc(text)}</p>` : '';
const pre = value => `<pre>${esc(typeof value === 'string' ? value : JSON.stringify(value, null, 2))}</pre>`;
function btn(action, label, cls = '', attrs = '') { return `<button type="button" data-action="${esc(action)}" class="${esc(cls)}" ${attrs}>${esc(label)}</button>`; }
function field(name, label, value = '', type = 'text', attrs = '', hint = '') {
  return `<label class="field"><span>${esc(label)}</span><input name="${esc(name)}" type="${esc(type)}" value="${esc(value)}" ${attrs}>${hint ? `<span class="hint">${esc(hint)}</span>` : ''}</label>`;
}
function select(name, label, options, value, attrs = '') {
  return `<label class="field"><span>${esc(label)}</span><select name="${esc(name)}" ${attrs}>${options.map(([v, l]) => `<option value="${esc(v)}" ${String(v) === String(value) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>`;
}
const checkbox = (name, label, checked = false, attrs = '') => `<label class="check"><input type="checkbox" name="${esc(name)}" ${checked ? 'checked' : ''} ${attrs}><span>${esc(label)}</span></label>`;
function meter(used, total, kind = '') {
  const pct = total ? Math.max(0, Math.min(100, used / total * 100)) : 0;
  return `<div class="meter ${kind}" role="img" aria-label="${esc(number(pct, 0))}%"><i data-width="${pct.toFixed(1)}"></i></div>`;
}
/* CSP forbids inline style attributes, so widths are applied through CSSOM. */
function applyWidths(root = document) { $$('[data-width]', root).forEach(el => { el.style.width = el.dataset.width + '%'; }); }
const isAdmin = () => state.me && state.me.role === 'admin';
