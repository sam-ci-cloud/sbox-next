/* Deterministic lifecycle regressions against the real Portal script.
   Mock HTTP/DOM data is NOT live deployment, VPN or browser acceptance evidence. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../frontend-src/portal/portal.js'), 'utf8');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return {promise, resolve}; };
const reply = (value, status = 200) => ({ok: status < 400, status, json: async () => value});
const me = (changes = {}) => ({display_name: 'Private test user', status: 'active', reset_password: false,
  freshness: 'fresh', sampled_at: 100, timezone: 'Asia/Hong_Kong', used_bytes: 100,
  upload_bytes: 40, download_bytes: 60, remaining_bytes: 900, quota_bytes: 1000,
  period: 'monthly', ...changes});
const history = () => ({window: '30d', timezone: 'Asia/Hong_Kong', buckets: [], totals: {upload_bytes: 40, download_bytes: 60}});

function environment(page = 'overview') {
  const elements = new Map(), listeners = {}, intervals = [], revoked = [], calls = [];
  let context;
  class Element {
    constructor(id, tag = 'div') { this.id = id; this.tagName = tag.toUpperCase(); this.value = ''; this.disabled = false; this.hidden = false; this.isConnected = true; this._html = ''; this.children = new Set(); this.attrs = {}; }
    set innerHTML(value) {
      for (const child of this.children) { child.isConnected = false; if (elements.get(child.id) === child) elements.delete(child.id); }
      this.children.clear(); this._html = value;
      for (const match of value.matchAll(/<([a-z][\w-]*)\b([^>]*\bid="([^"]+)"[^>]*)>/gi)) {
        const child = new Element(match[3], match[1]);
        child.value = /\bvalue="([^"]*)"/.exec(match[2])?.[1] || '';
        const prior = elements.get(child.id); if (prior) prior.isConnected = false;
        elements.set(child.id, child); this.children.add(child);
      }
    }
    get innerHTML() { return this._html; }
    setAttribute(key, value) { this.attrs[key] = value; }
    replaceChildren() { this.innerHTML = ''; }
    focus() { document.activeElement = this; }
    closest(selector) { return selector === 'button' && this.tagName === 'BUTTON' ? this : null; }
    querySelector(selector) { return selector.startsWith('#') ? elements.get(selector.slice(1)) || null : new Element('', 'button'); }
    contains(node) { return this.children.has(node); }
    close() { this.open = false; }
    showModal() { this.open = true; }
  }
  for (const id of ['language', 'brand-label', 'theme', 'footer', 'content', 'portal-nav', 'message',
    'confirm-dialog', 'confirm-title', 'confirm-description', 'confirm-cancel', 'confirm-submit']) elements.set(id, new Element(id));
  const document = {hidden: false, activeElement: null, documentElement: {dataset: {}},
    querySelector: s => elements.get(s.slice(1)) || null, querySelectorAll: () => [],
    getElementById: id => elements.get(id) || null, addEventListener: (name, fn) => { listeners[name] = fn; },
    createElement: tag => new Element('', tag)};
  context = {document, navigator: {language: 'en'}, localStorage: {getItem: () => null, setItem() {}},
    matchMedia: () => ({matches: true, addEventListener() {}}), fetch: () => new Promise(() => {}),
    URL: {createObjectURL: () => 'blob:private-test', revokeObjectURL: url => revoked.push(url)},
    URLSearchParams, Blob, Date, setTimeout, clearTimeout, scrollX: 0, scrollY: 240,
    scrollTo: (x, y) => { context.scrollX = x; context.scrollY = y; },
    setInterval: (fn, ms) => { intervals.push({fn, ms}); return intervals.length; },
    SBOXUsage: {size: n => String(n ?? '—'), quotaSize: n => String(n ?? '—'), render: d => `<p>Measured history ${d.totals.upload_bytes}</p>`,
      picker: id => `<form id="${id}"><input id="history-draft" value="2026-10-28"></form>`,
      params: form => form.params || {window: '30d'}, download() {}}};
  vm.createContext(context); vm.runInContext(source, context);
  context.fixtureMe = me(); context.fixturePage = page;
  vm.runInContext("generation++;csrf='existing-csrf';current=fixtureMe;page=fixturePage;usage=null;render()", context);
  context.fetch = async (url, options) => { const route = url.split('/portal/')[1]; calls.push({route, options}); return reply(route === 'me' ? me() : history()); };
  return {context, elements, listeners, intervals, revoked, calls,
    run: code => vm.runInContext(code, context),
    route(fn) { context.fetch = async (url, options) => { const route = url.split('/portal/')[1]; calls.push({route, options}); return fn(route, options); }; },
    event(id) { return {target: elements.get(id), preventDefault() {}}; }};
}

const tests = {
  async 'navigation refreshes paused account, expiry and remaining quota'() {
    const e = environment();
    e.route(route => reply(route === 'me' ? me({status: 'manually_disabled', remaining_bytes: 123, expires_at: 123456}) : history()));
    await e.run("openPage('plan')");
    assert.equal(e.run('current.status'), 'manually_disabled');
    assert.equal(e.run('current.remaining_bytes'), 123);
    assert.equal(e.run('current.expires_at'), 123456);
    assert.match(e.elements.get('portal-heading')?.innerHTML || e.elements.get('content').innerHTML, /Paused/);
  },
  async 'history 401 clears all private state, QR and authenticated controls'() {
    const e = environment(); e.run("connection={exports:{}};qrUrl='blob:private-old'");
    e.route(route => route === 'me' ? reply(me()) : reply({error: 'Session expired'}, 401));
    await e.run("openPage('usage')");
    for (const name of ['current', 'usage', 'connection', 'qrUrl']) assert.equal(e.run(name), null, name);
    assert.equal(e.run('csrf'), ''); assert.equal(e.elements.get('portal-nav').hidden, true);
    assert.ok(e.revoked.includes('blob:private-old'));
    assert.doesNotMatch(e.elements.get('content').innerHTML, /Private test user|id="logout"/);
  },
  async 'late history cannot restore data after a separate 401'() {
    const e = environment(), delayed = deferred();
    e.route(route => route === 'me' ? reply(me()) : route.startsWith('me/history') ? delayed.promise : reply({error: 'Expired'}, 401));
    const pending = e.run("openPage('usage')");
    await new Promise(r => setImmediate(r));
    await e.run("api('me/connection',{}).catch(()=>{})");
    delayed.resolve(reply(history())); await pending;
    assert.equal(e.run('current'), null); assert.equal(e.run('usage'), null);
    assert.doesNotMatch(e.elements.get('content').innerHTML, /Measured history/);
  },
  async 'late me response cannot restore a signed-out session'() {
    const e = environment(), delayed = deferred();
    e.route(route => route === 'me' ? delayed.promise : reply({}));
    const pending = e.run('refreshCurrent()'); await Promise.resolve();
    await e.elements.get('logout').onclick(e.event('logout'));
    delayed.resolve(reply(me())); await pending;
    assert.equal(e.run('current'), null); assert.equal(e.run('usage'), null);
  },
  async 'refresh preserves unsent account fields, focused node and scroll'() {
    const e = environment('account');
    const input = e.elements.get('new'); input.value = 'unsent-password-value'; input.focus();
    await e.run('refreshCurrent()');
    assert.equal(e.elements.get('new'), input); assert.equal(input.value, 'unsent-password-value');
    assert.equal(e.context.document.activeElement, input); assert.equal(e.context.scrollY, 240);
    assert.equal(e.run('connection'), null);
  },
  async 'refresh keeps the mounted Export Center (selection and QR) instead of remounting'() {
    const e = environment('connection'); let mounts = 0;
    e.context.SBOXExportCenter = {mount: () => { mounts++; return {destroy() {}}; }};
    e.run("connection={recoverable:true,active:true,state:'ready',catalog:{schema:1,clients:[],profiles:[],endpoints:[],methods:[],text:{},files:{},urls:null}};render();qrUrl='blob:current'");
    assert.equal(mounts, 1, 'mounted once with the revealed connection');
    await e.run('refreshCurrent()');
    assert.equal(mounts, 1, 'background refresh patches data and does not reset the user selection');
    assert.equal(e.run('qrUrl'), 'blob:current');
  },
  async 'visible 30s timer refreshes me and history, hidden pauses and return refreshes'() {
    const e = environment(); const timer = e.intervals.find(row => row.ms === 30000);
    assert.ok(timer, 'safe periodic refresh must be installed');
    assert.ok(e.elements.get('refresh'), 'manual refresh must be visible');
    await timer.fn(); assert.ok(e.calls.some(row => row.route === 'me'));
    assert.ok(e.calls.some(row => row.route.startsWith('me/history')));
    const count = e.calls.length; e.context.document.hidden = true; await timer.fn();
    assert.equal(e.calls.length, count, 'hidden page must not poll');
    e.context.document.hidden = false; await e.listeners.visibilitychange();
    assert.ok(e.calls.length > count, 'returning to page immediately checks current status');
  },
  async 'transient failure retains values with stale state and offers working retry'() {
    const e = environment(); e.route(() => reply({error: 'Temporary service failure'}, 503));
    await e.run('refreshCurrent()'); assert.equal(e.run('current.status'), 'active');
    assert.equal(e.run('refreshState'), 'stale');
    assert.match(e.elements.get('portal-refresh-state').innerHTML, /retry|Retry/);
    e.route(route => reply(route === 'me' ? me({status: 'expired', remaining_bytes: 0}) : history()));
    await e.elements.get('retry-refresh').onclick(e.event('retry-refresh'));
    assert.equal(e.run('refreshState'), 'fresh'); assert.equal(e.run('current.status'), 'expired');
    assert.doesNotMatch(e.elements.get('portal-refresh-state').innerHTML, /Online|Connected/);
  },
  async 'CSRF and same-origin action request semantics remain intact'() {
    const e = environment('account'); await e.run("api('me/connection',{format:'yaml'})");
    const request = e.calls.at(-1).options;
    assert.equal(request.method, 'POST'); assert.equal(request.credentials, 'same-origin');
    assert.equal(request.cache, 'no-store'); assert.equal(request.headers['X-CSRF-Token'], 'existing-csrf');
    assert.equal(JSON.parse(request.body).format, 'yaml');
  },
  async 'an old 401 cannot clear a newer successful login or its CSRF'() {
    const e = environment(), old = deferred();
    e.route(route => route === 'old-private-request' ? old.promise : reply(route === 'login' ? {csrf: 'new-session-csrf'} : route === 'me' ? me() : history()));
    const pending = e.run("api('old-private-request').catch(()=>{})");
    e.run('login()');
    await e.elements.get('login').onsubmit(e.event('login'));
    await new Promise(r => setImmediate(r));
    old.resolve(reply({error: 'Obsolete session expired'}, 401)); await pending;
    assert.equal(e.run('csrf'), 'new-session-csrf');
    assert.equal(e.run('current.display_name'), 'Private test user');
    assert.doesNotMatch(e.elements.get('message').textContent, /Obsolete/);
  },
  async 'duplicate login submits cannot race session cookies or CSRF'() {
    const e = environment(), first = deferred(); let logins = 0;
    e.route(route => route === 'login' ? (logins++, first.promise) : reply(route === 'me' ? me() : history()));
    e.run('login()'); const form = e.elements.get('login');
    const one = form.onsubmit(e.event('login')), two = form.onsubmit(e.event('login'));
    assert.equal(logins, 1, 'only one login may issue a session cookie at a time');
    first.resolve(reply({csrf: 'accepted-csrf'})); await one; await two;
    await new Promise(r => setImmediate(r));
    assert.equal(e.run('csrf'), 'accepted-csrf');
    assert.equal(e.run('current.status'), 'active');
  },
  async 'pending custom history is not superseded by a background refresh'() {
    const e = environment('usage'), account = deferred(), selected = deferred();
    e.context.initialHistory = history(); e.run('usage=initialHistory;render()');
    const form = e.elements.get('history-picker');
    form.params = {window: 'custom', start: '2026-10-26', end: '2026-10-27'};
    e.route(route => route === 'me' ? account.promise : route.includes('window=custom') ? selected.promise : reply(history()));
    const background = e.run('refreshCurrent()');
    const manual = form.onsubmit(e.event('history-picker'));
    account.resolve(reply(me())); await background;
    selected.resolve(reply({...history(), window: 'custom'})); await manual;
    await new Promise(r => setImmediate(r));
    assert.equal(e.run('usage.window'), 'custom');
    assert.equal(e.run('usage.selected_start'), '2026-10-26');
    assert.equal(e.run('historyParams.end'), '2026-10-27');
    assert.ok(!e.calls.some(row => row.route.includes('window=30d')), 'background must not discard an in-flight chosen range');
    assert.equal(e.elements.get('history-picker'), form, 'the picker draft must keep its DOM node');
  },
  async 'late background history cannot replace a newer chosen range'() {
    const e = environment('usage'), oldHistory = deferred();
    e.context.initialHistory = history(); e.run('usage=initialHistory;render()');
    e.route(route => route === 'me' ? reply(me()) : route.includes('window=30d') ? oldHistory.promise : reply({...history(), window: 'custom'}));
    const background = e.run('refreshCurrent()'); await new Promise(r => setImmediate(r));
    const form = e.elements.get('history-picker');
    form.params = {window: 'custom', start: '2026-10-26', end: '2026-10-27'};
    await form.onsubmit(e.event('history-picker')); await new Promise(r => setImmediate(r));
    oldHistory.resolve(reply(history())); await background;
    assert.equal(e.run('usage.window'), 'custom');
    assert.equal(e.run('usage.selected_end'), '2026-10-27');
  },
};
(async () => { let failed = 0; for (const [name, test] of Object.entries(tests)) { try { await test(); console.log('PASS', name); } catch (error) { failed++; console.error('FAIL', name, '\n', error.stack); } } console.log(`${Object.keys(tests).length - failed}/${Object.keys(tests).length} lifecycle regressions passed; deterministic fixtures, NOT live acceptance.`); process.exitCode = failed ? 1 : 0; })();
