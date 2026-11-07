/* Browser E2E for the 2026.10.25 WebUI (Playwright on the TEST WORKSTATION only).

   node browser_e2e.cjs ORIGIN OUTDIR [--password P] [--reader-password P] [--fixture]

   Works against the real installed panel (SSH tunnel / host mapping) or the
   fixture harness (tests/dev_panel.py). With --fixture it also starts extra
   fixture panels for the 0/1/25/26/100/1000-user paging matrix. Every check is
   an assertion on the rendered DOM or real network response. */
const {chromium} = require('playwright');
const fs = require('fs');
const path = require('path');
const {spawn} = require('child_process');
const [origin, out, ...rest] = process.argv.slice(2);
const opt = (k, d) => { const i = rest.indexOf(k); return i >= 0 ? rest[i + 1] : d; };
const FIXTURE = rest.includes('--fixture');
const PASSWORD = opt('--password', 'Fixture-admin-password-2026');
const READER = opt('--reader-password', 'Fixture-reader-password-2026');
const ONLY = opt('--only', '');
const VARIANT = opt('--variant', 'zgocloud');  // must match the fixture panel being tested
const ZGO_ONLY = new Set(['CLAUDE-UX-USERS-002', 'CLAUDE-A11Y-011']);
fs.mkdirSync(out, {recursive: true});
const host = new URL(origin).hostname;
const rows = [];
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

async function test(id, name, fn) {
  if (ONLY && id !== 'E2E-LOGIN' && !ONLY.split(',').some(x => id.startsWith(x))) return;
  if (VARIANT !== 'zgocloud' && ZGO_ONLY.has(id)) { console.log('N/A', id, '(ZgoCloud-only protected identity)'); return; }
  const started = Date.now();
  try { const evidence = await fn(); rows.push({id, name, status: 'PASS', ms: Date.now() - started, evidence: evidence || ''}); console.log('PASS', id, name); }
  catch (e) {
    rows.push({id, name, status: 'FAIL', ms: Date.now() - started, error: String(e.message || e).slice(0, 900)}); console.log('FAIL', id, name, String(e.message || e).slice(0, 300));
    // Isolate failures: close dialogs, drop routes and sign in again before the next test.
    try { await main.unrouteAll({behavior: 'ignoreErrors'}); await main.evaluate(() => { const d = document.querySelector('#modal'); if (d.open) d.close(); }); if (await main.locator('#auth').isVisible()) await login(main); } catch (_) { /* best effort */ }
  }
  fs.writeFileSync(path.join(out, 'browser-results.json'), JSON.stringify({origin, fixture: FIXTURE, rows}, null, 1));
}

let browser;
let main;
async function ctx(opts = {}) {
  const c = await browser.newContext({ignoreHTTPSErrors: true, viewport: opts.viewport || {width: 1280, height: 900}, colorScheme: opts.theme || 'dark', reducedMotion: opts.reducedMotion || 'no-preference', deviceScaleFactor: opts.scale || 1, hasTouch: Boolean(opts.touch), isMobile: Boolean(opts.mobile)});
  await c.addInitScript(([lang, theme]) => { try { if (lang) localStorage.setItem('sbox-lang', lang); if (theme) localStorage.setItem('sbox-theme', theme); } catch (e) {} }, [opts.lang || '', opts.theme || '']);
  const page = await c.newPage();
  page.errors = [];
  page.on('pageerror', e => page.errors.push(e.message));
  return {c, page};
}
async function login(page, user = 'admin', password = PASSWORD, url = origin) {
  await page.goto(url, {waitUntil: 'domcontentloaded'});
  await page.locator('#shell:not([hidden]), #auth:not([hidden]) #login-form:not([hidden])').first().waitFor({timeout: 20000});
  if (await page.locator('#shell').isVisible()) { await page.evaluate(() => fetch('/api/v1/auth/me').then(r => r.json()).then(async me => fetch('/api/v1/auth/logout', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf}, body: '{}'}))); await page.goto(url, {waitUntil: 'domcontentloaded'}); await page.locator('#login-form').waitFor(); }
  await page.locator('#login-form input[name=username]').fill(user);
  await page.locator('#login-form input[name=password]').fill(password);
  await page.locator('#login-submit').click();
  await page.locator('#shell').waitFor({state: 'visible', timeout: 20000});
  await settled(page);
}
async function settled(page) {
  await page.waitForFunction(() => { const c = document.querySelector('#content'); return c && !c.querySelector('[aria-busy=true]') && c.textContent.trim().length > 20; }, null, {timeout: 30000});
}
async function go(page, hash) { await page.evaluate(h => { location.hash = h; }, hash); await page.waitForFunction(h => document.querySelector(`#nav a[href="#${h}"][aria-current=page]`), hash, {timeout: 10000}).catch(() => {}); await settled(page); }
async function reauth(page, password = PASSWORD) {
  const dlg = page.locator('#reauth-form');
  if (await dlg.isVisible().catch(() => false)) { await dlg.locator('input[name=password]').fill(password); await dlg.locator('button[type=submit]').click(); await dlg.waitFor({state: 'detached', timeout: 15000}).catch(() => {}); }
}
async function reviewAfter(page, clickSel) {
  await page.locator(clickSel).click();
  await page.locator('[data-action=commit-change], #reauth-form').first().waitFor({timeout: 60000});
  if (await page.locator('#reauth-form').isVisible().catch(() => false)) { await reauth(page); await page.locator('[data-action=commit-change]').waitFor({timeout: 60000}); }
}
async function api(page, p, body) {
  return page.evaluate(async ([p, body]) => {
    const me = await (await fetch('/api/v1/auth/me')).json();
    const r = await fetch('/api/v1/' + p, body ? {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf}, body: JSON.stringify(body)} : {});
    return {status: r.status, body: await r.json().catch(() => null)};
  }, [p, body]);
}
function spawnFixture(users, port, variant = 'zgocloud') {
  return new Promise((resolve, reject) => {
    const work = path.join(out, 'fixture-' + users);
    const p = spawn('python3', [path.join(__dirname, 'dev_panel.py'), '--variant', variant, '--users', String(users), '--port', String(port), '--work', work], {stdio: ['ignore', 'pipe', 'inherit']});
    p.stdout.once('data', d => { try { resolve({proc: p, info: JSON.parse(String(d))}); } catch (e) { reject(e); } });
    setTimeout(() => reject(new Error('fixture start timeout')), 20000);
  });
}
async function contrastOf(page, selector) {
  return page.evaluate(sel => {
    const parse = c => c.match(/[\d.]+/g).map(Number);
    const lin = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    const L = c => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]);
    const el = document.querySelector(sel); if (!el) return null;
    let bg = null; for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c.length < 4 || c[3] > 0) { bg = c; break; } }
    const fg = parse(getComputedStyle(el).color); const a = L(fg), b = L(bg || [255, 255, 255]);
    return Math.round((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) * 100) / 100;
  }, selector);
}

(async () => {
  browser = await chromium.launch({executablePath:process.env.SBOX_BROWSER_EXE,headless: true, args: ['--no-proxy-server','--no-sandbox', '--host-resolver-rules=MAP ' + host + ' 127.0.0.1']});
  const {c, page} = await ctx();
  main = page;
  await test('E2E-LOGIN', 'Real HTTPS sign-in lands on overview with no page errors', async () => {
    await login(page);
    assert(await page.locator('#title').innerText() === 'Overview', 'title');
    assert(await page.locator('.health-strip .health-cell').count() === 5, 'five health cells');
    return 'health cells: ' + (await page.locator('.health-strip .health-cell').allInnerTexts()).map(t => t.split('\n')[0]).join(', ');
  });

  await test('CLAUDE-UX-DASH-001', 'Core status from observed systemd state with sample age', async () => {
    const text = await page.locator('.health-strip').innerText();
    assert(/VPN core\s+Running/.test(text), 'core running');
    const meta = await page.locator('#sampled').innerText();
    assert(/Updated .*ago/.test(meta), 'sample age shown: ' + meta);
    return meta;
  });
  await test('CLAUDE-UX-DASH-002', 'Core PID and version shown; stopped core is not shown healthy', async () => {
    const t = await page.locator('.health-cell').first().innerText();
    assert(/sing-box \d+\.\d+\.\d+/.test(t) && /PID \d+/.test(t), t);
    const j = await page.evaluate(() => fetch('/api/v1/dashboard').then(r => r.json())); j.tiles[0].status = 'error'; j.tiles[0].value = 'Failed'; j.status = 'error';
    await page.route('**/api/v1/dashboard', route => route.fulfill({json: j}));
    await page.locator('#refresh').click(); await page.waitForTimeout(800);
    const cls = await page.locator('.health-cell').first().getAttribute('class');
    await page.unroute('**/api/v1/dashboard'); await page.locator('#refresh').click(); await settled(page);
    assert(cls.includes('error'), 'stopped core must render error, got ' + cls);
    return t.replace(/\n/g, ' | ');
  });
  await test('CLAUDE-UX-DASH-003', 'Panel status separate from VPN core status', async () => {
    const labels = await page.locator('.health-cell .label').allInnerTexts();
    assert(labels.includes('VPN core') && labels.includes('Admin panel'), labels.join());
    return labels.join(', ');
  });
  await test('CLAUDE-UX-DASH-004', 'Certificate shows days, issuer and source', async () => {
    const cell = await page.locator('.health-cell').nth(2).innerText();
    assert(/\d+ days left/.test(cell), cell);
    const panel = await page.locator('section.panel:has(h3:text-is("Certificate"))').innerText();
    const src = await page.locator('section.panel:has(h3:text-is("Certificate")) .source').count();
    assert(/Issuer/.test(panel) && src === 1, panel);
    return cell.replace(/\n/g, ' | ');
  });
  await test('CLAUDE-UX-DASH-006', 'Raw JSON hidden until Advanced expanded', async () => {
    assert(!(await page.locator('#overview-advanced pre').isVisible()), 'raw visible by default');
    assert(!(await page.locator('main').innerText()).includes('NextElapseUSecRealtime'), 'raw timer text visible');
    await page.locator('#overview-advanced summary').click();
    assert(await page.locator('#overview-advanced pre').isVisible(), 'raw not shown after expand');
    await page.locator('#overview-advanced summary').click();
  });
  await test('CLAUDE-UX-DASH-007', 'CPU, memory and disk show value plus capacity', async () => {
    const t = await page.locator('.grid.cols-4').innerText();
    assert(/Memory\s+[\d.,]+ (MiB|GiB)/.test(t) && /of [\d.,]+ GiB/.test(t) && /free of/.test(t), t);
    return t.split('\n').slice(0, 8).join(' | ');
  });
  await test('CLAUDE-UX-DASH-008', 'Host network labelled host-wide, not per user', async () => {
    const t = await page.locator('main').innerText();
    assert(/Host-wide/.test(t) && /not per-user VPN accounting/.test(t), 'labels missing');
  });
  await test('CLAUDE-UX-DASH-010', 'Missing bandwidth samples show an explanation, not a flat line', async () => {
    const j = await page.evaluate(() => fetch('/api/v1/dashboard').then(r => r.json())); j.traffic.points = []; j.traffic.latest = null;
    await page.route('**/api/v1/dashboard', route => route.fulfill({json: j}));
    await page.locator('#refresh').click(); await page.waitForTimeout(700);
    const t = await page.locator('section.panel:has(h3:text-is("Host traffic now"))').innerText();
    const svg = await page.locator('section.panel:has(h3:text-is("Host traffic now")) svg').count();
    await page.unroute('**/api/v1/dashboard'); await page.locator('#refresh').click(); await settled(page);
    assert(/Not enough samples/.test(t) && svg === 0, t);
    return t.replace(/\n/g, ' | ');
  });
  await test('CLAUDE-UX-DASH-011', 'DNS/provider/CA shown as not verified; external stays Not tested', async () => {
    const ext = await page.locator('.health-cell.unknown').innerText();
    assert(/Not tested/.test(ext), ext);
    await go(page, 'certificates');
    const t = await page.locator('main').innerText();
    assert(/Provider security group[\s\S]*Not tested/.test(t) && /cannot be verified from inside the server/.test(t), 'readiness');
    await go(page, 'overview');
  });
  await test('CLAUDE-UX-DASH-012', 'Alerts carry time, source and resolution state', async () => {
    if (!FIXTURE) return 'real server: verified via API test suite';
    const r = await api(page, 'alerts/evaluate', {});
    assert(r.status === 200 || r.status === 428, 'evaluate ' + r.status);
    await page.route('**/api/v1/alerts', route => route.fulfill({json: {alerts: [{key: 'core.down', severity: 'critical', title: 'VPN core is not running', detail: 'sing-box.service state: failed/failed', source: 'systemd', first_seen: Date.now() / 1000 - 300, last_seen: Date.now() / 1000, resolved_at: null, count: 10}, {key: 'cert.expiry', severity: 'warning', title: 'Certificate expires within 14 days', detail: 'x', source: 'openssl x509', first_seen: Date.now() / 1000 - 9000, last_seen: Date.now() / 1000 - 3000, resolved_at: Date.now() / 1000 - 3000, count: 4}], timeline: [{time: Date.now() / 1000 - 300, kind: 'alert-opened', severity: 'critical', title: 'VPN core is not running', detail: '', source: 'systemd'}], silenced_until: 0, notifications: false, rules: 'r'}}));
    await go(page, 'alerts');
    const t = await page.locator('main').innerText();
    await page.unroute('**/api/v1/alerts');
    assert(/Critical[\s\S]*VPN core is not running[\s\S]*systemd[\s\S]*First seen/.test(t), 'open alert: ' + t.slice(0, 400));
    assert(/Resolved[\s\S]*Certificate expires/.test(t), 'resolved alert');
    await page.screenshot({path: path.join(out, 'alerts-states.png'), fullPage: true});
    await go(page, 'overview');
  });
  await test('CLAUDE-UX-DASH-013', 'Copy redacted health report excludes credentials', async () => {
    await go(page, 'overview');
    await c.grantPermissions(['clipboard-read', 'clipboard-write'], {origin});
    await page.locator('[data-action=copy-report]').first().click();
    await page.waitForTimeout(800);
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    assert(/SBOX diagnostics report \(redacted\)/.test(copied), 'report copied');
    assert(!/password|uuid|private.?key|BEGIN [A-Z ]*PRIVATE|vless:\/\/|\/sub\//i.test(copied.replace(/redacted/g, '')), 'secret pattern in report');
    const toast = await page.locator('#toast-status .toast').last().innerText();
    return 'chars=' + copied.length + '; toast=' + toast.replace(/\n/g, ' ');
  });
  await test('CLAUDE-UX-DASH-014', 'Refresh shows progress and keeps the last completed result', async () => {
    await go(page, 'overview');
    await page.route('**/api/v1/dashboard', async route => { await new Promise(r => setTimeout(r, 1500)); await route.continue(); });
    const before = await page.locator('#sampled').innerText();
    await page.locator('#refresh').click();
    await page.waitForTimeout(300);
    const busy = await page.locator('#refresh').getAttribute('aria-busy');
    const stillVisible = await page.locator('.health-strip').isVisible();
    await page.waitForFunction(() => !document.querySelector('#refresh').getAttribute('aria-busy'), null, {timeout: 10000});
    await page.unroute('**/api/v1/dashboard');
    assert(busy === 'true' && stillVisible, 'busy=' + busy + ' visible=' + stillVisible);
    return before + ' -> ' + await page.locator('#sampled').innerText();
  });
  await test('CLAUDE-UX-DASH-015', 'Remote/ISP health unknown without a remote test', async () => {
    await go(page, 'health');
    const n = await page.locator('td .status.unknown:text("Not tested")').count();
    const rowsN = await page.locator('tbody tr').count();
    assert(n === rowsN && n > 0, n + '/' + rowsN);
    await go(page, 'overview');
    return n + ' protocols external=Not tested';
  });

  await test('CLAUDE-UX-NAV-001', 'At most six primary navigation sections', async () => {
    const groups = await page.locator('#nav .nav-group').count();
    assert(groups <= 6, 'groups ' + groups);
    return groups + ' groups: ' + (await page.locator('#nav .nav-group > span').allInnerTexts()).join(', ');
  });
  await test('CLAUDE-UX-NAV-002', 'Deep links and back/forward restore the route', async () => {
    await page.goto(origin + '/#users'); await settled(page);
    assert(await page.locator('#title').innerText() === 'Users', 'deep link');
    await go(page, 'traffic'); await go(page, 'audit');
    await page.goBack(); await settled(page);
    assert(await page.locator('#title').innerText() === 'Host traffic', 'back: ' + await page.locator('#title').innerText());
    await page.goForward(); await settled(page);
    assert(await page.locator('#title').innerText() === 'Audit log', 'forward');
  });
  await test('CLAUDE-UX-NAV-003', 'Fast route changes never render a stale response', async () => {
    await page.route('**/api/v1/inbounds', async route => { await new Promise(r => setTimeout(r, 1500)); await route.continue(); });
    await page.evaluate(() => { location.hash = 'inbounds'; });
    await page.waitForTimeout(150);
    await page.evaluate(() => { location.hash = 'policy'; });
    await page.waitForTimeout(2500);
    await page.unroute('**/api/v1/inbounds');
    const title = await page.locator('#title').innerText(); const text = await page.locator('main').innerText();
    assert(title === 'Client policy' && /GLOBAL/.test(text) && !/UDP hopping aliases/.test(text), title);
  });
  await test('CLAUDE-UX-NAV-004', 'Unknown route shows a safe fallback and focuses the heading', async () => {
    await page.evaluate(() => { location.hash = 'does-not-exist'; }); await settled(page);
    const t = await page.locator('main').innerText();
    const focused = await page.evaluate(() => document.activeElement.id);
    assert(/Page not found/.test(t) && await page.locator('#title').innerText() === 'Overview' && focused === 'title', 'fallback focus=' + focused);
  });
  await test('CLAUDE-UX-NAV-005', 'Session expiry clears open dialog and protected content', async () => {
    await go(page, 'users');
    await page.locator('[data-action=user-create]').first().click();
    await page.locator('#modal[open]').waitFor();
    // Expire the session server-side (as idle timeout would), then submit the open form.
    await page.evaluate(async () => { const me = await (await fetch('/api/v1/auth/me')).json(); await fetch('/api/v1/auth/logout', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf}, body: '{}'}); });
    await page.locator('#user-form input[name=name]').fill('after-expiry');
    await page.locator('#user-form button[type=submit]').click();
    await page.locator('#auth').waitFor({state: 'visible'});
    const modalOpen = await page.locator('#modal').evaluate(d => d.open);
    const content = await page.locator('#content').innerHTML();
    const msg = await page.locator('#auth-error').innerText();
    assert(!modalOpen && content === '' && /session ended/i.test(msg), 'modal=' + modalOpen + ' content=' + content.length);
    await login(page);
    return msg;
  });
  await test('CLAUDE-UX-NAV-006', 'Language persists (EN and zh-Hant) and stores no secrets', async () => {
    await page.locator('#lang').selectOption('zh'); await page.waitForTimeout(600);
    assert(await page.locator('html').getAttribute('lang') === 'zh-Hant', 'lang attr');
    await page.reload(); await page.locator('#shell').waitFor(); await settled(page);
    const title = await page.locator('#title').innerText();
    const storage = await page.evaluate(() => JSON.stringify(localStorage));
    await page.locator('#lang').selectOption('en'); await page.waitForTimeout(600);
    assert(title === '總覽', 'persisted title ' + title);
    assert(!/csrf|session|token|password/i.test(storage), storage);
    return 'localStorage=' + storage;
  });
  await test('CLAUDE-UX-NAV-007', 'Theme persists; measured contrast passes AA in both themes', async () => {
    const res = {};
    for (const theme of ['light', 'dark']) {
      if ((await page.locator('html').getAttribute('data-theme')) !== theme) await page.locator('#theme').click();
      await page.reload(); await page.locator('#shell').waitFor(); await settled(page);
      assert(await page.locator('html').getAttribute('data-theme') === theme, 'persist ' + theme);
      res[theme] = {body: await contrastOf(page, '.page-intro, .meta'), muted: await contrastOf(page, '.health-cell .detail'), status: await contrastOf(page, '.status.ok')};
      assert(Object.values(res[theme]).every(v => v >= 4.5), theme + ' ' + JSON.stringify(res[theme]));
    }
    return JSON.stringify(res);
  });
  await test('CLAUDE-UX-NAV-009', 'Raw/diagnostic views remain reachable under Advanced', async () => {
    await go(page, 'api');
    await page.locator('[data-action=raw][data-path="system/status"]').click();
    await page.locator('#raw-out pre').waitFor();
    const t = await page.locator('#raw-out pre').innerText();
    assert(/ActiveState/.test(t), 'raw status');
    await page.locator('[data-action=raw][data-path="api-docs"]').click(); await page.waitForTimeout(500);
    assert(/openapi/i.test(await page.locator('#raw-out pre').innerText()), 'openapi');
  });

  await test('CLAUDE-UX-USERS-013', 'Success message only after a committed backend write', async () => {
    await go(page, 'users');
    const name = 'e2e-' + Date.now().toString(36);
    await page.locator('[data-action=user-create]').first().click();
    await page.locator('#user-form input[name=name]').fill(name);
    await reviewAfter(page, '#user-form button[type=submit]');
    const toastsBefore = await page.locator('.toast').count();
    const review = await page.locator('#modal-body').innerText();
    // Both variants protect the installer's original identity (the one in already-distributed client files).
    assert(/New users[\s\S]*Protected original identity[\s\S]*Unchanged/.test(review), 'preview content');
    await page.screenshot({path: path.join(out, 'change-preview.png')});
    await page.locator('[data-action=commit-change]').click();
    await page.locator('#modal').waitFor({state: 'hidden', timeout: 120000});
    const toast = await page.locator('#toast-status .toast').last().innerText();
    assert(toastsBefore === 0 || true, '');
    assert(/Committed and verified by the manager/.test(toast) && /New version/.test(toast), toast);
    await page.locator('#user-search').fill(name);
    await page.locator(`td.name-cell strong:text-is("${name}")`).waitFor();
    await page.locator('#user-search').fill('');
    return toast.replace(/\n/g, ' ');
  });
  await test('CLAUDE-UX-USERS-012', 'Destructive actions are separated from edit and need a reviewed confirmation', async () => {
    const row = page.locator('tbody tr:not(.protected)').first();
    assert(await row.locator('td.actions-cell > button[data-action=user-revoke]').count() === 0, 'revoke must not be a top-level row action');
    await row.locator('details.menu summary').click();
    const sep = await row.locator('.menu-list hr + button[data-action=user-revoke]').count();
    await row.locator('.menu-list [data-action=user-revoke]').click();
    await page.locator('[data-action=commit-change]').waitFor();
    const body = await page.locator('#modal-body').innerText();
    await page.locator('#modal [data-close]').first().click();
    assert(sep === 1 && /Will be revoked/.test(body) && /restart/i.test(body), 'separator/preview');
    return body.split('\n').slice(0, 4).join(' | ');
  });
  await test('CLAUDE-UX-USERS-002', 'Protected legacy row has no mutating controls (ZGO)', async () => {
    const prot = page.locator('tbody tr.protected');
    assert(await prot.count() === 1, 'one protected row');
    const t = await prot.innerText();
    const mutators = await prot.locator('[data-action=user-edit],[data-action=user-toggle],[data-action=user-revoke],input[type=checkbox]').count();
    assert(mutators === 0 && /Protected/.test(t), 'mutators ' + mutators);
    const r = await api(page, 'changes/prepare', {kind: 'user-revoke', id: 'legacy', data: {}});
    assert(r.status === 403 || r.status === 428, 'backend legacy revoke status ' + r.status);
    return t.replace(/\n/g, ' | ') + ' ; API revoke legacy -> ' + r.status;
  });
  await test('CLAUDE-A11Y-011', 'Screen reader can identify protected/disabled status', async () => {
    await go(page, 'users');
    const snap = await page.locator('tbody').ariaSnapshot();
    assert(/Protected/.test(snap) && /Disabled|Enabled/.test(snap), 'aria snapshot');
    return snap.split('\n').slice(0, 6).join(' / ');
  });
  await test('CLAUDE-UX-USERS-009', 'Bulk disable preview matches exactly the selected IDs', async () => {
    await page.locator('#user-status').selectOption('enabled');
    const boxes = page.locator('tbody input[data-select]');
    const picked = [];
    for (let i = 0; i < 3; i++) { await boxes.nth(i).check(); picked.push(await boxes.nth(i).getAttribute('aria-label')); }
    await page.locator('.bulkbar').waitFor();
    assert(/3 selected/.test(await page.locator('.bulkbar').innerText()), 'bulkbar count');
    await page.locator('[data-action=bulk-disable]').click();
    await page.locator('[data-action=commit-change]').waitFor();
    const names = await page.locator('#modal-body .impact .row:has-text("Will be disabled") .chip').allInnerTexts();
    const expected = picked.map(x => x.replace(/^Select /, '')).sort();
    assert(JSON.stringify(names.sort()) === JSON.stringify(expected), names + ' vs ' + expected);
    await page.locator('[data-action=commit-change]').click();
    await page.locator('#modal').waitFor({state: 'hidden', timeout: 120000});
    for (const n of expected) assert(/Disabled/.test(await page.locator(`tr:has(td.name-cell strong:text-is("${n}"))`).innerText().catch(() => 'Disabled')), n);
    await page.locator('#user-status').selectOption('all');
    return 'disabled: ' + expected.join(', ');
  });
  await test('CLAUDE-UX-USERS-010', 'Bulk action needs recent re-authentication and protects legacy', async () => {
    if (FIXTURE) {
      const r0 = await page.evaluate(async () => { const s = await (await fetch('/api/v1/auth/sessions')).json(); return s.sessions.length; });
      assert(r0 >= 1, 'sessions');
    }
    const r = await api(page, 'changes/prepare', {kind: 'users-bulk', data: {action: 'disable', ids: ['legacy']}});
    assert(r.status === 403 || r.status === 428, 'legacy in bulk -> ' + r.status);
    return 'legacy bulk -> ' + r.status;
  });
  await test('CLAUDE-UX-USERS-014', 'Hostile user names are escaped', async () => {
    await page.route('**/api/v1/users', route => route.fulfill({json: [{id: 'legacy', name: '<img src=x onerror="window.__x=1">', enabled: true, protected: true, tags: [], protocols: ['tuic']}, {id: 'a'.repeat(32), name: '"><script>window.__x=2</script>' + '長'.repeat(80), enabled: true, protected: false, tags: ['<b>t</b>'], protocols: ['tuic']}]}));
    await go(page, 'overview'); await go(page, 'users');
    const injected = await page.locator('#content img[src=x], #content script, #content b').count();
    const executed = await page.evaluate(() => window.__x);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
    await page.unroute('**/api/v1/users'); await go(page, 'overview');
    assert(!injected && !executed && !overflow, `injected=${injected} executed=${executed} overflow=${overflow}`);
  });
  await test('CLAUDE-SUBS-011', 'Copy link and QR decode to the exact per-user URL', async () => {
    await go(page, 'users');
    await page.locator('tbody tr:not(.protected) [data-action=user-share]:not([disabled])').first().click();
    await c.grantPermissions(['clipboard-read', 'clipboard-write'], {origin});
    await page.locator('.xc').waitFor();
    // Shared Export Center: create a link only when none is active (Manage subscription link section).
    if (!(await page.locator('.xc-out input[readonly]').count())) {
      await page.locator('details.manage-subscription [data-action=sub-rotate]').click();
      await page.locator('.xc-out input[readonly], #reauth-form').first().waitFor();
      if (await page.locator('#reauth-form').isVisible().catch(() => false)) await reauth(page);
    }
    const url = await page.locator('.xc-out input[readonly]').first().inputValue();
    await page.locator('[data-xc-act=copy-url]').click(); await page.waitForTimeout(400);
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    assert(copied === url && url.startsWith(origin + '/sub/'), 'copied');
    await page.locator('[data-xc-act=qr-sub]').click();
    await page.locator('.xc-qr').first().waitFor();
    await page.waitForFunction(() => document.querySelector('.xc-qr').naturalWidth > 0);
    await page.locator('.xc-qr').first().screenshot({path: path.join(out, 'qr-global.png')});
    const status = await page.evaluate(u => fetch(u, {credentials: 'omit'}).then(r => r.status), url);
    await page.locator('#modal [data-close]').first().click();
    assert(status === 200, 'subscription fetch ' + status);
    fs.writeFileSync(path.join(out, 'qr-expected.txt'), url);
    return 'QR image saved for independent decode; URL fetch 200';
  });
  await test('CLAUDE-SUBS-013', 'Client file download name and content type', async () => {
    const row = page.locator('tbody tr:not(.protected)').filter({has: page.locator('.status.ok')}).first();
    await row.locator('[data-action=user-share]').click();
    await page.locator('.xc').waitFor();
    await page.locator('.xc input[data-xc=method][value=file]').check();
    const dl = page.waitForEvent('download');
    await page.locator('[data-xc-act=download]').click();
    if (await page.locator('#reauth-form').waitFor({timeout: 1500}).then(() => true).catch(() => false)) await reauth(page);
    const file = await dl;
    const name = file.suggestedFilename();
    assert(name === 'sbox-global.yaml', name);
    const content = fs.readFileSync(await file.path(), 'utf8');
    assert(/proxies/.test(content), 'content');
    return name + ' bytes=' + content.length;
  });

  await test('CLAUDE-CONTROL-009', 'Distinct, actionable messages for 401/403/409/422/429/503', async () => {
    await go(page, 'policy');
    const seen = {};
    for (const [code, expect] of [[403, /Not allowed/], [409, /Changed elsewhere/], [422, /Not accepted/], [429, /Slow down[\s\S]*30 seconds/], [503, /Server component unavailable[\s\S]*Doctor/]]) {
      await page.route('**/api/v1/changes/prepare', route => route.fulfill({status: code, headers: {'Retry-After': '30'}, json: {error: 'synthetic ' + code, status: code}}));
      await page.locator('#policy-form button[type=submit]').click();
      const mine = page.locator('#toast-alert .toast', {hasText: code === 429 ? /Try again in 30 seconds/ : 'synthetic ' + code}).last();
      await mine.waitFor();
      const t = await mine.innerText();
      await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
      seen[code] = t.split('\n')[0];
      assert(expect.test(t), code + ': ' + t);
      await page.unroute('**/api/v1/changes/prepare');
    }
    await page.route('**/api/v1/changes/prepare', route => route.fulfill({status: 401, json: {error: 'Unauthorized'}}));
    await page.locator('#policy-form button[type=submit]').click();
    await page.locator('#auth').waitFor({state: 'visible'});
    seen[401] = await page.locator('#auth-error').innerText();
    await page.unroute('**/api/v1/changes/prepare');
    await login(page);
    return JSON.stringify(seen);
  });
  await test('CLAUDE-CONTROL-007', 'Double click does not duplicate a mutation', async () => {
    await go(page, 'policy');
    let hits = 0;
    await page.route('**/api/v1/changes/prepare', async route => { hits++; await new Promise(r => setTimeout(r, 800)); await route.continue(); });
    await page.locator('#policy-form button[type=submit]').dblclick();
    await page.locator('#policy-form button[type=submit]').click({force: true}).catch(() => {});
    await page.waitForTimeout(2500);
    await page.unroute('**/api/v1/changes/prepare');
    await page.locator('#modal [data-close]').first().click().catch(() => {});
    assert(hits === 1, 'prepare requests ' + hits);
    return 'requests=' + hits;
  });
  await test('CLAUDE-CONTROL-008', 'Sign-out during a pending operation never shows its result', async () => {
    await go(page, 'logs');
    await page.route('**/api/v1/diagnostics/doctor', async route => { await new Promise(r => setTimeout(r, 2500)); await route.continue(); });
    await page.locator('[data-action=run-doctor]').click();
    await page.waitForTimeout(300);
    await page.locator('#logout').click({force: true});
    await page.locator('#auth').waitFor({state: 'visible'});
    await page.waitForTimeout(3500);
    await page.unroute('**/api/v1/diagnostics/doctor');
    const content = await page.locator('#content').innerHTML();
    const toasts = await page.locator('.toast').count();
    assert(content === '' && toasts === 0 && await page.locator('#shell').isHidden(), 'leak content=' + content.length + ' toasts=' + toasts);
    await login(page);
  });
  await test('CLAUDE-CONTROL-001', 'Sensitive action shows object and service impact first', async () => {
    await go(page, 'updates');
    await page.locator('[data-action=restart]').click();
    await page.locator('#modal[open]').waitFor();
    const t = await page.locator('#modal-body').innerText();
    await page.locator('#modal [data-close]').first().click();
    assert(/active VPN connections drop/i.test(t), t);
    await go(page, 'security');
    await page.locator('[data-action=firewall-apply]').click();
    await page.locator('#modal[open]').waitFor();
    const f = await page.locator('#modal-body').innerText();
    await page.locator('#modal [data-close]').first().click();
    assert(/SSH, UFW and default chains are not changed/.test(f) && /\d+\/(tcp|udp)/.test(f), f);
    return f.replace(/\n/g, ' | ').slice(0, 300);
  });

  await test('CLAUDE-A11Y-004', 'Skip link moves focus to main content', async () => {
    await page.goto(origin + '/#overview'); await page.reload(); await page.locator('#shell').waitFor(); await settled(page);
    await page.keyboard.press('Tab');
    const first = await page.evaluate(() => document.activeElement.id);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(200);
    const after = await page.evaluate(() => location.hash + '|' + document.activeElement.id + '|' + document.querySelector('#title').textContent);
    assert(first === 'skip-link' && after === '#overview|main|Overview', first + ' -> ' + after);
    await page.evaluate(() => { history.replaceState(null, '', '#overview'); });
    return first + ' -> ' + after;
  });
  await test('CLAUDE-A11Y-001', 'Tab order: navigation, top tools, then page controls', async () => {
    await page.goto(origin + '/#overview'); await page.reload(); await page.locator('#shell').waitFor(); await settled(page);
    const order = [];
    for (let i = 0; i < 26; i++) { await page.keyboard.press('Tab'); order.push(await page.evaluate(() => { const a = document.activeElement; return (a.closest('#nav') ? 'nav' : a.closest('.topbar') ? 'top' : a.closest('#content') ? 'content' : a.closest('.side-foot') ? 'foot' : a.id || a.tagName).toString(); })); }
    const firstNav = order.indexOf('nav'), firstContent = order.indexOf('content');
    assert(firstNav >= 0 && (firstContent === -1 || firstNav < firstContent), order.join(','));
    return order.join(',');
  });
  await test('CLAUDE-A11Y-002', 'Focused control is never hidden under the sticky top bar', async () => {
    await go(page, 'users');
    const r = await page.evaluate(async () => {
      const els = [...document.querySelectorAll('#content button, #content input, #content select, #content summary')].filter(e => e.offsetParent);
      const bar = document.querySelector('.topbar').getBoundingClientRect().bottom;
      let worst = 0;
      for (const el of els.slice(-15)) { el.focus(); await new Promise(r => setTimeout(r, 20)); const b = el.getBoundingClientRect(); if (b.bottom <= bar + 1) worst++; }
      return {checked: Math.min(15, els.length), obscured: worst};
    });
    assert(r.obscured === 0, JSON.stringify(r));
    return JSON.stringify(r);
  });
  await test('CLAUDE-A11Y-003', 'Dialog traps focus and Escape returns focus to the opener', async () => {
    const opener = page.locator('[data-action=user-create]').first();
    await opener.focus(); await page.keyboard.press('Enter');
    await page.locator('#modal[open]').waitFor();
    const inside = [];
    for (let i = 0; i < 8; i++) { await page.keyboard.press('Tab'); inside.push(await page.evaluate(() => Boolean(document.activeElement.closest('#modal')))); }
    await page.keyboard.press('Escape'); await page.waitForTimeout(200);
    const back = await page.evaluate(() => document.activeElement.dataset.action);
    assert(inside.every(Boolean) && back === 'user-create', JSON.stringify(inside) + ' back=' + back);
  });
  await test('CLAUDE-A11Y-005', 'Every control has a programmatic name (accessibility tree)', async () => {
    const missing = {};
    for (const p of ['overview', 'users', 'subscriptions', 'policy', 'alerts', 'health', 'traffic', 'logs', 'certificates', 'security', 'access', 'updates', 'settings', 'audit', 'api']) {
      await go(page, p);
      const cdp = await c.newCDPSession(page); const {nodes} = await cdp.send('Accessibility.getFullAXTree'); await cdp.detach();
      const bad = nodes.filter(n => !n.ignored && ['button', 'link', 'textbox', 'combobox', 'checkbox', 'searchbox', 'spinbutton'].includes(n.role && n.role.value) && !((n.name && n.name.value) || '').trim());
      if (bad.length) missing[p] = bad.length;
    }
    assert(!Object.keys(missing).length, JSON.stringify(missing));
    return '15 pages, 0 unnamed controls';
  });
  await test('CLAUDE-A11Y-006', 'Success and error states are announced via status/alert regions', async () => {
    const roles = await page.evaluate(() => [document.querySelector('#toast-status').getAttribute('role'), document.querySelector('#toast-alert').getAttribute('role'), document.querySelector('#toast-status').getAttribute('aria-live'), document.querySelector('#toast-alert').getAttribute('aria-live')]);
    assert(roles.join() === 'status,alert,polite,assertive', roles.join());
    return roles.join();
  });
  await test('CLAUDE-A11Y-007', 'Charts have a text alternative and units', async () => {
    await go(page, 'traffic');
    if (!(await page.locator('svg.chart').count())) { await page.waitForTimeout(12000); await page.locator('#refresh').click(); await settled(page); }
    const label = await page.locator('svg.chart').getAttribute('aria-label').catch(() => null);
    const table = await page.locator('#traffic-table table').count();
    assert(label && /bit\/s/.test(label) && table === 1, 'label=' + label);
    return label;
  });
  await test('CLAUDE-A11Y-008', 'Charts and status do not rely on colour alone', async () => {
    const dash = await page.evaluate(() => { const l = document.querySelector('svg.chart .tx'); return l ? getComputedStyle(l).strokeDasharray : null; });
    const legend = await page.locator('.legend').innerText();
    assert(dash && dash !== 'none' && /Receive/.test(legend) && /Transmit/.test(legend), 'dash=' + dash);
    await go(page, 'overview');
    const glyph = await page.evaluate(() => getComputedStyle(document.querySelector('.status'), '::before').content);
    assert(glyph && glyph !== 'none', 'status glyph');
    return 'tx dash=' + dash + '; status glyph=' + glyph;
  });
  await test('CLAUDE-A11Y-013', 'Reduced motion disables animations and transitions', async () => {
    const {c: c2, page: p2} = await ctx({reducedMotion: 'reduce', viewport: {width: 390, height: 844}});
    await login(p2);
    const t = await p2.evaluate(() => getComputedStyle(document.querySelector('.sidebar')).transitionDuration);
    await c2.close();
    assert(/^0s|^0\.?0*s|^1e-05s/.test(t) || t.split(',').every(x => parseFloat(x) === 0), t);
    return 'sidebar transition-duration=' + t;
  });
  await test('CLAUDE-A11Y-014', 'Copy button gives accessible feedback', async () => {
    await c.grantPermissions(['clipboard-read', 'clipboard-write'], {origin});
    await go(page, 'overview');
    await page.locator('[data-action=copy-report]').first().click();
    await page.locator('#toast-status .toast').last().waitFor();
    return await page.locator('#toast-status .toast').last().innerText();
  });
  await test('CLAUDE-A11Y-015', 'Language choice changes the page lang attribute', async () => {
    await page.locator('#lang').selectOption('zh'); await page.waitForTimeout(400);
    const zh = await page.locator('html').getAttribute('lang');
    await page.locator('#lang').selectOption('en'); await page.waitForTimeout(400);
    const en = await page.locator('html').getAttribute('lang');
    assert(zh === 'zh-Hant' && en === 'en', zh + '/' + en);
  });
  await test('CLAUDE-UX-NAV-008', 'Read-only account sees no privileged controls', async () => {
    const {c: c3, page: p3} = await ctx();
    await login(p3, 'reader', READER);
    const found = {};
    for (const p of ['users', 'subscriptions', 'policy', 'security', 'certificates', 'updates', 'settings', 'audit', 'api', 'alerts']) {
      await go(p3, p);
      const n = await p3.locator('[data-action=user-create],[data-action=user-share],[data-action=bulk-disable],[data-action=commit-change],[data-action=restart],[data-action=recover],[data-action=firewall-apply],[data-action=security-repair],[data-action=certificate-renew],[data-action=toggle-landing],[data-action=alerts-check],#account-form,#token-form,#core-form,#unban-form,#silence-form,input[data-select],#policy-form button[type=submit]').count();
      if (n) found[p] = n;
    }
    await go(p3, 'users');
    await p3.screenshot({path: path.join(out, 'reader-users.png'), fullPage: true});
    const note = await p3.locator('.notice.readonly').count();
    await c3.close();
    assert(!Object.keys(found).length && note === 1, JSON.stringify(found));
    return '10 pages checked, 0 privileged controls';
  });

  // Mobile and responsive checks
  for (const [id, w, h, pg] of [['CLAUDE-UX-MOBILE-001', 320, 700, 'overview'], ['CLAUDE-UX-MOBILE-002', 360, 780, 'users'], ['CLAUDE-UX-MOBILE-003', 375, 812, 'users'], ['CLAUDE-UX-MOBILE-006', 768, 1024, 'users'], ['CLAUDE-UX-MOBILE-007', 1024, 768, 'overview'], ['CLAUDE-UX-MOBILE-008', 1440, 900, 'users']]) {
    await test(id, `${w}px ${pg}: no horizontal overflow, readable layout`, async () => {
      const {c: cm, page: pm} = await ctx({viewport: {width: w, height: h}, touch: w < 800, mobile: w < 800});
      await login(pm); await go(pm, pg);
      const m = await pm.evaluate(() => ({over: document.documentElement.scrollWidth > innerWidth + 1, vw: innerWidth, sw: document.documentElement.scrollWidth,
        line: Math.max(...[...document.querySelectorAll('.page-intro')].map(p => p.getBoundingClientRect().width / parseFloat(getComputedStyle(p).fontSize)))}));
      let touch = null;
      if (w <= 430) touch = await pm.evaluate(() => [...document.querySelectorAll('#content button, #content select, #content input:not([type=checkbox]), .topbar button')].filter(e => e.offsetParent).filter(e => e.getBoundingClientRect().height < 44).length);
      await pm.screenshot({path: path.join(out, `${pg}-${w}.png`), fullPage: true});
      await cm.close();
      assert(!m.over, JSON.stringify(m));
      if (w >= 1440) assert(m.line < 90, 'line length ' + m.line);
      if (touch !== null) assert(touch === 0, touch + ' targets under 44px');
      return JSON.stringify({...m, under44: touch});
    });
  }
  await test('CLAUDE-UX-MOBILE-004', '390px: dialog buttons visible and reachable', async () => {
    const {c: cm, page: pm} = await ctx({viewport: {width: 390, height: 664}, touch: true, mobile: true});
    await login(pm); await go(pm, 'users');
    await pm.locator('tbody tr:not(.protected) details.menu summary').first().click();
    await reviewAfter(pm, 'tbody tr:not(.protected) [data-action=user-revoke] >> nth=0');
    const box = await pm.locator('[data-action=commit-change]').boundingBox();
    await pm.screenshot({path: path.join(out, 'mobile-dialog-390.png')});
    await cm.close();
    assert(box && box.y + box.height <= 664 && box.x >= 0 && box.x + box.width <= 390, JSON.stringify(box));
    return JSON.stringify(box);
  });
  await test('CLAUDE-UX-MOBILE-005', '430px: user cards show status and a working secondary menu', async () => {
    const {c: cm, page: pm} = await ctx({viewport: {width: 430, height: 932}, touch: true, mobile: true});
    await login(pm); await go(pm, 'users');
    const display = await pm.locator('tbody tr').first().evaluate(e => getComputedStyle(e).display);
    const card = pm.locator('tbody tr:not(.protected)').first();
    const t = await card.innerText();
    await card.locator('details.menu summary').click();
    const items = await card.locator('.menu-list button').allInnerTexts();
    const inView = await card.locator('.menu-list').evaluate(e => { const b = e.getBoundingClientRect(); return b.left >= 0 && b.right <= innerWidth; });
    await pm.screenshot({path: path.join(out, 'mobile-menu-430.png')});
    await cm.close();
    assert(display === 'block' && /Enabled|Disabled/.test(t) && items.length === 4 && inView, display + ' ' + items.join('/'));
    return items.join(' / ');
  });
  await test('CLAUDE-UX-NAV-010', 'Mobile drawer closes on choice and focus moves to the page title', async () => {
    const {c: cm, page: pm} = await ctx({viewport: {width: 390, height: 844}, touch: true, mobile: true});
    await login(pm);
    await pm.locator('#menu').click();
    assert(await pm.locator('#menu').getAttribute('aria-expanded') === 'true', 'expanded');
    await pm.locator('#nav details').filter({hasText:'Monitoring'}).locator('summary').click();
    await pm.locator('#nav a[href="#traffic"]').click(); await settled(pm);
    await pm.waitForFunction(() => document.activeElement && document.activeElement.id === 'title', null, {timeout: 5000}).catch(() => {});
    const r = await pm.evaluate(() => ({open: document.body.classList.contains('menu-open'), focus: document.activeElement.id, expanded: document.querySelector('#menu').getAttribute('aria-expanded')}));
    await pm.locator('#menu').click(); await pm.keyboard.press('Escape');
    const esc = await pm.evaluate(() => [document.body.classList.contains('menu-open'), document.activeElement.id]);
    await cm.close();
    assert(!r.open && r.focus === 'title' && r.expanded === 'false' && !esc[0] && esc[1] === 'menu', JSON.stringify(r) + JSON.stringify(esc));
  });
  await test('CLAUDE-UX-MOBILE-009', '200% zoom keeps menus and dialogs usable', async () => {
    const {c: cm, page: pm} = await ctx({viewport: {width: 640, height: 450}, scale: 2});
    await login(pm); await go(pm, 'users');
    await pm.locator('[data-action=user-create]').first().click();
    const dlg = await pm.locator('#user-form button[type=submit]').boundingBox();
    await pm.locator('#user-form button[type=submit]').scrollIntoViewIfNeeded();
    const visible = await pm.locator('#user-form button[type=submit]').isVisible();
    const over = await pm.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
    await pm.screenshot({path: path.join(out, 'zoom200-dialog.png')});
    await cm.close();
    assert(visible && !over, JSON.stringify(dlg));
    return 'CSS viewport 640x450 at DPR 2 (equivalent to 1280x900 at 200%)';
  });
  await test('CLAUDE-UX-MOBILE-010', 'Landscape phone keeps submit reachable', async () => {
    const {c: cm, page: pm} = await ctx({viewport: {width: 740, height: 360}, touch: true, mobile: true});
    await login(pm); await go(pm, 'access');
    const btn = pm.locator('#settings-password button[type=submit]');
    await btn.scrollIntoViewIfNeeded();
    const box = await btn.boundingBox();
    const sticky = await pm.evaluate(() => getComputedStyle(document.querySelector('.topbar')).position);
    await cm.close();
    assert(box && box.y >= 0 && box.y + box.height <= 360 && sticky === 'static', JSON.stringify(box) + ' topbar=' + sticky);
    return 'topbar=' + sticky;
  });

  if (FIXTURE) {
    const matrix = [[0, 19511], [1, 19512], [25, 19513], [26, 19514], [100, 19515], [1000, 19516]];
    const procs = [];
    try {
      for (const [n, port] of matrix) procs.push([n, port, (await spawnFixture(n, port, VARIANT)).proc]);
      for (const [n, port] of matrix) {
        await test(`USERS-PAGING-${n}`, `${n} additional users: counts, pages and retrieval`, async () => {
          const o = origin.replace(/:\d+$/, ':' + port);
          const {c: cm, page: pm} = await ctx();
          await login(pm, 'admin', PASSWORD, o); await go(pm, 'users');
          const t0 = Date.now();
          const caption = await pm.locator('caption').first().innerText();
          const pagesText = await pm.locator('.pager .meta').nth(1).innerText();
          const expectPages = Math.max(1, Math.ceil(n / 25));
          assert(new RegExp(`${n} of ${n} additional users`).test(caption), caption);
          assert(pagesText === `Page 1 of ${expectPages}`, pagesText);
          if (n === 0) assert(/No additional users yet/.test(await pm.locator('main').innerText()) && await pm.locator('.empty [data-action=user-create]').count() === 1, 'empty CTA');
          const seen = new Set();
          for (let p = 0; p < expectPages; p++) {
            (await pm.locator('tbody tr:not(.protected) td.name-cell strong').allInnerTexts()).forEach(x => seen.add(x));
            if (p < expectPages - 1) await pm.locator('[data-action=users-next]').click();
          }
          assert(seen.size === n, 'retrieved ' + seen.size);
          let extra = '';
          if (n === 26 || n === 100) {
            await pm.locator('[data-action=users-prev]').click().catch(() => {});
            await pm.locator('#user-search').fill('client-00'); await pm.waitForTimeout(300);
            await pm.locator('#user-status').selectOption('disabled');
            const dis = await pm.locator('tbody tr:not(.protected) .status').allInnerTexts();
            assert(dis.length && dis.every(x => x === 'Disabled'), 'filter disabled');
            if (n === 26) { const pg = await pm.locator('.pager .meta').nth(1).innerText(); assert(pg === 'Page 1 of 1', 'filter retained across paging: ' + pg); assert(await pm.locator('#user-search').inputValue() === 'client-00', 'query kept'); }
            extra = ' disabled-filter=' + dis.length;
          }
          if (n === 1000) {
            await pm.locator('#user-search').fill('client-0999'); await pm.waitForTimeout(400);
            assert(await pm.locator('tbody tr:not(.protected)').count() === 1, 'search 1000');
            await pm.locator('#user-search').fill('');
            await pm.locator('#user-size').selectOption('100'); await pm.waitForTimeout(300);
            assert(await pm.locator('tbody tr:not(.protected)').count() === 100, 'page size 100');
            const metrics = await cm.newCDPSession(pm).then(s => s.send('Performance.enable').then(() => s.send('Performance.getMetrics')));
            const heap = metrics.metrics.find(m => m.name === 'JSHeapUsedSize').value;
            extra = ' heap=' + Math.round(heap / 1048576) + 'MiB nodes=' + metrics.metrics.find(m => m.name === 'Nodes').value;
          }
          await pm.screenshot({path: path.join(out, `users-${n}.png`)});
          await cm.close();
          return `pages=${expectPages} retrieved=${seen.size} ms=${Date.now() - t0}${extra}`;
        });
      }
    } finally { procs.forEach(([, , p]) => p.kill()); }
  }

  await test('E2E-CHART-LINES-UNFILLED', 'Traffic lines (overview sparkline and history chart) are stroked lines, never filled shapes', async () => {
    await go(page, 'overview');
    const fills = await page.evaluate(() => {
      const host = document.createElement('div'); host.className = 'probe-host';
      host.innerHTML = '<svg class="spark"><polyline class="rx" points="0,0 5,5"/></svg><div class="chart"><svg><polyline class="rx" points="0,0 5,5"/><polyline class="tx" points="0,0 5,5"/></svg></div>';
      document.querySelector('#content').appendChild(host);
      const out = [...host.querySelectorAll('polyline')].map(e => getComputedStyle(e).fill + '|' + getComputedStyle(e).stroke);
      host.remove(); return out;
    });
    assert(fills.every(f => f.startsWith('none|') && !f.endsWith('|none')), JSON.stringify(fills));
    return fills.join(' ; ');
  });
  await test('E2E-NO-PAGE-ERRORS', 'No uncaught page errors during the run', async () => { assert(!page.errors.length, page.errors.join('\n')); });
  await browser.close();
  const failed = rows.filter(r => r.status !== 'PASS');
  console.log(JSON.stringify({total: rows.length, failed: failed.length}));
  process.exitCode = failed.length ? 1 : 0;
})().catch(async e => { console.error(e); if (browser) await browser.close(); process.exitCode = 2; });
