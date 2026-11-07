/* Responsive layout, overlap and form-behaviour matrix. FIXTURE ONLY.

   node test_layout_matrix_browser.cjs [OUTDIR] [--quick]

   Starts the REAL panel server with the in-memory fixture bridge
   (tests/dev_panel.py), signs in, and audits real pages with the production
   CSS/JS at every required width, in English and Hong Kong Traditional
   Chinese, light/dark/system themes and 125-200% text. The portal is the real
   page with mocked /api/v1/portal responses. Negative controls deliberately
   reintroduce defects (overlap, overflow, clipping, unnamed control, the old
   1360px width cap, a 15-result time-zone cap) and the audit must catch them.
   Not live acceptance: no VPN, no real users, synthetic data. */
const {chromium} = require('playwright');
const {spawn} = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert/strict');
const audit = require('./layout_audit.cjs');
const root = path.resolve(__dirname, '..');
const out = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : fs.mkdtempSync(path.join(os.tmpdir(), 'sbox-layout-'));
const QUICK = process.argv.includes('--quick');
fs.mkdirSync(out, {recursive: true});
const WIDTHS = QUICK ? [320, 390, 1024, 2048] : [320, 360, 375, 390, 414, 600, 640, 768, 900, 1024, 1280, 1440, 1600, 1920, 2048, 2560];
const SCALE_WIDTHS = QUICK ? [390, 1280] : [320, 390, 768, 1280, 2048];
const SCALES = [1.25, 1.5, 1.75, 2];
const HOST = process.env.SBOX_LAYOUT_HOST || 'panel.sbox.test', PORT = 20000 + Math.floor(Math.random() * 3000), ORIGIN = `https://${HOST}:${PORT}`;
const rows = [];
let failures = 0;

function startPanel() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sbox-layout-panel-'));
  const child = spawn('python3', [path.join(root, 'tests/dev_panel.py'), '--variant', 'universal', '--users', '14', '--port', String(PORT), '--work', work, '--host', HOST], {stdio: ['ignore', 'pipe', 'inherit'], env: {...process.env, SBOX_FIXTURE_SAMPLE_SECONDS: '3600'}});
  return new Promise((resolve, reject) => {
    let buf = '';
    child.stdout.on('data', d => { buf += d; if (buf.includes('\n')) resolve({child, info: JSON.parse(buf.split('\n')[0])}); });
    child.on('exit', code => reject(new Error('panel exited ' + code)));
  });
}
async function scaleText(page, scale) {
  await page.evaluate(scale => { for (const [n, size] of Object.entries({'--step--1': 13, '--step-0': 15, '--step-1': 17, '--step-2': 21, '--step-3': 28})) document.documentElement.style.setProperty(n, size * scale + 'px'); document.documentElement.style.fontSize = 16 * scale + 'px'; }, scale);
}
async function check(page, label, extra = {}) {
  await page.waitForTimeout(120);
  await page.evaluate(() => Promise.all(document.getAnimations().map(a => a.finished.catch(() => null))));
  const result = await page.evaluate(`(${audit.toString()})()`);
  const problems = result.problems;
  rows.push({label, ...extra, problems: problems.length, stats: result.stats});
  if (problems.length) {
    failures++;
    const shot = path.join(out, 'FAIL-' + label.replace(/[^a-z0-9]+/gi, '_') + '.png');
    await page.screenshot({path: shot});
    console.log('FAIL', label, JSON.stringify(problems.slice(0, 6)));
  }
  return result;
}
async function login(page, password) {
  await page.goto(ORIGIN + '/', {waitUntil: 'domcontentloaded'});
  await page.locator('#login-form input[name=password]').waitFor();
  await page.locator('#login-form input[name=username]').fill('admin');
  await page.locator('#login-form input[name=password]').fill(password);
  await page.locator('#login-submit').click();
  await page.locator('#shell').waitFor({state: 'visible'});
}
async function closeModal(page) { await page.evaluate(() => { const d = document.querySelector('#modal'); if (d.open) d.close(); document.querySelectorAll('[popover]').forEach(p => { try { p.hidePopover(); } catch {} }); }); }
async function openPlan(page) {
  await page.goto(ORIGIN + '/#users'); await page.locator('[data-action=user-create]').first().waitFor();
  await page.locator('[data-action=user-create]').first().click();
  await page.locator('#new-user-wizard input[name=name]').fill('layout-user');
  await page.locator('[data-action=wizard-next]').click();
  await page.locator('.plan-fields .plan-preview .plan-summary').waitFor({timeout: 15000});
}

(async () => {
  const {child, info} = await startPanel();
  const browser = await chromium.launch({args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1, MAP * ~NOTFOUND`, '--no-proxy-server']});
  try {
    // ---------------------------------------------------------- admin matrix
    for (const lang of ['en', 'zh']) {
      const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1280, height: 900}, colorScheme: 'light'});
      await ctx.addInitScript(([l]) => { try { localStorage.setItem('sbox-lang', l); localStorage.setItem('sbox-theme', 'light'); } catch {} }, [lang]);
      const page = await ctx.newPage();
      page.on('pageerror', e => { failures++; console.log('FAIL pageerror', e.message); });
      await login(page, info.password);
      for (const width of WIDTHS) {
        await page.setViewportSize({width, height: width < 700 ? 844 : 900});
        const tag = `${lang}/${width}`;
        await page.goto(ORIGIN + '/#overview'); await page.locator('.health-strip').waitFor();
        await check(page, `${tag}/overview`);
        if (width >= 1000) {
          const used = await page.evaluate(() => { const m = document.querySelector('main').getBoundingClientRect(); return {right: m.right, vw: document.documentElement.clientWidth}; });
          const ok = used.right >= used.vw - 2; rows.push({label: `${tag}/main uses full width`, ok}); if (!ok) { failures++; console.log('FAIL width', tag, used); }
        }
        await page.goto(ORIGIN + '/#users'); await page.locator('.users-table, table').first().waitFor();
        await check(page, `${tag}/users`);
        // Action menu (native popover) open.
        const more = page.locator('.users-table .menu > summary').first();
        if (await more.count()) { await more.click(); await page.waitForTimeout(150); await check(page, `${tag}/users action menu open`); await page.keyboard.press('Escape'); }
        await page.goto(ORIGIN + '/#access'); await page.locator('#settings-password').waitFor();
        await check(page, `${tag}/password form`);
        // Plan step and its states.
        await openPlan(page);
        await check(page, `${tag}/plan default (unlimited)`);
        await page.locator('input[name=unlimited]').uncheck();
        await page.locator('input[name=amount]').fill('100');
        await page.locator('select[name=unit]').selectOption('GiB');
        await page.waitForTimeout(400);
        await page.locator('input[name=no_expiry]').uncheck();
        await page.locator('input[name=amount]').fill('-1'); await page.locator('input[name=amount]').evaluate(el => el.setAttribute('aria-invalid', 'true'));
        await check(page, `${tag}/plan limited + dropdown + expiry + invalid amount`);
        await page.locator('input[name=amount]').fill('100');
        for (const [query, kind] of [['', 'all'], ['a', 'many'], ['america/a', 'some'], ['hong', 'one'], ['zzzz', 'none']]) {
          await page.locator('[data-timezone-search]').click();
          await page.locator('[data-timezone-search]').fill(query);
          await page.waitForTimeout(200);
          await check(page, `${tag}/time zone ${kind}`);
          await page.keyboard.press('Escape');
        }
        await closeModal(page);
        if (width === 390 || width === 1280) {
          // User detail usage chart with keyboard tooltip.
          await page.goto(ORIGIN + '/#users'); await page.locator('[data-action=user-detail]').first().click();
          await page.locator('[data-tab=usage]').click(); await page.locator('.usage-bar').first().waitFor();
          await page.locator('.usage-bar[tabindex="0"]').focus(); await page.keyboard.press('End');
          await check(page, `${tag}/usage chart tooltip`);
          const tip = await page.evaluate(() => { const t = document.querySelector('.usage-tooltip'); if (!t || t.hidden) return null; const r = t.getBoundingClientRect(); return {l: r.left, r: r.right, t: r.top, b: r.bottom, vw: innerWidth, vh: innerHeight}; });
          const inside = tip && tip.l >= 0 && tip.t >= 0 && tip.r <= tip.vw && tip.b <= tip.vh;
          rows.push({label: `${tag}/tooltip inside viewport`, ok: Boolean(inside)}); if (!inside) { failures++; console.log('FAIL tooltip', tag, tip); }
          await closeModal(page);
        }
      }
      // Enlarged text.
      for (const width of SCALE_WIDTHS) for (const scale of SCALES) {
        await page.setViewportSize({width, height: 900});
        await page.goto(ORIGIN + '/#overview'); await page.locator('.health-strip').waitFor(); await scaleText(page, scale);
        await check(page, `${lang}/${width}/text ${scale * 100}%/overview`);
        await openPlan(page); await scaleText(page, scale);
        await check(page, `${lang}/${width}/text ${scale * 100}%/plan`);
        await closeModal(page);
      }
      // Themes (dark and system) at representative widths.
      for (const theme of ['dark', 'system']) for (const width of [390, 1280, 2048]) {
        await page.evaluate(t => { localStorage.setItem('sbox-theme', t); }, theme);
        await page.emulateMedia({colorScheme: 'dark'});
        await page.setViewportSize({width, height: 900});
        await page.goto(ORIGIN + '/#overview'); await page.reload(); await page.locator('.health-strip').waitFor();
        await check(page, `${lang}/${width}/${theme}/overview`);
        await openPlan(page); await check(page, `${lang}/${width}/${theme}/plan`); await closeModal(page);
      }
      await ctx.close();
    }

    // ------------------------------------------------- behaviour assertions
    const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1280, height: 900}});
    await ctx.addInitScript(() => { try { localStorage.setItem('sbox-lang', 'zh'); } catch {} });
    const page = await ctx.newPage();
    await login(page, info.password);
    await openPlan(page);
    assert.equal(await page.locator('input[name=unlimited]').count(), 1, 'one unlimited checkbox');
    assert.equal(await page.locator('select[name=unit]').count(), 1, 'one native scrollable unit selector');
    assert.equal(await page.locator('[data-plan-preset], input[type=radio][name=unit]').count(), 0, 'no duplicate presets or radio units');
    assert.deepEqual(await page.locator('select[name=unit] option').evaluateAll(os=>os.map(o=>o.value)),
      ['GB','TB','GiB','TiB','MB','MiB','KB','KiB','B']);
    assert.equal(await page.locator('.quota-amount').isVisible(), false, 'unlimited hides amount controls');
    // Exact byte semantics through the real server preview.
    for (const [unit, bytes] of [['GB', '100000000000'], ['GiB', '107374182400'], ['TB', '100000000000000']]) {
      await page.locator('input[name=unlimited]').uncheck();
      await page.locator('input[name=amount]').fill('100');
      await page.locator('select[name=unit]').selectOption(unit);
      await page.waitForTimeout(700);
      await page.locator('.plan-exact > summary').click();
      const text = (await page.locator('.plan-exact p').textContent()).replace(/[^0-9 ]/g, '');
      assert.ok(text.includes(Number(bytes).toLocaleString('en').replace(/,/g, '')) || text.replace(/ /g, '').includes(bytes), `${unit} preview shows exact bytes ${bytes}: ${text}`);
      await page.locator('.plan-exact > summary').click();
    }
    const amount = await page.locator('.plan-amount').textContent();
    assert.match(amount, /100 TB/, 'summary shows the selected amount, not a raw byte count');
    // Full time-zone database, searchable, no 15-result cap.
    const total = await page.evaluate(() => state.timezoneData.timezones.length);
    assert.ok(total >= 400, 'server provides the full IANA database: ' + total);
    await page.locator('[data-timezone-search]').click(); await page.locator('[data-timezone-search]').fill('');
    await page.waitForTimeout(200);
    assert.equal(await page.locator('.timezone-options [role=option]').count(), total, 'every zone is listed for an empty query');
    const search = async q => { await page.locator('[data-timezone-search]').fill(q); await page.waitForTimeout(150); return page.locator('.timezone-options [role=option]').evaluateAll(o => o.map(x => x.dataset.zone)); };
    assert.ok((await search('a')).length > 15, 'more than 15 matches are shown');
    assert.ok((await search('hong kong')).includes('Asia/Hong_Kong'));
    assert.ok((await search('香港')).includes('Asia/Hong_Kong'), 'localized city name');
    assert.ok((await search('東京')).includes('Asia/Tokyo'));
    const plus8 = await search('+8');
    assert.ok(plus8.includes('Asia/Hong_Kong') && plus8.includes('Asia/Singapore') && !plus8.includes('Europe/London'), 'offset search');
    await search('Asia/Kolkata');  // an exact identifier selects immediately
    assert.equal(await page.locator('input[name=timezone]').inputValue(), 'Asia/Kolkata');
    await page.locator('[data-timezone-search]').fill(''); await page.waitForTimeout(100);
    assert.ok((await search('india')).includes('Asia/Kolkata'), 'country name');
    assert.equal((await search('zzzz')).length, 0);
    assert.match(await page.locator('.zone-empty').textContent(), /沒有相符的時區/);
    await page.keyboard.press('Escape');
    // Keyboard selection.
    await page.locator('[data-timezone-search]').fill('tokyo'); await page.waitForTimeout(150); await page.keyboard.press('Enter');
    assert.equal(await page.locator('input[name=timezone]').inputValue(), 'Asia/Tokyo');
    assert.equal(await page.locator('[data-timezone-search]').getAttribute('aria-expanded'), 'false');
    await closeModal(page);
    // Saved time zone is kept when editing (user with Europe/London plan).
    await page.goto(ORIGIN + '/#users');
    const londonId = await page.evaluate(async () => (await api('accounting')).users.find(u => u.plan?.timezone === 'Europe/London')?.id);
    if (londonId) { await page.evaluate(id => userDetail(id, 'plan'), londonId); await page.locator('[data-tab=plan]').click(); await page.locator('#quota-form [data-timezone-search]').waitFor();
      assert.equal(await page.locator('#quota-form input[name=timezone]').inputValue(), 'Europe/London', 'saved choice preserved'); await closeModal(page); }
    // Server list failure: honest browser fallback with retry.
    await page.route('**/api/v1/system/timezones', r => r.fulfill({status: 503, contentType: 'application/json', body: '{"error":"fixture outage"}'}));
    await page.evaluate(() => { state.timezoneData = null; });
    await openPlan(page);
    assert.ok(await page.locator('.timezone-source').isVisible(), 'fallback is labelled');
    assert.ok((await page.evaluate(() => state.timezoneData.source)) === 'browser');
    await page.unroute('**/api/v1/system/timezones');
    await page.locator('[data-action=timezone-retry]').click(); await page.waitForTimeout(500);
    assert.equal(await page.evaluate(() => state.timezoneData.source), 'server', 'retry restores the server list');
    await closeModal(page);
    // Password confirmation mismatch never reaches the server.
    await page.goto(ORIGIN + '/#access'); await page.locator('#settings-password').waitFor();
    let posted = false; await page.route('**/api/v1/auth/change-password', r => { posted = true; r.abort(); });
    await page.locator('#settings-password input[name=old]').fill('Fixture-admin-password-2026');
    await page.locator('#settings-password input[name=password]').fill('Another-long-password-1');
    await page.locator('#settings-password-confirm').fill('Different-long-password-1');
    await page.locator('#settings-password button[type=submit]').click(); await page.waitForTimeout(300);
    assert.equal(posted, false); assert.equal(await page.locator('#settings-password-confirm').getAttribute('aria-invalid'), 'true');
    const pad = await page.locator('#settings-password input[name=password]').evaluate(el => parseFloat(getComputedStyle(el).paddingRight));
    assert.ok(pad >= 40, 'room for password-manager icons: ' + pad);
    rows.push({label: 'behaviour: presets, exact bytes, full time zones, fallback, password confirmation', ok: true});
    await ctx.close();

    // ---------------------------------------------------------- portal
    for (const lang of ['en', 'zh']) for (const width of WIDTHS) for (const reset of [false, true]) {
      const c = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width, height: 900}});
      await c.addInitScript(l => { try { localStorage.setItem('sbox-portal-lang', l); } catch {} }, lang);
      const p = await c.newPage();
      const me = {fixture: true, display_name: 'Synthetic', status: reset ? 'password_change_required' : 'active', reset_password: reset, freshness: 'fresh', sampled_at: Date.now() / 1000, timezone: 'Asia/Hong_Kong', used_bytes: 38.2e9, upload_bytes: 6e9, download_bytes: 32.2e9, remaining_bytes: 61.8e9, quota_bytes: 100e9, unlimited: false, period: 'monthly', next_reset: Date.now() / 1000 + 86400};
      const hist = {window: '24h', timezone: 'Asia/Hong_Kong', start: 0, end: 1, oldest_date: '2026-08-01', latest_date: '2026-10-30', incomplete: true, totals: {upload_bytes: 5e8, download_bytes: 9e8}, buckets: Array.from({length: 24}, (_, i) => ({start: 1e9 + i * 3600, end: 1e9 + (i + 1) * 3600, up: i % 7 === 3 ? null : 1e7 * i, down: i % 7 === 3 ? null : 3e7 * i, state: i % 7 === 3 ? 'unobserved' : 'recorded'}))};
      await p.route('**/api/v1/portal/**', r => { const n = new URL(r.request().url()).pathname.split('/api/v1/portal/')[1]; r.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(n === 'me/history' ? hist : {...me, csrf: 'x'})}); });
      await p.goto(ORIGIN + '/portal'); await p.waitForTimeout(700);
      await check(p, `portal/${lang}/${width}/${reset ? 'change password' : 'overview'}`);
      if (width >= 1000) {
        const used = await p.evaluate(() => ({right: document.querySelector('main').getBoundingClientRect().right, vw: document.documentElement.clientWidth}));
        const ok = used.right >= used.vw - 60; rows.push({label: `portal/${lang}/${width} uses full width`, ok}); if (!ok) { failures++; console.log('FAIL portal width', width, used); }
      }
      await c.close();
    }

    // -------------------------------------------------- negative controls
    const neg = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 2048, height: 900}});
    const np = await neg.newPage();
    await login(np, info.password);
    const expectCaught = async (name, setup, kind) => {
      await np.goto(ORIGIN + '/#overview'); await np.reload(); await np.locator('.health-strip').waitFor();
      await np.evaluate(setup);
      const r = await np.evaluate(`(${audit.toString()})()`);
      const caught = r.problems.some(x => x.kind === kind);
      rows.push({label: 'negative control: ' + name, ok: caught});
      if (!caught) { failures++; console.log('FAIL negative control not caught:', name, JSON.stringify(r.problems.slice(0, 3))); }
    };
    await expectCaught('overlapping button', () => { const b = document.createElement('button'); b.textContent = 'Overlap'; Object.assign(b.style, {position: 'absolute', left: '0', top: '0', width: '100%', height: '100%', opacity: '0.01'}); const host = document.querySelector('.overview-actions') || document.querySelector('main'); host.style.position = 'relative'; host.appendChild(b); }, 'overlap');
    await expectCaught('horizontal overflow', () => { const d = document.createElement('div'); d.style.width = '4000px'; d.style.height = '4px'; document.querySelector('main').appendChild(d); document.querySelector('main').style.overflow = 'visible'; }, 'page-overflow');
    await expectCaught('unnamed control', () => { const b = document.createElement('button'); b.style.width = '40px'; b.style.height = '40px'; document.querySelector('main').prepend(b); }, 'no-accessible-name');
    await expectCaught('clipped control', () => { const w = document.createElement('div'); Object.assign(w.style, {overflow: 'hidden', height: '20px', width: '300px'}); const b = document.createElement('button'); b.textContent = 'Clipped action'; b.style.height = '60px'; w.appendChild(b); document.querySelector('main').prepend(w); }, 'clipped');
    await expectCaught('covered control', () => { const c = document.createElement('div'); Object.assign(c.style, {position: 'fixed', left: '0', top: '0', width: '100vw', height: '100vh', background: 'transparent', zIndex: '999'}); document.body.appendChild(c); }, 'covered');
    // Reintroduced 1360px cap must fail the full-width rule.
    await np.goto(ORIGIN + '/#overview'); await np.reload(); await np.locator('.health-strip').waitFor();
    await np.evaluate(() => { document.querySelector('main').style.maxWidth = '1360px'; });  // the old rule, via CSSOM (CSP blocks inline style tags)
    const capped = await np.evaluate(() => document.querySelector('main').getBoundingClientRect().right >= document.documentElement.clientWidth - 2);
    rows.push({label: 'negative control: 1360px cap detected', ok: !capped}); if (capped) { failures++; console.log('FAIL 1360 cap not detected'); }
    // Reintroduced 15-result cap must fail the full-list rule.
    await np.goto(ORIGIN + '/#users'); await np.reload(); await np.locator('[data-action=user-create]').first().waitFor();
    await np.evaluate(() => { const original = searchZones; window.searchZones = q => original(q).slice(0, 15); });
    await openPlan(np);
    await np.locator('[data-timezone-search]').click(); await np.locator('[data-timezone-search]').fill('a'); await np.waitForTimeout(150);
    const shown = await np.locator('.timezone-options [role=option]').count();
    rows.push({label: 'negative control: 15-result cap detected', ok: shown <= 15}); if (shown > 15) { failures++; console.log('FAIL cap control ineffective', shown); }
    await neg.close();
  } finally {
    await browser.close(); child.kill();
    fs.writeFileSync(path.join(out, 'layout-matrix.json'), JSON.stringify({fixture: true, widths: WIDTHS, scale_widths: SCALE_WIDTHS, scales: SCALES, rows, failures}, null, 1));
  }
  const audited = rows.filter(r => r.stats).length;
  console.log(JSON.stringify({fixture: true, scope: 'admin + portal, 2 locales, ' + WIDTHS.length + ' widths, themes, 125-200% text, dialogs/menus/time-zone list/chart tooltip, negative controls', audited_states: audited, checks: rows.length, failures}));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
