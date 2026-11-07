/* Before/after screenshot harness. FIXTURE ONLY - NOT LIVE EVIDENCE.

   node ui_screens.cjs WEBUI_ROOT OUTDIR [--only name,name]

   Starts the REAL panel server (tests/dev_panel.py) from WEBUI_ROOT with the
   in-memory fixture bridge, signs in with the synthetic fixture password and
   captures the same pages/viewports for any revision. The personal portal is
   rendered from the real portal.html/js/css with mocked /api/v1/portal/*
   responses (synthetic numbers, clearly labelled). Writes OUTDIR/index.json
   with viewport, language and theme metadata for every image. */
const {chromium} = require('playwright');
const {spawn} = require('child_process');
const fs = require('fs');
const path = require('path');
const [webroot, out, ...rest] = process.argv.slice(2);
if (!webroot || !out) { console.error('usage: ui_screens.cjs WEBUI_ROOT OUTDIR'); process.exit(2); }
const ONLY = (rest[rest.indexOf('--only') + 1] || '').split(',').filter(Boolean);
const PORT = 19400 + Math.floor(Math.random() * 500);
const HOST = 'panel.sbox.test';
const ORIGIN = `https://${HOST}:${PORT}`;
fs.mkdirSync(out, {recursive: true});
const shots = [];

function startPanel() {
  const work = fs.mkdtempSync(path.join(require('os').tmpdir(), 'sbox-screens-'));
  const child = spawn('python3', [path.join(webroot, 'tests/dev_panel.py'), '--variant', 'universal', '--users', '14', '--port', String(PORT), '--work', work, '--host', HOST], {stdio: ['ignore', 'pipe', 'inherit'], env: {...process.env, SBOX_FIXTURE_SAMPLE_SECONDS: '3600'}});
  return new Promise((resolve, reject) => {
    let buf = '';
    child.stdout.on('data', d => { buf += d; const line = buf.split('\n')[0]; if (buf.includes('\n')) { try { resolve({child, info: JSON.parse(line)}); } catch (e) { reject(e); } } });
    child.on('exit', code => reject(new Error('panel exited ' + code)));
  });
}

const HOUR = 3600, NOW = Math.floor(Date.UTC(2026, 9, 30, 12) / 1000);
function history(window = '24h', n = 24) {
  const buckets = Array.from({length: n}, (_, i) => {
    const start = NOW - (n - i) * HOUR;
    const gap = i === 5 || i === 6;
    const zero = i === 10;
    return {start, end: start + HOUR, up: gap ? null : zero ? 0 : 20e6 + (i % 7) * 31e6, down: gap ? null : zero ? 0 : 150e6 + ((i * 37) % 11) * 90e6, state: gap ? 'unobserved' : 'recorded'};
  });
  const up = buckets.reduce((s, b) => s + (b.up || 0), 0), down = buckets.reduce((s, b) => s + (b.down || 0), 0);
  return {fixture: true, window, timezone: 'Asia/Hong_Kong', start: buckets[0].start, end: NOW, buckets, totals: {upload_bytes: up, download_bytes: down}, oldest_date: '2026-08-01', latest_date: '2026-10-30', incomplete: true};
}
const portalMe = reset => ({fixture: true, display_name: 'Synthetic portal user', status: reset ? 'password_change_required' : 'active', reset_password: reset, freshness: 'fresh', sampled_at: NOW - 60, timezone: 'Asia/Hong_Kong', used_bytes: 38.2e9, upload_bytes: 6.1e9, download_bytes: 32.1e9, remaining_bytes: 61.8e9, quota_bytes: 100e9, unlimited: false, period: 'monthly', reset_day: 1, next_reset: NOW + 2 * 86400, expires_at: 0});

async function portalRoutes(page, reset) {
  await page.route('**/api/v1/portal/**', route => {
    const url = new URL(route.request().url());
    const name = url.pathname.replace('/api/v1/portal/', '');
    const body = name === 'session' ? {fixture: true, csrf: 'fixture-csrf', ...portalMe(reset)} : name === 'me' ? portalMe(reset) : name === 'me/history' ? history(url.searchParams.get('window') || '24h', url.searchParams.get('window') === '7d' ? 7 * 24 : 24) : {fixture: true};
    route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(body)});
  });
}

async function shot(page, name, meta) {
  if (ONLY.length && !ONLY.some(x => name.startsWith(x))) return;
  await page.evaluate(() => document.fonts && document.fonts.ready);
  await page.waitForTimeout(250);
  const file = name + '.png';
  await page.screenshot({path: path.join(out, file), fullPage: !!meta.full});
  shots.push({file, ...meta});
  console.log('shot', file);
}

(async () => {
  const {child, info} = await startPanel();
  // Offline: never use an environment proxy; map the fixture hostname to loopback.
  const browser = await chromium.launch({args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1, MAP * ~NOTFOUND`, '--no-proxy-server']});
  try {
    for (const lang of ['en', 'zh']) {
      for (const theme of ['light', 'dark']) {
        const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 2048, height: 1100}, colorScheme: theme});
        await ctx.addInitScript(([l, t]) => { try { localStorage.setItem('sbox-lang', l); localStorage.setItem('sbox-theme', t); localStorage.setItem('sbox-portal-lang', l); localStorage.setItem('sbox-portal-theme', t); } catch (e) {} }, [lang, theme]);
        const page = await ctx.newPage();
        await page.goto(ORIGIN + '/', {waitUntil: 'domcontentloaded'});
        await page.locator('#login-form input[name=password]').waitFor();
        await page.locator('#login-form input[name=username]').fill('admin');
        await page.locator('#login-form input[name=password]').fill(info.password);
        await page.locator('#login-submit').click();
        await page.locator('#shell').waitFor({state: 'visible'});
        const views = theme === 'light' ? [[2048, 1100], [1440, 900], [390, 844]] : [[2048, 1100], [390, 844]];
        for (const [w, h] of views) {
          await page.setViewportSize({width: w, height: h});
          const meta = {viewport: `${w}x${h}`, lang, theme};
          await page.goto(ORIGIN + '/#overview'); await page.locator('.health-strip, .health-cell').first().waitFor({timeout: 15000}).catch(() => {});
          await page.waitForTimeout(600);
          await shot(page, `admin-overview-${w}-${lang}-${theme}`, {...meta, page: 'Admin overview', full: true});
          if (theme === 'dark') continue;
          await page.goto(ORIGIN + '/#users'); await page.waitForTimeout(900);
          await shot(page, `admin-users-${w}-${lang}-${theme}`, {...meta, page: 'Users & quota'});
          await page.goto(ORIGIN + '/#access'); await page.waitForTimeout(700);
          await shot(page, `admin-password-${w}-${lang}-${theme}`, {...meta, page: 'Admin change password'});
          if (w === 1440) continue;
          // Add-user wizard, plan step.
          await page.goto(ORIGIN + '/#users'); await page.waitForTimeout(600);
          await page.locator('[data-action=user-create]').first().click();
          await page.locator('#new-user-wizard').waitFor();
          await page.locator('#new-user-wizard input[name=name]').fill('screen-user');
          await page.locator('[data-action=wizard-next]').click();
          await page.locator('.plan-fields').waitFor();
          await page.waitForTimeout(900);
          await shot(page, `wizard-plan-${w}-${lang}-${theme}`, {...meta, page: 'Create user · plan step'});
          // Time zone search with many matches.
          await page.locator('[data-timezone-search]').click();
          await page.locator('[data-timezone-search]').fill('a');
          await page.waitForTimeout(500);
          await shot(page, `wizard-timezone-${w}-${lang}-${theme}`, {...meta, page: 'Create user · time zone search open'});
          await page.keyboard.press('Escape');
          await page.evaluate(() => { const d = document.querySelector('#modal'); if (d.open) d.close(); });
        }
        // User detail usage chart.
        await page.setViewportSize({width: 1440, height: 900});
        await page.goto(ORIGIN + '/#users'); await page.waitForTimeout(800);
        const detail = page.locator('[data-action=user-detail]').first();
        if (await detail.count()) {
          await detail.click(); await page.locator('#detail-panel').waitFor();
          await page.locator('[data-tab=usage]').click(); await page.waitForTimeout(700);
          await shot(page, `user-usage-1440-${lang}-${theme}`, {viewport: '1440x900', lang, theme, page: 'User detail · usage chart'});
          await page.evaluate(() => { const d = document.querySelector('#modal'); if (d.open) d.close(); });
        }
        // Portal.
        for (const reset of [false, true]) {
          const p = await ctx.newPage();
          await portalRoutes(p, reset);
          for (const [w, h] of [[2048, 1100], [1280, 900], [390, 844]]) {
            await p.setViewportSize({width: w, height: h});
            await p.goto(ORIGIN + '/portal', {waitUntil: 'domcontentloaded'});
            await p.waitForTimeout(1200);
            await shot(p, `portal-${reset ? 'password' : 'overview'}-${w}-${lang}-${theme}`, {viewport: `${w}x${h}`, lang, theme, page: reset ? 'Portal · change initial password' : 'Portal overview', full: !reset});
          }
          await p.close();
        }
        await ctx.close();
      }
    }
  } finally {
    fs.writeFileSync(path.join(out, 'index.json'), JSON.stringify({fixture: true, note: 'Synthetic fixture data; not a live deployment.', shots}, null, 1));
    await browser.close();
    child.kill();
  }
})().catch(e => { console.error(e); process.exit(1); });
