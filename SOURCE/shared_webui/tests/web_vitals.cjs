/* Web vitals for the panel from the browser's own Performance APIs (Playwright Chromium).

   node web_vitals.cjs ORIGIN OUT.json --password P [--label L] [--runs 5] [--ignore-tls]

   FCP/LCP: PerformanceObserver 'paint' / 'largest-contentful-paint' (buffered) after sign-in,
            measured on a cold navigation (new context, empty cache) and a warm reload.
   CLS:     sum of 'layout-shift' entries without recent input across overview -> users -> traffic,
            including the background poll re-render.
   INP:     Event Timing API ('event', durationThreshold 16): the longest interaction duration
            over real clicks on navigation, a filter and typing in the user search.
   Also: transferred bytes and request count for the app shell. Hardware context is recorded. */
const {chromium} = require('playwright');
const fs = require('fs'); const os = require('os');
const [origin, out, ...rest] = process.argv.slice(2);
const opt = (k, d) => { const i = rest.indexOf(k); return i >= 0 ? rest[i + 1] : d; };
const PASSWORD = opt('--password'); const LABEL = opt('--label', 'panel'); const RUNS = Number(opt('--runs', 5));
const insecure = rest.includes('--ignore-tls');
const median = a => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor((s.length - 1) / 2)] : null; };
const p95 = a => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.min(s.length - 1, Math.ceil(0.95 * s.length) - 1)] : null; };

const OBS = () => {
  window.__v = {cls: 0, lcp: 0, fcp: 0, inp: 0, events: []};
  new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__v.cls += e.value; }).observe({type: 'layout-shift', buffered: true});
  new PerformanceObserver(l => { for (const e of l.getEntries()) window.__v.lcp = Math.max(window.__v.lcp, e.renderTime || e.loadTime || e.startTime); }).observe({type: 'largest-contentful-paint', buffered: true});
  new PerformanceObserver(l => { for (const e of l.getEntries()) if (e.name === 'first-contentful-paint') window.__v.fcp = e.startTime; }).observe({type: 'paint', buffered: true});
  new PerformanceObserver(l => { for (const e of l.getEntries()) if (e.interactionId) { window.__v.inp = Math.max(window.__v.inp, e.duration); window.__v.events.push([e.name, Math.round(e.duration)]); } }).observe({type: 'event', buffered: true, durationThreshold: 16});
};

async function settled(page) {
  await page.waitForFunction(() => { const c = document.querySelector('#content'); return c && !c.querySelector('[aria-busy=true]') && c.textContent.trim().length > 20; }, null, {timeout: 45000});
}

(async () => {
  const browser = await chromium.launch({executablePath:process.env.SBOX_BROWSER_EXE,args:process.env.SBOX_BROWSER_MAP?['--no-proxy-server','--host-resolver-rules='+process.env.SBOX_BROWSER_MAP]:['--no-proxy-server']});
  const cold = [], warm = [], shell = [];
  let cookies = null;
  // Sign in once; reuse the session cookie for measured navigations.
  {
    const c = await browser.newContext({ignoreHTTPSErrors: insecure}); const p = await c.newPage();
    await p.goto(origin, {waitUntil: 'domcontentloaded'});
    await p.locator('#login-form input[name=username]').fill('admin'); await p.locator('#login-form input[name=password]').fill(PASSWORD);
    await p.locator('#login-form button[type=submit]').click(); await p.locator('#shell').waitFor({state: 'visible', timeout: 30000}); cookies = await c.cookies(); await c.close();
  }
  for (let i = 0; i < RUNS; i++) {
    const c = await browser.newContext({ignoreHTTPSErrors: insecure, viewport: {width: 1440, height: 900}}); await c.addCookies(cookies); await c.addInitScript(OBS);
    const p = await c.newPage();
    const t0 = Date.now(); await p.goto(origin + '/#overview', {waitUntil: 'load'}); await settled(p); const ready = Date.now() - t0;
    await p.waitForTimeout(500);
    const v = await p.evaluate(() => ({fcp: window.__v.fcp, lcp: window.__v.lcp, nav: performance.getEntriesByType('navigation')[0].toJSON(),
      res: performance.getEntriesByType('resource').map(r => ({n: r.name.split('/').pop().split('?')[0], t: r.transferSize, d: Math.round(r.duration)}))}));
    cold.push({fcp: v.fcp, lcp: v.lcp, overview_ready_ms: ready, ttfb: v.nav.responseStart, dcl: v.nav.domContentLoadedEventEnd});
    if (i === 0) shell.push({document_bytes: v.nav.transferSize, requests: v.res.length + 1, transferred_bytes: v.nav.transferSize + v.res.reduce((a, r) => a + r.t, 0), resources: v.res});
    const t1 = Date.now(); await p.reload({waitUntil: 'load'}); await settled(p); const wready = Date.now() - t1; await p.waitForTimeout(300);
    const w = await p.evaluate(() => ({fcp: window.__v.fcp, lcp: window.__v.lcp}));
    warm.push({fcp: w.fcp, lcp: w.lcp, overview_ready_ms: wready});
    await c.close();
  }
  // CLS + INP over a realistic session, including one background poll.
  const c = await browser.newContext({ignoreHTTPSErrors: insecure, viewport: {width: 1440, height: 900}}); await c.addCookies(cookies); await c.addInitScript(OBS);
  const p = await c.newPage(); await p.goto(origin + '/#overview', {waitUntil: 'load'}); await settled(p);
  for (const route of ['users', 'traffic', 'health', 'overview', 'users']) {
    const link = p.locator(`#nav a[href="#${route}"]`); if (!(await link.count())) continue;
    const group=link.locator('xpath=ancestor::details');if(await group.count() && !(await group.evaluate(d=>d.open)))await group.locator('summary').first().click();  // older UI may lack a page
    await link.click(); await settled(p);
  }
  const search = p.locator('#user-search');
  if (await search.count()) { await search.click(); await p.keyboard.type('user-1', {delay: 40}); await p.waitForTimeout(400); await search.fill(''); }
  const status = p.locator('#content select').first(); if (await status.count()) { await status.click(); await p.keyboard.press('Escape'); }
  await p.waitForTimeout(6000); // one background poll
  const session = await p.evaluate(() => ({cls: window.__v.cls, inp: window.__v.inp, interactions: window.__v.events.length, worst: window.__v.events.sort((a, b) => b[1] - a[1]).slice(0, 5)}));
  await c.close(); await browser.close();
  const result = {label: LABEL, origin_host: new URL(origin).hostname, hardware: {cpus: os.cpus().length, cpu_model: os.cpus()[0].model, mem_gib: Math.round(os.totalmem() / 2 ** 30), browser: 'Playwright Chromium, no CPU/network throttling'},
    runs: RUNS, cold: {fcp_ms_median: median(cold.map(x => x.fcp)), lcp_ms_median: median(cold.map(x => x.lcp)), lcp_ms_p95: p95(cold.map(x => x.lcp)), overview_ready_ms_median: median(cold.map(x => x.overview_ready_ms)), ttfb_ms_median: median(cold.map(x => x.ttfb)), samples: cold},
    warm: {fcp_ms_median: median(warm.map(x => x.fcp)), lcp_ms_median: median(warm.map(x => x.lcp)), overview_ready_ms_median: median(warm.map(x => x.overview_ready_ms))},
    session: session, shell: shell[0]};
  fs.writeFileSync(out, JSON.stringify(result, null, 1));
  console.log(JSON.stringify({label: LABEL, fcp: result.cold.fcp_ms_median, lcp: result.cold.lcp_ms_median, cls: session.cls, inp: session.inp, bytes: result.shell.transferred_bytes}));
})().catch(e => { console.error(e); process.exit(1); });
