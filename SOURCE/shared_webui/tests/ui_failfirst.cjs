/* Fail-first UI checks that use only behaviour common to the baseline and new
   UI, so the SAME assertions can run against both frontends.
   node ui_failfirst.cjs ORIGIN OUTDIR LABEL */
const {chromium} = require('playwright');
const fs = require('fs');
const path = require('path');
const [origin, out, label] = process.argv.slice(2);
fs.mkdirSync(out, {recursive: true});
const rows = [];
async function check(id, name, fn) {
  try { const ev = await fn(); rows.push({id, name, status: ev.pass ? 'PASS' : 'FAIL', evidence: ev.evidence}); }
  catch (e) { rows.push({id, name, status: 'FAIL', evidence: 'error: ' + String(e.message).slice(0, 300)}); }
  console.log(rows.at(-1).status, id, rows.at(-1).evidence);
}
(async () => {
  const browser = await chromium.launch({executablePath:process.env.SBOX_BROWSER_EXE,args: ['--no-proxy-server','--no-sandbox', '--host-resolver-rules=MAP ' + new URL(origin).hostname + ' 127.0.0.1']});
  async function session(viewport, theme = 'dark') {
    const c = await browser.newContext({ignoreHTTPSErrors: true, viewport, colorScheme: theme});
    await c.addInitScript(t => { localStorage.setItem('sbox-theme', t); localStorage.setItem('sbox-lang', 'en'); }, theme);
    const p = await c.newPage();
    await p.goto(origin);
    await p.locator('#login-form input[name=password]').fill('Fixture-admin-password-2026');
    await p.locator('#login-form button').first().click();
    await p.locator('#shell').waitFor({state: 'visible'});
    await p.waitForTimeout(1500);
    return {c, p};
  }
  const only = process.argv[5];
  const skip = id => only && !only.split(',').includes(id);
  if (!skip('FF-MOBILE-ACTIONS')) await check('FF-MOBILE-ACTIONS', '390px Users: every user row action is inside the viewport', async () => {
    const {c, p} = await session({width: 390, height: 844});
    await p.evaluate(() => { location.hash = 'users'; }); await p.waitForTimeout(1500);
    const r = await p.evaluate(() => {
      const btns = [...document.querySelectorAll('#content tbody button, #content tbody summary')].filter(b => b.offsetParent);
      const outside = btns.filter(b => { const r = b.getBoundingClientRect(); return r.right > innerWidth || r.left < 0; });
      return {buttons: btns.length, outside: outside.length};
    });
    await p.screenshot({path: path.join(out, label + '-users-390-actions.png')});
    await c.close();
    return {pass: r.buttons > 0 && r.outside === 0, evidence: JSON.stringify(r)};
  });
  if (!skip('FF-SKIP-LINK')) await check('FF-SKIP-LINK', 'Skip link keeps the current page', async () => {
    const {c, p} = await session({width: 1280, height: 900});
    await p.evaluate(() => { location.hash = 'users'; }); await p.waitForTimeout(1500);
    await p.reload(); await p.locator('#shell').waitFor(); await p.waitForTimeout(1500);
    await p.keyboard.press('Tab'); await p.keyboard.press('Enter'); await p.waitForTimeout(1200);
    const r = await p.evaluate(() => ({hash: location.hash, title: document.querySelector('#title').textContent}));
    await c.close();
    return {pass: /users/i.test(r.title), evidence: JSON.stringify(r)};
  });
  if (!skip('FF-POLL-FOCUS')) await check('FF-POLL-FOCUS', 'Overview auto-refresh keeps scroll position and keyboard focus', async () => {
    const {c, p} = await session({width: 1280, height: 600});
    await p.evaluate(() => { location.hash = 'overview'; }); await p.waitForTimeout(1500);
    const target = p.locator('#content button, #content summary');
    const hasTarget = await target.count();
    if (hasTarget) await target.first().focus();
    await p.evaluate(() => window.scrollTo(0, 400)); await p.waitForTimeout(300);
    const before = await p.evaluate(() => ({y: Math.round(scrollY), focus: document.activeElement.outerHTML.slice(0, 60)}));
    await p.waitForTimeout(33000);
    const after = await p.evaluate(() => ({y: Math.round(scrollY), focus: document.activeElement.outerHTML.slice(0, 60)}));
    await c.close();
    return {pass: before.y > 0 && Math.abs(before.y - after.y) < 5 && before.focus === after.focus, evidence: JSON.stringify({before, after, focusable: hasTarget})};
  });
  if (!skip('FF-LIGHT-CONTRAST')) await check('FF-LIGHT-CONTRAST', 'Light theme secondary text meets 4.5:1', async () => {
    const {c, p} = await session({width: 1280, height: 900}, 'light');
    if ((await p.locator('html').getAttribute('data-theme')) !== 'light') { await p.locator('#theme').click(); await p.waitForTimeout(300); }
    const r = await p.evaluate(() => {
      const parse = s => s.match(/[\d.]+/g).map(Number);
      const lin = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
      const L = c => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]);
      const worst = [];
      for (const el of document.querySelectorAll('#content *')) {
        if (!el.childNodes.length || ![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
        const r = el.getBoundingClientRect(); if (!r.width) continue;
        let bg = null; for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c.length < 4 || c[3] > 0.9) { bg = c; break; } }
        const fg = parse(getComputedStyle(el).color); const ratio = (Math.max(L(fg), L(bg)) + 0.05) / (Math.min(L(fg), L(bg)) + 0.05);
        const size = parseFloat(getComputedStyle(el).fontSize); const need = size >= 24 ? 3 : 4.5;
        if (ratio < need) worst.push(Math.round(ratio * 100) / 100);
      }
      return {failing: worst.length, min: worst.length ? Math.min(...worst) : null};
    });
    await c.close();
    return {pass: r.failing === 0, evidence: JSON.stringify(r)};
  });
  if (!skip('FF-SUCCESS-TEXT')) await check('FF-SUCCESS-TEXT', 'Committed change message names the result (not a generic success)', async () => {
    const {c, p} = await session({width: 1280, height: 900});
    await p.evaluate(() => { location.hash = 'users'; }); await p.waitForTimeout(1500);
    await p.locator('[data-action=create-user], [data-action="user-create"]').first().click();
    await p.locator('#user-form input[name=name]').fill('ff-' + Date.now().toString(36));
    await p.locator('#user-form button').last().click();
    await p.locator('[data-action=commit], [data-action=commit-change]').first().waitFor({timeout: 30000});
    await p.locator('[data-action=commit], [data-action=commit-change]').first().click();
    await p.waitForTimeout(2500);
    const text = await p.evaluate(() => [...document.querySelectorAll('#toast, .toast')].map(t => t.textContent).join(' | '));
    await c.close();
    return {pass: /verified/i.test(text) && /version/i.test(text), evidence: text.slice(0, 200)};
  });
  fs.writeFileSync(path.join(out, label + '-failfirst.json'), JSON.stringify(rows, null, 1));
  await browser.close();
})();
