/* Real installed panel in a real browser (lab client namespace; never production).

   node real_panel_browser.cjs ORIGIN OUTDIR --password BOOTSTRAP_PASSWORD [--variant zgocloud|universal]

   First login with the root-only generated credential, the forced password
   change, every page at desktop and phone width (screenshots), a real user
   creation through the UI with server-validated impact preview, and a check that
   no fixture data is shown. TLS: the panel uses a disposable lab CA that this
   Chromium profile does not trust, so certificate errors are ignored here; the
   same certificate (chain + hostname) is fully verified by lab_post_install.py. */
const {chromium} = require('playwright');
const fs = require('fs');
const path = require('path');

const [origin, out, ...rest] = process.argv.slice(2);
const opt = (k, d) => { const i = rest.indexOf(k); return i >= 0 ? rest[i + 1] : d; };
const BOOT = opt('--password',process.env.SBOX_TEST_PASSWORD); const VARIANT = opt('--variant', 'zgocloud');
const NEWPW = 'Browser-' + Math.random().toString(36).slice(2) + '-Lab-2026';
const ROUTES = ['overview', 'monitor', 'users', 'subscriptions', 'inbounds', 'policy', 'alerts', 'health', 'traffic', 'logs', 'certificates', 'security', 'access', 'updates', 'settings', 'audit', 'api'];
fs.mkdirSync(out, {recursive: true});
const results = [];
async function test(id, name, fn) {
  try { const ev = await fn(); results.push({id, name, status: 'PASS', evidence: ev || ''}); console.log('PASS', id, name, String(ev || '').slice(0, 200)); }
  catch (e) { results.push({id, name, status: 'FAIL', evidence: String(e.message || e).slice(0, 400)}); console.log('FAIL', id, name, String(e.message || e).slice(0, 300)); }
}
const assert = (c, m) => { if (!c) throw new Error(m); };
async function settled(page) {
  await page.waitForFunction(() => { const c = document.querySelector('#content'); return c && !c.querySelector('[aria-busy=true]') && c.textContent.trim().length > 20; }, null, {timeout: 45000});
}
async function go(page, hash) {
  await page.evaluate(h => { location.hash = h; }, hash);
  await page.waitForFunction(h => document.querySelector(`#nav a[href="#${h}"][aria-current=page]`), hash, {timeout: 10000}).catch(() => {});
  await settled(page);
}

(async () => {
  const browser = await chromium.launch({executablePath:process.env.SBOX_BROWSER_EXE,args:process.env.SBOX_BROWSER_MAP?['--no-proxy-server','--host-resolver-rules='+process.env.SBOX_BROWSER_MAP]:['--no-proxy-server']});
  const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1440, height: 900}});
  const page = await ctx.newPage();
  const errors = [], failed = []; let preLogin = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') if(!/status of (401|403)/.test(m.text()))errors.push('console: ' + m.text()); });
  page.on('response', async r => { if (r.status() >= 500){failed.push(r.status()+' '+r.url().split('?')[0]);try{console.log('API-ERROR',new URL(r.url()).pathname,(await r.json()).error)}catch{}} if(r.url().endsWith('/api/v1/changes/commit')){try{const v=await r.json();console.log('COMMIT-RESPONSE',r.status(),Object.keys(v),Boolean(v.onboarding));}catch{}} });

  await test('REAL-FIRST-LOGIN', 'Generated credential signs in and the password change is required first', async () => {
    await page.goto(origin, {waitUntil: 'domcontentloaded'});
    await page.locator('#login-form').waitFor();
    await page.screenshot({path: path.join(out, 'real-login-desktop.png')});
    await page.locator('#login-form input[name=username]').fill('admin');
    await page.locator('#login-form input[name=password]').fill(BOOT);
    await page.locator('#login-submit').click();
    await page.locator('#password-form:not([hidden])').waitFor({timeout: 20000});
    await page.screenshot({path: path.join(out, 'real-password-change.png')});
    await page.locator('#password-form input[name=old]').fill(BOOT);
    await page.locator('#password-form input[name=password]').fill(NEWPW);
    await page.locator('#pw-confirm').fill(NEWPW);
    await page.locator('#pw-submit').click();
    await page.locator('#shell').waitFor({state: 'visible', timeout: 20000});
    await settled(page);
    // The signed-out session probe (GET /auth/me -> 401) on the sign-in page is expected.
    preLogin = errors.splice(0).filter(e => !/status of 401/.test(e)); errors.push(...preLogin);
    return 'password changed in the UI';
  });

  await test('REAL-NO-FIXTURE', 'Real installation: no fixture banner or fixture data anywhere', async () => {
    const t = await page.locator('body').innerText();
    assert(!/FIXTURE/i.test(t), 'fixture text visible');
    return 'no fixture marker';
  });

  await test('REAL-OVERVIEW', 'Overview reflects the real bridge: core, listeners, certificate; external path not claimed', async () => {
    const t = await page.locator('#content').innerText();
    assert(/Internet reachability[\s\S]{0,40}Not tested/.test(t), 'external reachability must read "Not tested"');
    assert(/VPN core[\s\S]{0,40}Running/.test(t), 'core not reported running');
    await page.screenshot({path: path.join(out, 'real-overview-desktop.png'), fullPage: true});
    return t.split('\n').slice(0, 6).join(' | ');
  });

  for (const r of ROUTES) {
    await test('REAL-PAGE-' + r.toUpperCase(), 'Page renders from real data: ' + r, async () => {
      await go(page, r);
      const t = await page.locator('#content').innerText();
      assert(t.trim().length > 40, 'empty page');
      assert(!/Traceback|undefined|NaN|\[object Object\]/.test(t), 'raw error text: ' + (t.match(/Traceback|undefined|NaN|\[object Object\]/) || [''])[0]);
      await page.screenshot({path: path.join(out, `real-${r}-desktop.png`), fullPage: true});
      return t.replace(/\s+/g, ' ').slice(0, 120);
    });
  }

  let created = '';
  await test('REAL-UI-USER-CREATE', 'Create a user through the UI: impact preview, reauth, real commit, row appears', async () => {
    await go(page, 'users');
    created = 'browser-' + Date.now().toString(36);
    await page.locator('[data-action=user-create]').first().click();
    await page.locator('#new-user-wizard input[name=name]').fill(created);
    await page.locator('[data-action=wizard-next]').click();
    await page.locator('#new-user-wizard input[name=quota_bytes]').fill('5 GiB');
    await page.locator('[data-action=wizard-next]').click();
    await page.locator('#new-user-wizard button[type=submit]').click();
    await page.locator('[data-action=commit-change], #reauth-form').first().waitFor({timeout: 60000});
    if (await page.locator('#reauth-form').isVisible().catch(() => false)) {
      await page.locator('#reauth-form input[name=password]').fill(NEWPW);
      await page.locator('#reauth-form button[type=submit]').click();
      await page.locator('[data-action=commit-change]').waitFor({timeout: 60000});
    }
    const review = await page.locator('#modal-body').innerText();
    if (VARIANT === 'zgocloud') assert(/Protected original identity[\s\S]*Unchanged/.test(review), 'protected identity not shown as unchanged');
    await page.screenshot({path: path.join(out, 'real-change-preview.png')});
    await page.locator('[data-action=commit-change]').click();
    await page.locator('#onboarding-links').waitFor({timeout: 45000}).catch(async e=>{throw new Error('Onboarding missing: '+(await page.locator('#toast-status').innerText()).slice(0,300)+'; '+JSON.stringify({errors,failed}).slice(0,250))});
    const links = await page.locator('#onboarding-links input').evaluateAll(xs => xs.map(x => x.value));
    assert(links.length === 3 && links.every(x => /\/sub\/.+\/(global|cn|internal)\.yaml$/.test(x)), 'three private subscription profiles provisioned');
    for(let i=0;i<links.length;i++){const response=await page.evaluate(async url=>{const r=await fetch(url);return {status:r.status,yaml:await r.text()}},links[i]);assert(response.status===200,'new subscription resolves');assert(response.yaml.includes('proxies:'),'new profile YAML');if(process.env.SBOX_PRIVATE_PROFILE_DIR){fs.mkdirSync(process.env.SBOX_PRIVATE_PROFILE_DIR,{recursive:true,mode:0o700});fs.writeFileSync(path.join(process.env.SBOX_PRIVATE_PROFILE_DIR,'profile-'+i+'.yaml'),response.yaml,{mode:0o600})}}
    await page.screenshot({path: path.join(out, 'real-user-onboarding.png'), mask:[page.locator('#onboarding-links')]} );
    await page.locator('#modal [data-close]').last().click();
    await page.locator('#modal').waitFor({state: 'hidden', timeout: 10000});
    const toast = await page.locator('#toast-status .toast').last().innerText();
    assert(/Committed and verified by the manager/.test(toast), toast);
    await page.locator('#user-search').fill(created);
    await page.locator(`td.name-cell strong:text-is("${created}")`).waitFor({timeout: 20000});
    const visibleUserRows = await page.locator('#content td.name-cell strong').allTextContents();
    assert(visibleUserRows.some(x => x.trim() === created), 'created user row is visible in filtered results');
    await page.screenshot({path: path.join(out, 'real-users-after-create.png')});
    await page.locator('#user-search').fill('');
    return toast.replace(/\n/g, ' ');
  });

  if (VARIANT === 'zgocloud') await test('REAL-PROTECTED-ROW', 'Original shared identity row is locked in the UI', async () => {
    await go(page, 'users');
    await page.locator('#user-search').fill('');
    await page.waitForFunction(() => /Legacy shared identity[\s\S]*Protected/.test(document.querySelector('#content').innerText), null, {timeout: 10000}).catch(() => {});
    const t = await page.locator('#content').innerText();
    assert(/Legacy shared identity[\s\S]*Protected/.test(t), 'no protected marker');
    const row = page.locator('tr:has-text("Legacy shared identity")');
    assert(await row.locator('input[type=checkbox]').count() === 0, 'protected row is selectable for bulk actions');
    assert(await row.locator('text=More').count() === 0, 'protected row offers edit/revoke menu');
    await page.screenshot({path: path.join(out, 'real-users-protected-row.png')});
    return 'protected marker shown';
  });

  await test('REAL-MOBILE', 'Phone width (390x844): navigation drawer, no horizontal overflow on any page', async () => {
    const m = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 390, height: 844}, isMobile: true, hasTouch: true, deviceScaleFactor: 2});
    await m.addCookies(await ctx.cookies());
    const p = await m.newPage(); p.on('pageerror', e => errors.push('mobile: ' + e.message));
    await p.goto(origin + '/#overview', {waitUntil: 'domcontentloaded'});
    await p.locator('#shell').waitFor({state: 'visible', timeout: 20000}); await settled(p);
    const bad = [];
    for (const r of ROUTES) {
      await go(p, r);
      const over = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (over > 1) bad.push(r + ':' + over);
      if (['overview', 'users', 'health', 'alerts', 'traffic', 'logs'].includes(r)) await p.screenshot({path: path.join(out, `real-${r}-mobile.png`), fullPage: true});
    }
    await m.close();
    assert(!bad.length, 'overflow ' + bad.join(','));
    return 'no overflow on ' + ROUTES.length + ' pages';
  });

  await test('QUOTA-DRAWER','Usage drawer shows actual usage, quota plan and distinct portal controls',async()=>{
    await go(page,'users');await page.locator('[data-action=user-detail]').first().click();
    await page.locator('#quota-form').waitFor();const text=await page.locator('#modal-body').innerText();assert(/Measured this cycle/.test(text),'No measured usage');assert(/Usage-only portal/.test(text),'No portal controls');await page.screenshot({path:path.join(out,'actual-user-quota-drawer.png'),fullPage:true});await page.locator('#modal .close').click();return 'Actual root collector view';
  });
  await test('PORTAL-BROWSER','Separate portal login, own measured usage, all screen sizes and translations',async()=>{
    const pctx=await browser.newContext({ignoreHTTPSErrors:true});const p=await pctx.newPage();p.on('pageerror',e=>errors.push('portal: '+e.message));
    await p.goto(origin+'/portal');await p.locator('#login').waitFor();await p.locator('#username').fill(process.env.SBOX_PORTAL_USERNAME);await p.locator('#password').fill(process.env.SBOX_PORTAL_PASSWORD);await p.locator('#login button').click();await p.locator('#refresh').waitFor({timeout:30000});
    const me=await p.evaluate(async()=>{const r=await fetch('/api/v1/portal/me');return r.json()});assert(me.display_name==='MeterAlice'&&me.used_bytes>0,'Portal is not real own usage');
    const denied=await p.evaluate(async()=>{const r=await fetch('/api/v1/users');return r.status});assert(denied===401||denied===403,'Portal reached admin users');
    for(const width of [320,375,430,768,1280])for(const lang of ['en','zh'])for(const theme of ['dark','light']){
      await p.setViewportSize({width,height:900});await p.evaluate(({lang,theme})=>{localStorage.setItem('sbox-portal-lang',lang);localStorage.setItem('sbox-portal-theme',theme);location.reload()},{lang,theme});await p.locator('#refresh').waitFor();assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Portal horizontal overflow '+width+' '+lang+' '+theme);if(width===320||width===1280)await p.screenshot({path:path.join(out,`portal-${width}-${lang}-${theme}.png`),fullPage:true});
    }
    await pctx.close();return '5 widths × 2 languages × 2 themes; own authenticated counters';
  });
  await test('ADMIN-RESPONSIVE','Admin users and monitoring at 320/375/430/768/1280, bilingual and both themes',async()=>{
    const bad=[];
    for(const width of [320,375,430,768,1280])for(const lang of ['en','zh'])for(const theme of ['dark','light']){
      await page.setViewportSize({width,height:900});await page.evaluate(({lang,theme})=>{localStorage.setItem('sbox-lang',lang);localStorage.setItem('sbox-theme',theme)},{lang,theme});await page.reload();await page.locator('#shell').waitFor({state:'visible'});await settled(page);
      for(const route of ['users','monitor','subscriptions']){await go(page,route);if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))bad.push({width,lang,theme,route});if(width===320||width===1280)await page.screenshot({path:path.join(out,`admin-${route}-${width}-${lang}-${theme}.png`),fullPage:true});}
    }
    assert(!bad.length,JSON.stringify(bad));return '60 page combinations';
  });
  await test('REAL-NO-ERRORS', 'No page errors, console errors or HTTP 5xx during the run', async () => {
    assert(!errors.length && !failed.length, JSON.stringify({errors, failed}).slice(0, 400));
    return 'clean';
  });

  await browser.close();
  fs.writeFileSync(path.join(out, 'real-panel-browser.json'), JSON.stringify({origin, variant: VARIANT, created_user: created, results}, null, 1));
  console.log(JSON.stringify({total: results.length, failed: results.filter(r => r.status !== 'PASS').map(r => r.id)}));
  process.exitCode=results.some(r=>r.status!=='PASS')?1:0;
})();
