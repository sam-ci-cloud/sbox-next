// Real installed panel in the lab VM with real accounting data. LAB ONLY.
const {chromium} = require('playwright'); const fs = require('fs'), path = require('path');
const [origin, pwFile, newPwFile, out, userName] = process.argv.slice(2);
const pw = fs.readFileSync(pwFile, 'utf8').match(/Password:\s*(\S+)/)[1];
let newPw = fs.existsSync(newPwFile) ? fs.readFileSync(newPwFile, 'utf8').trim() : null;
(async () => {
  const browser = await chromium.launch({args: ['--host-resolver-rules=MAP lab.sbox.test 10.77.0.2', '--ignore-certificate-errors']});
  for (const [w, h, lang] of [[1440, 900, 'en'], [390, 844, 'zh'], [1440, 900, 'zh']]) {
    const ctx = await browser.newContext({viewport: {width: w, height: h}, ignoreHTTPSErrors: true}); const page = await ctx.newPage();
    await page.goto(origin + '/'); await page.locator('#login-form input[name=username]').fill('admin');
    await page.locator('#login-form input[name=password]').fill(newPw || pw); await page.locator('#login-submit').click();
    await page.waitForTimeout(1500);
    if (await page.locator('#password-form').isVisible()) {
      newPw = 'Lab-' + require('crypto').randomBytes(12).toString('hex'); fs.writeFileSync(newPwFile, newPw, {mode: 0o600});
      const inputs = page.locator('#password-form input[type=password]'); const n = await inputs.count();
      await inputs.nth(0).fill(pw); for (let i = 1; i < n; i++) await inputs.nth(i).fill(newPw);
      await page.locator('#password-form button[type=submit]').click(); await page.waitForTimeout(2000);
    }
    await page.locator('#shell').waitFor({state: 'visible', timeout: 20000});
    await page.selectOption('#lang', lang).catch(() => {}); await page.waitForTimeout(400);
    await page.goto(origin + '/#overview'); await page.waitForTimeout(2500);
    await page.screenshot({path: path.join(out, `real-overview-${w}-${lang}.png`), fullPage: w > 400});
    await page.goto(origin + '/#users'); await page.waitForTimeout(2000);
    await page.screenshot({path: path.join(out, `real-users-${w}-${lang}.png`)});
    const row = page.locator('tr, .user-card', {hasText: userName}).locator('[data-action=user-detail]').first();
    await row.click(); await page.locator('#detail-panel').waitFor();
    await page.locator('[data-tab=usage]').click(); await page.waitForTimeout(1500);
    await page.selectOption('#detail-history-picker select[name=window]', '24h').catch(() => {}); await page.waitForTimeout(2000);
    await page.screenshot({path: path.join(out, `real-usage-24h-${w}-${lang}.png`)});
    await page.locator('[data-tab=overview]').click(); await page.waitForTimeout(1200);
    await page.screenshot({path: path.join(out, `real-detail-overview-${w}-${lang}.png`)});
    await ctx.close();
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
