/* LAB ONLY: Chromium visits the public REALITY port inside the isolated
   namespace started by lab_reality_fallback.py. The lab leaf is accepted only
   through an exact SPKI pin (no blanket certificate bypass).
   node lab_reality_browser.cjs SPKI_SHA256_BASE64 OUTDIR REALITY_PORT */
const {chromium} = require('playwright');
const fs = require('fs'), path = require('path');
const [spki, out, port] = process.argv.slice(2);
(async () => {
  const browser = await chromium.launch({args: ['--no-proxy-server', '--host-resolver-rules=MAP cloud.sbox.test 127.0.0.1, MAP * ~NOTFOUND', `--ignore-certificate-errors-spki-list=${spki}`]});
  const results = [];
  try {
    const page = await browser.newPage({viewport: {width: 1280, height: 860}});
    for (const p of ['/', '/files/', '/media/', '/about/']) {
      const response = await page.goto(`https://cloud.sbox.test:${port}` + p, {waitUntil: 'load'});
      const marker = await page.locator('meta[name=generator][content=sbox-personal-cloud]').count();
      const title = await page.title();
      const security = await response.securityDetails();
      results.push({path: p, status: response.status(), title, marker, subject: security && security.subjectName});
      await page.screenshot({path: path.join(out, 'reality-relay' + p.replace(/\//g, '_') + '.png'), fullPage: true});
    }
  } finally { await browser.close(); }
  fs.writeFileSync(path.join(out, 'reality-browser.json'), JSON.stringify(results, null, 1));
  const ok = results.length === 4 && results.every(r => r.status === 200 && r.marker === 1 && r.subject === 'cloud.sbox.test');
  console.log(JSON.stringify(results));
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
