/* Portal device choices and honest compatibility guidance. These deterministic
   DOM/HTTP fixtures do not establish real client compatibility or VPN traffic. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
// Reuse the existing lightweight DOM harness without running its test cases.
const lifecycle = fs.readFileSync(path.join(__dirname, 'test_portal_lifecycle.cjs'), 'utf8');
const marker = 'const tests = {';
assert.ok(lifecycle.includes(marker), 'lifecycle harness boundary must be explicit');
const environment = new Function('require', '__dirname', lifecycle.split(marker)[0] + '\nreturn environment;')(require, __dirname);

const tests = {
  // Device/format pickers were replaced by the shared Export Center (test_connect_intents.cjs, test_connect_browser.cjs).
  'plain status explains next action, expiry and administrator support'() {
    const e = environment();
    e.run("current.status='manually_disabled';current.expires_at=123456");
    assert.match(e.run('serviceAdvice()'), /administrator paused/);
    assert.match(e.run('heading()'), /Service ends on/);
    assert.match(e.run('heading()'), /administrator who gave you this login/);
    e.run("current.status='active'"); assert.match(e.run('serviceAdvice()'), /does not show a live device connection/);
    e.run("lang='zh';current.status='expired'"); assert.match(e.run('serviceAdvice()'), /聯絡管理員續期/);
  },
  'missing usage copy is friendly without converting missing data into zero'() {
    const e = environment();
    e.context.copy = 'Partial coverage · measured lower bound. Before local history collection. 部分觀測 · 實測下限';
    const text = e.run('friendlyUsage(copy)');
    assert.match(text, /actual usage may be higher/); assert.match(text, /實際用量可能較多/);
    assert.doesNotMatch(text, /lower bound|collection|實測下限/);
  },
};
let failed = 0;
for (const [name, test] of Object.entries(tests)) {
  try { test(); console.log('PASS', name); } catch (error) { failed++; console.error('FAIL', name, error.stack); }
}
console.log(`${Object.keys(tests).length - failed}/${Object.keys(tests).length} device regressions passed; fixtures, NOT real client acceptance.`);
process.exitCode = failed ? 1 : 0;
