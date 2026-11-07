/* Native-browser negative controls for the audit itself. All pages below are
   synthetic fixtures, not application, deployment, VPN or firewall evidence. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const run = promisify(execFile);
const modes = ['healthy', 'overflow', 'contrast', 'unnamed', 'runtime-error'];
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sbox-audit-gate-'));
function html(mode) {
  const badWidth = mode === 'overflow' ? 'width:1400px;' : '';
  const badColor = mode === 'contrast' ? 'color:rgb(180,180,180);' : '';
  return `<!doctype html><html><head><meta charset="utf-8"><title>Labelled audit fixture</title>
<style>*{box-sizing:border-box}body{margin:16px;color:#000;background:#fff;font:16px Arial}button,input{min-width:48px;min-height:48px}p{${badWidth}${badColor}}</style></head><body>
<form id="login-form"><input name="username" aria-label="Username"><input name="password" type="password" aria-label="Password"><button type="submit">Sign in</button></form>
<div id="shell" hidden><main id="content"><p>This is a synthetic page used only to test the layout audit.</p><button${mode === 'unnamed' ? '' : ' aria-label="Continue"'}>${mode === 'unnamed' ? '' : 'Continue'}</button></main></div>
<script>document.querySelector('form').onsubmit=e=>{e.preventDefault();document.querySelector('form').hidden=true;document.querySelector('#shell').hidden=false;${mode === 'runtime-error' ? "setTimeout(()=>{throw new Error('Intentional audit negative control')},0);" : ''}}</script></body></html>`;
}
(async () => {
  let checks = 0;
  try {
    for (const mode of modes) {
      const url = 'https://sbox-fixture.invalid/';
      const fixture = path.join(root, mode + '.html');fs.writeFileSync(fixture, html(mode));
      let code = 0, diagnostic = "";
      try {
        await run(process.execPath, [process.env.SBOX_AUDIT_SCRIPT || path.join(__dirname, 'ui_audit.cjs'), url, root, mode,
          '--fixture-html', fixture,
          '--pages', 'overview', '--widths', '390', '--langs', 'en', '--themes', 'light'], {timeout: 45000, env: process.env});
      } catch (error) {
        if (typeof error.code !== 'number') throw error;
        code = error.code; diagnostic = error.stderr || error.stdout || error.message;
      }
      assert.ok(fs.existsSync(path.join(root, mode + '-audit.json')), diagnostic || 'Audit report missing');
      const report = JSON.parse(fs.readFileSync(path.join(root, mode + '-audit.json'), 'utf8'));
      assert.equal(report.summary.runs, 1, 'Exactly one audit cell must execute');
      if (mode === 'healthy') {
        assert.equal(code, 0, 'A healthy page must pass');
        assert.equal(report.summary.passed, true);
      } else {
        assert.notEqual(code, 0, `${mode}: detected defects must fail the process, not only appear in a report`);
        const field = {overflow: 'overflowRuns', contrast: 'contrastFailures', unnamed: 'axMissing', 'runtime-error': 'pageErrors'}[mode];
        assert.ok(report.summary[field] > 0, `${mode}: the intended defect must actually be detected`);
        assert.equal(report.summary.passed, false);
      }
      checks++;
    }
    console.log(JSON.stringify({fixture: true, scope: 'UI audit negative controls with actual browser pages', cases: checks, passed: true}));
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
})().catch(error => {console.error(error.stack || error.message);process.exitCode = 1;});
