/* Chart truthfulness: the production usage chart against synthetic fixtures.
   Empty, one, two, sparse, dense, gaps, all-zero and partial ranges. Checks
   proportional bar heights, stacked upload/download, no fabricated zeros for
   missing data, an honest scale label, totals = sum of known buckets, CSV rows
   identical to the plotted buckets, and quota amounts in the plan's own unit
   family. Not live data. */
const assert = require('assert/strict'), fs = require('fs'), vm = require('vm'), path = require('path');
const source = fs.readFileSync(path.join(__dirname, '../frontend-src/shared/usage.js'), 'utf8');
function load(code) {
  let csv = null;
  const context = {window: {}, document: {addEventListener() {}, createElement: () => ({click() {}})}, Blob: class { constructor(parts) { csv = parts.join(''); } },
    URL: {createObjectURL: () => 'blob:x', revokeObjectURL() {}}, setTimeout: () => 0};
  vm.runInNewContext(code, context);
  return {chart: context.window.SBOXUsage, csv: () => csv};
}
const {chart, csv} = load(source);
const T0 = 1793116800;
function fixture(values) {
  const buckets = values.map((v, i) => ({time: T0 + i * 3600, start: T0 + i * 3600, end: T0 + (i + 1) * 3600,
    up: v === null ? null : v[0], down: v === null ? null : v[1], state: v === null ? 'unobserved' : v[2] || 'recorded'}));
  const known = buckets.filter(b => b.up !== null);
  return {window: 'custom', timezone: 'Asia/Hong_Kong', start: T0, end: T0 + values.length * 3600, oldest_date: '2026-10-01', latest_date: '2026-10-30',
    totals: {upload_bytes: known.length ? known.reduce((s, b) => s + b.up, 0) : null, download_bytes: known.length ? known.reduce((s, b) => s + b.down, 0) : null},
    buckets, incomplete: buckets.some(b => b.state !== 'recorded'), legacy_utc_daily: []};
}
const attr = (html, cls, name) => [...html.matchAll(new RegExp(`class="${cls}" x="[^"]*" y="([\\d.\\-]+)" width="([\\d.]+)" height="([\\d.\\-]+)"`, 'g'))].map(m => ({y: Number(m[1]), w: Number(m[2]), h: Number(m[3])}));
let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log('PASS', name); };

test('empty range renders no bars and dashes, not zero', () => {
  const html = chart.render(fixture([]), 'en');
  assert.equal((html.match(/class="usage-bar"/g) || []).length, 0);
  assert.match(html, /<strong>—<\/strong>/);
  assert.ok(!/NaN|Infinity|undefined/.test(html));
});
test('single point is a narrow centred bar, never a full-width block', () => {
  const html = chart.render(fixture([[100, 300]]), 'en');
  const up = attr(html, 'usage-up')[0], down = attr(html, 'usage-down')[0];
  assert.ok(up.w <= 20 && up.w > 0, 'bounded width ' + up.w);
  assert.ok(Math.abs(up.h + down.h - 150) < 0.01, 'the only (largest) bucket uses the full plot height');
  assert.ok(Math.abs(up.h / down.h - 1 / 3) < 1e-9, 'upload:download proportion preserved');
});
test('two points keep exact proportional heights', () => {
  const html = chart.render(fixture([[100, 100], [300, 500]]), 'en');
  const ups = attr(html, 'usage-up'), downs = attr(html, 'usage-down');
  const totals = ups.map((u, i) => u.h + downs[i].h);
  assert.ok(Math.abs(totals[0] / totals[1] - 200 / 800) < 1e-9);
  assert.ok(Math.abs(downs[1].y - (174 - downs[1].h)) < 1e-9 && Math.abs(ups[1].y - (downs[1].y - ups[1].h)) < 1e-9, 'upload stacked on download from the baseline');
});
test('gaps stay missing: no bar height, an explicit gap marker, excluded from totals', () => {
  const data = fixture([[10, 10], null, null, [20, 20]]);
  const html = chart.render(data, 'en');
  const ups = attr(html, 'usage-up');
  assert.equal(ups[1].h, 0); assert.equal(ups[2].h, 0);
  assert.equal((html.match(/class="usage-gap"/g) || []).length, 2);
  assert.match(html, /Not observed/);
  assert.equal(data.totals.upload_bytes + data.totals.download_bytes, 60);
});
test('sparse and dense ranges stay inside the plot', () => {
  for (const n of [24, 169]) {
    const values = Array.from({length: n}, (_, i) => i % 11 === 0 ? [i * 1000, i * 3000] : null);
    const html = chart.render(fixture(values), 'zh');
    for (const r of [...attr(html, 'usage-up'), ...attr(html, 'usage-down')]) { assert.ok(r.y >= 5 - 1e-9 && r.y + r.h <= 174 + 1e-9, 'inside plot'); }
    assert.ok(!/NaN|Infinity|undefined/.test(html));
  }
});
test('all-zero range is labelled 0, not a fabricated 1 B scale', () => {
  const html = chart.render(fixture([[0, 0], [0, 0]]), 'en');
  assert.match(html, /<span class="usage-scale">0 B<\/span>/);
  assert.equal((html.match(/class="usage-zero"/g) || []).length, 2, 'recorded zero shown as points');
  // Negative control: the base-commit expression produced "1 B" here.
  const base = load(source.replace("${size(buckets.some(b=>(b.up||0)+(b.down||0)>0)?max:0,lang)}", "${size(max===1&&up===null?0:max,lang)}")).chart;
  assert.match(base.render(fixture([[0, 0], [0, 0]]), 'en'), /<span class="usage-scale">1 B<\/span>/);
});
test('partial coverage is labelled as a measured lower bound', () => {
  const html = chart.render(fixture([[5, 5, 'partial']]), 'en');
  assert.match(html, /Partial coverage · measured lower bound/);
});
test('CSV export rows equal the plotted buckets', () => {
  const data = fixture([[1, 2], null, [3, 4, 'partial']]);
  chart.download(data);
  const rows = csv().split('\r\n').map(r => r.split(',').map(x => x.replace(/^"|"$/g, '')));
  assert.deepEqual(rows[0], ['start_utc', 'end_utc', 'timezone', 'upload_bytes', 'download_bytes', 'coverage']);
  assert.deepEqual(rows.slice(1).map(r => [r[3], r[4], r[5]]), [['1', '2', 'recorded'], ['', '', 'unobserved'], ['3', '4', 'partial']]);
});
test('quota amounts use the plan unit family (no 465.7 GiB beside a 500 GB plan)', () => {
  assert.equal(chart.quotaSize(500e9, 500e9, 'en'), '500 GB');
  assert.equal(chart.quotaSize(250e9, 500e9, 'en'), '250 GB');
  assert.equal(chart.quotaSize(100 * 2 ** 30, 100 * 2 ** 30, 'en'), '100 GiB');
  assert.equal(chart.quotaSize(50 * 2 ** 30, 100 * 2 ** 30, 'en'), '50 GiB');
  assert.equal(chart.quotaFamily(10e9), 'decimal'); assert.equal(chart.quotaFamily(2 ** 40), 'binary'); assert.equal(chart.quotaFamily(0), 'decimal');
  assert.equal(chart.quotaSize(null, 1e9, 'en'), '—');
  assert.notEqual(chart.size(500e9, 'en'), '500 GB', 'the generic binary formatter differs, which is why quotas use quotaSize');
});
test('chart totals, scale and tooltips use the plan unit family and say which', () => {
  const data = fixture([[100e9, 150e9], [50e9, 200e9]]);
  const gb = chart.render(data, 'en', {limit: 500e9});
  assert.match(gb, /<strong>500 GB<\/strong>/); assert.ok(!/GiB/.test(gb.replace(/1 GiB = [\d,]+ bytes/, '')), 'no GiB beside a GB plan');
  assert.match(gb, /1 GB = 1,000,000,000 bytes/);
  const gib = chart.render(fixture([[2 ** 30, 2 ** 31]]), 'en', {limit: 100 * 2 ** 30});
  assert.match(gib, /<strong>3 GiB<\/strong>/); assert.match(gib, /1 GiB = 1,073,741,824 bytes/);
  const unlimited = chart.render(data, 'zh', {});
  assert.match(unlimited, /500 GB/); assert.match(unlimited, /1 GB = 1,000,000,000 位元組/);
  const many = chart.render(fixture(Array.from({length: 24}, () => [1e6, 2e6])), 'en', {limit: 1e12});
  assert.match(many, /class="usage-mid"/, 'a middle date label helps read longer ranges');
});
console.log(`${passed}/10 chart truth regressions passed; synthetic fixtures, NOT live data.`);
