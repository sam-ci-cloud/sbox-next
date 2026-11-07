/* Personal subscription page adapter for the shared Export Center. Every request stays on
   this page's own token: file and node data come from its subscription URLs and QR codes
   from its restricted qr endpoint (no free-form text). */
(function () {
  'use strict';
  const data = JSON.parse(document.getElementById('xc-data').textContent);
  const base = location.pathname.replace(/[^/]*$/, '');
  async function getText(url) {
    const r = await fetch(url, {credentials: 'omit', cache: 'no-store'});
    if (!r.ok) throw new Error(data.lang === 'zh' ? '無法載入，請確認此連結仍然有效。' : 'Could not load. Check that this link is still active.');
    return r.text();
  }
  async function qr(params) {
    const r = await fetch(base + 'qr?' + new URLSearchParams(params), {credentials: 'omit', cache: 'no-store'});
    if (!r.ok) throw new Error(data.lang === 'zh' ? '無法產生 QR 碼。' : 'Could not create the QR code.');
    return (await r.json()).svg;
  }
  const withEndpoint = (url, ep) => window.SBOXExportCenter.withEndpoint(url, ep);
  window.SBOXExportCenter.mount(document.getElementById('export-center'), {
    catalog: data, lang: data.lang,
    adapter: {
      qrSubscription: sel => qr({kind: 'sub', profile: sel.profile, format: sel.format, endpoint: sel.endpoint}),
      nodes: async sel => (await getText(withEndpoint(base + sel.profile + '.links', sel.endpoint))).split(/\r?\n/).map(x => x.trim()).filter(Boolean),
      qrNode: (sel, index) => qr({kind: 'node', profile: sel.profile, endpoint: sel.endpoint, index: String(index)}),
      download: sel => getText(withEndpoint(base + sel.profile + '.' + sel.format, sel.endpoint))
    }
  });
}());
