/* SBOX Connect & Export Center: ONE component for the admin console, the personal portal
   and the subscription landing page. Choices and labels come from the backend catalog
   (backend/export_catalog.py); each page supplies only a small data adapter:
     adapter.qrSubscription(sel, url) -> Promise<svg text>
     adapter.nodes(sel)               -> Promise<[uri, ...]>
     adapter.qrNode(sel, index, uri)  -> Promise<svg text>
     adapter.download(sel)            -> Promise<text>
   No inline handlers, no third-party code; every catalog string is escaped. */
(function () {
  'use strict';
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const NODE = /^(vless|vmess|hysteria2|tuic|anytls):\/\//;
  const PROTOCOL = {vless: 'VLESS REALITY', vmess: 'VMess', hysteria2: 'Hysteria2', tuic: 'TUIC v5', anytls: 'AnyTLS'};
  let counter = 0;

  function withEndpoint(url, endpoint) {
    if (!url || !endpoint || endpoint === 'auto') return url || '';
    const u = new URL(url, location.href); u.searchParams.set('endpoint', endpoint); return u.href;
  }
  function svgImage(svg, alt) {
    const img = document.createElement('img');
    img.className = 'xc-qr'; img.alt = alt; img.width = 240; img.height = 240;
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));
    return img;
  }

  function mount(root, options) {
    if (root.__sboxExport) root.__sboxExport.destroy();
    const cat = options.catalog, adapter = options.adapter || {}, id = 'xc' + (++counter), stop = new AbortController();
    const lang = () => (typeof options.lang === 'function' ? options.lang() : options.lang) === 'zh' ? 'zh' : 'en';
    const t = v => v ? (v[lang()] || v.en || '') : '';
    const T = key => t(cat.text[key]);
    const urlsReady = !!cat.urls && cat.subscription_state === 'ready';
    const sel = {client: cat.clients[0].id, format: cat.clients[0].formats[0].id, profile: cat.profiles[0].id,
                 endpoint: cat.endpoints[0].id, method: urlsReady ? 'subscription' : 'file'};
    let generation = 0, endpointOpen = false, routingOpen = false;  // keep the address disclosure open once used
    const client = () => cat.clients.find(c => c.id === sel.client);
    const format = () => client().formats.find(f => f.id === sel.format) || client().formats[0];
    const profile = () => cat.profiles.find(p => p.id === sel.profile);
    const endpoint = () => cat.endpoints.find(e => e.id === sel.endpoint) || cat.endpoints[0];
    const method = () => cat.methods.find(m => m.id === sel.method);
    const basic = () => sel.format === 'json';
    // A chosen server address is kept in the file name (sbox-global-ipv6.yaml), like earlier releases.
    const fileName = s => (cat.files[s.format] || 'sbox.txt').replace('{profile}', s.profile + (s.endpoint && s.endpoint !== 'auto' ? '-' + s.endpoint : ''));
    const subscriptionUrl = () => urlsReady ? withEndpoint(cat.urls[sel.profile][sel.format], sel.endpoint) : '';

    const unavailable = () => (cat.unavailable && cat.unavailable[sel.format]) || [];
    function radios(name, items, current, disabled, off) {
      return items.map(it => {
        const blocked = !!(off && off.includes(it.id));
        const rid = `${id}-${name}-${it.id}`, hint = it.hint ? `<span class="xc-hint" id="${rid}-hint">${esc(t(it.hint))}</span>` : '';
        const extra = it.address ? ` <span class="xc-address">${esc(it.address)}</span>` : '';
        return `<div class="xc-radio"><input type="radio" id="${rid}" name="${id}-${name}" value="${esc(it.id)}" data-xc="${name}"${it.id === current ? ' checked' : ''}${disabled || blocked ? ' disabled' : ''}${it.hint ? ` aria-describedby="${rid}-hint"` : ''}>`
          + `<label for="${rid}">${esc(t(it.label))}${extra}</label>${blocked ? `<span class="xc-hint">${esc(T('profile_unavailable'))}</span>` : hint}</div>`;
      }).join('');
    }

    function output() {
      const parts = [];
      if (sel.method === 'subscription') {
        if (!urlsReady) parts.push(`<p class="xc-note">${esc(T(cat.subscription_state === 'missing' ? 'no_subscription' : 'not_recoverable'))}</p>`);
        else parts.push(`<label class="xc-field" for="${id}-url"><span>${esc(t(method().label))}</span><input id="${id}-url" readonly value="${esc(subscriptionUrl())}"></label>`
          + `<div class="xc-actions"><button type="button" data-xc-act="copy-url">${esc(T('copy_url'))}</button><button type="button" data-xc-act="qr-sub">${esc(T('show_qr'))}</button></div>`
          + `<div class="xc-qr-slot" id="${id}-subqr"></div>`
          + (cat.text.import_steps ? `<ol class="xc-steps">${cat.text.import_steps.map(x => `<li>${esc(t(x))}</li>`).join('')}</ol>` : ''));
      } else if (sel.method === 'file') {
        const name = fileName(sel);
        parts.push(`<p class="xc-note">${esc(T('file_note'))}</p><div class="xc-actions"><button type="button" class="primary" data-xc-act="download">${esc(T('download'))} · ${esc(name)}</button></div>`);
      } else {
        parts.push(`<p class="xc-note">${esc(T('nodes_note'))}</p><div class="xc-actions"><button type="button" data-xc-act="nodes">${esc(T('show_nodes'))}</button></div><div class="xc-nodes" id="${id}-nodes"></div>`);
      }
      return parts.join('');
    }

    function summary() {
      // Always name the configuration type (YAML / complete JSON / basic JSON / node URI).
      const bits = [t(client().label), sel.method === 'nodes' ? t(method().label) : t(format().label)];
      if (!basic() && sel.method !== 'nodes') bits.push(t(profile().label));
      const ep = endpoint(); bits.push(t(ep.label) + (ep.address ? ' · ' + ep.address : ''));
      if (sel.method !== 'nodes') bits.push(t(method().label));
      return bits.map(esc).join(' <span aria-hidden="true">›</span> ');
    }

    function render() {
      generation++;
      const ep = endpoint(), multi = cat.endpoints.length > 1, routing = sel.method !== 'nodes';
      let n = 0; const num = () => `<span class="xc-num">${++n}</span>`;  // number visible steps only
      root.innerHTML = `<div class="xc" id="${id}">
        <p class="xc-secret" role="note">${esc(T('secret'))}</p>
        <fieldset class="xc-step"><legend>${num()}${esc(T('step_client'))}</legend>${radios('client', cat.clients, sel.client)}
          ${client().formats.length > 1 ? `<fieldset class="xc-reveal"><legend>${esc(T('step_format'))}</legend>${radios('format', client().formats, sel.format)}</fieldset>` : ''}</fieldset>
        ${routing ? `<fieldset class="xc-step"><legend>${num()}${esc(T('step_profile'))}</legend>
          ${basic() ? `<p class="xc-note">${esc(T('step_profile_basic'))}</p>` : radios('profile', cat.profiles, sel.profile, false, unavailable())}
          ${cat.text.routing_note ? `<details class="xc-why"${routingOpen ? ' open' : ''}><summary>${esc(T('routing_note_title'))}</summary><p class="xc-hint xc-routing-note">${esc(T('routing_note'))}</p></details>` : ''}</fieldset>` : ''}
        <fieldset class="xc-step"><legend>${num()}${esc(T('step_endpoint'))}</legend>
          <p class="xc-hint">${esc(T('endpoint_hint'))}</p><p class="xc-current"><strong>${esc(t(ep.label))}</strong>${ep.address ? ` <span class="xc-address">${esc(ep.address)}</span>` : ''}</p>
          ${multi ? `<details class="xc-more"${endpointOpen || sel.endpoint !== cat.endpoints[0].id ? ' open' : ''}><summary>${esc(T('endpoint_change'))}</summary>${radios('endpoint', cat.endpoints, sel.endpoint)}</details>` : ''}</fieldset>
        <fieldset class="xc-step"><legend>${num()}${esc(T('step_method'))}</legend>${radios('method', cat.methods, sel.method)}</fieldset>
        <section class="xc-out" aria-labelledby="${id}-sum"><h3 id="${id}-sum">${esc(T('summary'))}</h3><p class="xc-summary">${summary()}</p>${output()}</section>
        <p class="xc-status" role="status" aria-live="polite" id="${id}-status"></p></div>`;
    }

    function status(text) { const el = root.querySelector('.xc-status'); if (el) el.textContent = text; }
    async function copy(text, button) {
      try { await (adapter.copy ? adapter.copy(text) : navigator.clipboard.writeText(text)); status(T('copied')); if (button) { const old = button.textContent; button.textContent = T('copied'); setTimeout(() => { button.textContent = old; }, 1500); } }
      catch (e) { status(e && e.message ? e.message : String(e)); }
    }
    async function guarded(task) {
      const mine = generation;
      try { const value = await task(); return mine === generation ? value : undefined; }
      catch (e) { if (mine === generation) status(e && e.message ? e.message : String(e)); return undefined; }
    }

    root.addEventListener('change', ev => {
      const name = ev.target.dataset && ev.target.dataset.xc; if (!name) return;
      sel[name] = ev.target.value;
      if (name === 'endpoint') endpointOpen = true;
      if (name === 'client') sel.format = client().formats[0].id;
      if (unavailable().includes(sel.profile)) sel.profile = cat.profiles.find(p => !unavailable().includes(p.id)).id;
      const focusId = ev.target.id; render();
      const again = document.getElementById(focusId); if (again) again.focus();
    }, {signal: stop.signal});
    root.addEventListener('toggle', ev => { const c = ev.target.classList; if (!c) return; if (c.contains('xc-more')) endpointOpen = ev.target.open; if (c.contains('xc-why')) routingOpen = ev.target.open; }, {capture: true, signal: stop.signal});
    root.addEventListener('click', async ev => {
      const btn = ev.target.closest('[data-xc-act]'); if (!btn || !root.contains(btn)) return;
      const act = btn.dataset.xcAct, snapshot = {...sel};
      if (act === 'copy-url') return copy(subscriptionUrl(), btn);
      if (act === 'qr-sub') {
        const svg = await guarded(() => adapter.qrSubscription(snapshot, subscriptionUrl())); if (!svg) return;
        const slot = document.getElementById(id + '-subqr'); slot.replaceChildren(svgImage(svg, T('qr_sub_caption')));
        const cap = document.createElement('p'); cap.className = 'xc-caption'; cap.textContent = T('qr_sub_caption'); slot.append(cap); return;
      }
      if (act === 'download') {
        const text = await guarded(() => adapter.download(snapshot)); if (text == null) return;
        const name = fileName(snapshot);
        const url = URL.createObjectURL(new Blob([text], {type: snapshot.format === 'yaml' ? 'application/yaml' : snapshot.format === 'links' ? 'text/plain' : 'application/json'}));
        const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000); return;
      }
      if (act === 'nodes') {
        const nodes = await guarded(() => adapter.nodes(snapshot)); if (!nodes) return;
        const box = document.getElementById(id + '-nodes');
        box.innerHTML = nodes.filter(u => NODE.test(u)).map((uri, i) => {
          const proto = PROTOCOL[uri.split(':')[0]] || uri.split(':')[0];
          return `<div class="xc-node"><label class="xc-field" for="${id}-n${i}"><span>${esc(proto)}</span><input id="${id}-n${i}" readonly value="${esc(uri)}"></label>`
            + `<div class="xc-actions"><button type="button" data-xc-act="copy-node" data-i="${i}">${esc(T('copy_uri'))}</button><button type="button" data-xc-act="qr-node" data-i="${i}">${esc(T('node_qr'))}</button></div><div class="xc-qr-slot" id="${id}-nq${i}"></div></div>`;
        }).join(''); return;
      }
      if (act === 'copy-node') return copy(document.getElementById(`${id}-n${btn.dataset.i}`).value, btn);
      if (act === 'qr-node') {
        const i = Number(btn.dataset.i), uri = document.getElementById(`${id}-n${i}`).value;
        const svg = await guarded(() => adapter.qrNode(snapshot, i, uri)); if (!svg) return;
        const slot = document.getElementById(`${id}-nq${i}`); slot.replaceChildren(svgImage(svg, T('qr_node_caption')));
        const cap = document.createElement('p'); cap.className = 'xc-caption'; cap.textContent = T('qr_node_caption'); slot.append(cap);
      }
    }, {signal: stop.signal});
    render();
    const api = {render, selection: () => ({...sel}), destroy() { generation++; stop.abort(); root.__sboxExport = null; root.replaceChildren(); }};
    root.__sboxExport = api; return api;
  }
  window.SBOXExportCenter = {mount, withEndpoint};
}());
