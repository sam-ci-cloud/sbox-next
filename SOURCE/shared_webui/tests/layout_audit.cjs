/* Geometry audit run inside a page. Shared by the layout matrix and its
   negative controls. Checks, for the active layer (open modal dialog plus any
   open popover, otherwise the whole document):
   - document-level horizontal overflow and controls outside the viewport;
   - accidental overlap: pairwise intersection of visible interactive
     controls that do not contain each other and are not in an intentional
     overlay relationship;
   - hit testing: the centre of every visible control must reach that control
     (or something inside it) unless an OPEN intentional overlay covers it;
   - clipping by an ancestor with overflow hidden/clip (not scroll containers);
   - accessible names for every interactive control;
   - open overlays stay inside the viewport.
   Returns {problems:[...], stats:{...}}. */
module.exports = function audit(options = {}) {
  const vw = document.documentElement.clientWidth, vh = window.innerHeight;
  const problems = [];
  const add = (kind, el, detail = '') => problems.push({kind, el: describe(el), detail});
  function describe(el) {
    if (!el || !el.tagName) return String(el);
    const label = (el.getAttribute('aria-label') || el.textContent || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 40);
    return el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '') + (label ? ' "' + label + '"' : '');
  }
  const openOverlays = [...document.querySelectorAll('[popover]')].filter(p => { try { return p.matches(':popover-open'); } catch { return false; } });
  const dialog = [...document.querySelectorAll('dialog[open]')].pop() || null;
  const layerRoots = dialog ? [dialog, ...openOverlays] : [document.body];
  const inLayer = el => layerRoots.some(root => root.contains(el));
  const inOverlay = el => openOverlays.find(p => p.contains(el));
  function visible(el) {
    if (!el.isConnected) return false;
    const s = getComputedStyle(el);
    if (s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) === 0) return false;
    if (el.closest('[hidden],[inert]')) return false;
    const closed = el.closest('details:not([open])');
    if (closed) { const summary = closed.querySelector(':scope > summary'); if (!summary || !summary.contains(el)) return false; }
    const r = el.getBoundingClientRect();
    return r.width > 0.5 && r.height > 0.5;
  }
  const selector = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [role=option], [role=tab], [tabindex]:not([tabindex="-1"])';
  let controls = [...document.querySelectorAll(selector)].filter(el => inLayer(el) && visible(el));
  // Visually hidden native radios are represented by their visible labels.
  controls = controls.map(el => (el.matches('input[type=radio],input[type=checkbox]') && getComputedStyle(el).opacity === '0') ? el.closest('label') || el : el)
    .filter((el, i, a) => a.indexOf(el) === i && !el.matches('.sr, .sr *, .skip'));
  // Scroll containers: a control fully scrolled out of its container is not "visible" now.
  function scrollClip(el) {
    let r = el.getBoundingClientRect(), rect = {left: r.left, top: r.top, right: r.right, bottom: r.bottom};
    for (let p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) {
      const s = getComputedStyle(p);
      if (/(auto|scroll|hidden|clip)/.test(s.overflowX + s.overflowY)) {
        const pr = p.getBoundingClientRect();
        rect = {left: Math.max(rect.left, pr.left), top: Math.max(rect.top, pr.top), right: Math.min(rect.right, pr.right), bottom: Math.min(rect.bottom, pr.bottom)};
        if (/(hidden|clip)/.test(s.overflowX + s.overflowY) && !/(auto|scroll)/.test(s.overflowX + s.overflowY)) {
          const full = el.getBoundingClientRect();
          const shown = Math.max(0, rect.right - rect.left) * Math.max(0, rect.bottom - rect.top), area = full.width * full.height;
          if (area > 4 && shown > 0 && shown < area * 0.9 && !p.matches('.table-wrap,.unit-segment,.meter,.qr-box,.usage-plot,.health-strip')) add('clipped', el, 'by ' + describe(p));
        }
      }
    }
    return {left: Math.max(rect.left, 0), top: Math.max(rect.top, 0), right: Math.min(rect.right, vw), bottom: Math.min(rect.bottom, vh)};
  }
  // Sticky/fixed page chrome (top bar) legitimately sits above content that the
  // user has scrolled beneath it. Only when the page is scrolled, controls under
  // that chrome are "scrolled away", not accidentally covered. At rest (scroll
  // position 0) nothing may be under it.
  const chrome = window.scrollY > 0 && !dialog ? [...document.querySelectorAll('.topbar')].filter(t => /sticky|fixed/.test(getComputedStyle(t).position)).map(t => ({el: t, r: t.getBoundingClientRect()})) : [];
  const underChrome = (el, r) => chrome.some(c => !c.el.contains(el) && r.top < c.r.bottom && r.bottom > c.r.top);
  const boxes = controls.map(el => ({el, r: el.getBoundingClientRect(), shown: scrollClip(el)}))
    .filter(b => b.shown.right - b.shown.left > 1 && b.shown.bottom - b.shown.top > 1 && !underChrome(b.el, b.r));
  if (document.documentElement.scrollWidth > vw + 1) add('page-overflow', document.documentElement, document.documentElement.scrollWidth + ' > ' + vw);
  for (const b of boxes) {
    if (b.r.right > vw + 1 || b.r.left < -1) {
      const scroller = (() => { for (let p = b.el.parentElement; p; p = p.parentElement) { const s = getComputedStyle(p); if (/(auto|scroll)/.test(s.overflowX)) return p; } return null; })();
      if (!scroller) add('outside-viewport', b.el, `${Math.round(b.r.left)}..${Math.round(b.r.right)} of ${vw}`);
    }
  }
  // Pairwise accidental overlap.
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i], c = boxes[j];
    if (a.el.contains(c.el) || c.el.contains(a.el)) continue;
    if (Boolean(inOverlay(a.el)) !== Boolean(inOverlay(c.el))) continue; // intentional overlay over page content
    const w = Math.min(a.shown.right, c.shown.right) - Math.max(a.shown.left, c.shown.left);
    const h = Math.min(a.shown.bottom, c.shown.bottom) - Math.max(a.shown.top, c.shown.top);
    if (w > 2 && h > 2) add('overlap', a.el, describe(c.el) + ` ${Math.round(w)}x${Math.round(h)}`);
  }
  // Hit testing at the visible centre.
  for (const b of boxes) {
    const x = (b.shown.left + b.shown.right) / 2, y = (b.shown.top + b.shown.bottom) / 2;
    const hit = document.elementFromPoint(x, y);
    if (!hit) continue;
    const ok = b.el.contains(hit) || hit.contains(b.el) || (b.el.tagName === 'LABEL' && b.el.contains(hit)) || (hit.closest('label') && hit.closest('label').contains(b.el)) || (b.el.labels && [...b.el.labels].some(l => l.contains(hit)));
    if (ok) continue;
    const coveringOverlay = openOverlays.find(p => p.contains(hit));
    if (coveringOverlay && !coveringOverlay.contains(b.el)) continue; // intentional
    if (hit.closest('.toasts')) continue; // transient status messages, announced and dismissable
    add('covered', b.el, 'by ' + describe(hit));
  }
  // Accessible names.
  for (const b of boxes) {
    const el = b.el.matches('label') ? b.el.querySelector('input') || b.el : b.el;
    const name = (el.getAttribute('aria-label') || '').trim() || (el.getAttribute('aria-labelledby') || '').split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ').trim()
      || (el.labels && [...el.labels].map(l => l.textContent).join(' ').trim()) || (el.closest('label')?.textContent || '').trim()
      || (['BUTTON', 'A', 'SUMMARY'].includes(el.tagName) || el.getAttribute('role') ? el.textContent.trim() : '') || (el.getAttribute('title') || '').trim()
      || (el.tagName === 'INPUT' && ['submit', 'button'].includes(el.type) ? el.value : '') || (el.closest('fieldset')?.querySelector('legend')?.textContent || '').trim();
    if (!name) add('no-accessible-name', el);
  }
  // Open overlays must be inside the viewport and scroll internally if long.
  for (const p of openOverlays) {
    const r = p.getBoundingClientRect();
    if (r.left < -1 || r.top < -1 || r.right > vw + 1 || r.bottom > vh + 1) add('overlay-outside-viewport', p, `${Math.round(r.left)},${Math.round(r.top)},${Math.round(r.right)},${Math.round(r.bottom)} in ${vw}x${vh}`);
  }
  return {problems, stats: {controls: controls.length, measured: boxes.length, overlays: openOverlays.length, dialog: Boolean(dialog)}};
};
