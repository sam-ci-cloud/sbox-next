/* SVG coordinates follow measured CSS pixels, so axis text never shrinks with
   a desktop viewBox on a phone. The same source data is redrawn on resize. */
let adaptiveChartObserver;
function adaptiveChart(model) {
  return `<div class="adaptive-chart" data-chart="${esc(JSON.stringify(model))}"></div>`;
}
function adaptiveChartSvg(model, width) {
  const W = Math.max(160, Math.round(width)), H = model.height || 240;
  const pts = model.points || [], keys = model.keys;
  const values = pts.filter(p => !p.gap && keys.every(k => Number.isFinite(p[k])));
  if (!values.length) return `<p class="muted" role="status">${esc(bi('No measurements in this range yet.', '此範圍暫時未有測量記錄。'))}</p>`;
  const max = Math.max(1, ...values.flatMap(p => keys.map(k => p[k])));
  const ticks = model.ticks || [0, .5, 1].map(f => bitrate(max * f));
  const L = Math.min(W * .42, Math.max(66, ...ticks.map(t => String(t).length * 7 + 12))), R = 10, T = 14, B = 34;
  const t0 = Number.isFinite(model.start) ? model.start : pts[0].t;
  const t1 = Number.isFinite(model.end) ? model.end : pts.at(-1).t;
  const span = Math.max(1, t1 - t0);
  const x = t => L + (t1 === t0 ? .5 : (t - t0) / span) * (W - L - R);
  const y = v => T + (1 - v / max) * (H - T - B);
  const lines = keys.map((key, index) => {
    const segments = []; let current = [];
    for (const p of pts) {
      if (p.gap || !Number.isFinite(p[key])) { if (current.length) segments.push(current); current = []; }
      else current.push(p);
    }
    if (current.length) segments.push(current);
    return segments.map(segment => segment.length === 1
      ? `<circle class="${index ? 'tx' : 'rx'} chart-point" cx="${x(segment[0].t).toFixed(1)}" cy="${y(segment[0][key]).toFixed(1)}" r="3"><title>${esc(when(segment[0].t))}: ${esc(model.kind === 'metric' ? segment[0].label : bitrate(segment[0][key]))}</title></circle>`
      : `<polyline class="${index ? 'tx' : 'rx'}" points="${segment.map(p => x(p.t).toFixed(1) + ',' + y(p[key]).toFixed(1)).join(' ')}"/>`).join('');
  }).join('');
  const grid = [0, .5, 1].map((f, i) => `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(max * f)}" y2="${y(max * f)}"/><text class="axis" x="${L - 8}" y="${y(max * f) + 4}" text-anchor="end">${esc(ticks[i])}</text>`).join('');
  const times = (t0 === t1 ? [t0] : W < 480 ? [t0, t1] : [t0, (t0 + t1) / 2, t1]).map((t, i, list) => `<text class="axis" x="${x(t)}" y="${H - 9}" text-anchor="${i === 0 ? 'start' : i === list.length - 1 ? 'end' : 'middle'}">${esc(model.window_seconds <= 86400 ? when(t, {short: true}) : new Date(t * 1000).toLocaleDateString(locale(), {month: 'short', day: 'numeric'}))}</text>`).join('');
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${esc(model.label)}">${grid}${times}${lines}</svg>`;
}
function observeAdaptiveCharts(root) {
  if (adaptiveChartObserver) adaptiveChartObserver.disconnect();
  const draw = el => {
    if (!el.isConnected || el.clientWidth <= 0) return;
    const width = Math.round(el.clientWidth);
    if (el.dataset.chartWidth === String(width)) return;
    el.dataset.chartWidth = String(width);
    el.innerHTML = adaptiveChartSvg(JSON.parse(el.dataset.chart), width);
  };
  const charts = [...root.querySelectorAll('.adaptive-chart')];
  charts.forEach(draw);
  if (typeof ResizeObserver !== 'undefined') {
    adaptiveChartObserver = new ResizeObserver(entries => entries.forEach(e => draw(e.target)));
    charts.forEach(el => adaptiveChartObserver.observe(el));
  }
}

/* A native popover uses the top layer, outside table/scroll clipping. Keep its
   anchored menu inside the viewport and return Escape focus to the summary. */
function placeActionMenu(menu) {
  const panel = menu.querySelector('.menu-list');
  if (!panel) return;
  if (typeof panel.showPopover !== 'function') { panel.removeAttribute('popover'); return; }
  if (!menu.open) { if (panel.matches(':popover-open')) panel.hidePopover(); return; }
  if (!panel.matches(':popover-open')) panel.showPopover();
  const anchor = menu.querySelector('summary').getBoundingClientRect(), margin = 12, gap = 6;
  panel.style.maxHeight = 'none';
  const natural = panel.scrollHeight + panel.offsetHeight - panel.clientHeight;
  const below = Math.max(0, innerHeight - anchor.bottom - gap - margin), above = Math.max(0, anchor.top - gap - margin);
  const useBelow = below >= natural || below >= above;
  const available = useBelow ? below : above;
  panel.style.maxHeight = available + 'px';
  panel.style.left = Math.max(margin, Math.min(innerWidth - panel.offsetWidth - margin, anchor.right - panel.offsetWidth)) + 'px';
  const intended = useBelow ? anchor.bottom + gap : anchor.top - gap - panel.offsetHeight;
  panel.style.top = Math.max(margin, Math.min(innerHeight - panel.offsetHeight - margin, intended)) + 'px';
}

/* Opening a lower row can itself scroll the page. Keep a visible anchor's
   menu in place instead of letting that queued scroll undo the click. */
function refreshActionMenus(event) {
  if (event?.target?.closest?.('.menu-list')) return;
  for (const menu of document.querySelectorAll('details.menu[open]')) {
    const anchor = menu.querySelector('summary').getBoundingClientRect();
    if (document.querySelector('dialog[open]') || anchor.bottom <= 0 || anchor.top >= innerHeight || anchor.right <= 0 || anchor.left >= innerWidth) {
      menu.open = false;
    } else {
      placeActionMenu(menu);
    }
  }
}
