/* Anchored overlays (combobox lists and similar). One place decides layering
   and geometry instead of per-component z-index patches:
   - the browser top layer (popover="manual") is used when available, so an
     overlay is never clipped by a scrolling dialog body or a card;
   - the panel is anchored to its trigger, flips above when there is not
     enough room below, is clamped inside the viewport and scrolls internally;
   - it follows the trigger while any ancestor scrolls or the window resizes,
     and closes if the trigger leaves the viewport.
   Widths and offsets are applied through CSSOM, which the CSP permits. */
const OVERLAY_MARGIN = 8, OVERLAY_GAP = 6, OVERLAY_MAX = 360;
function overlayIsOpen(panel) {
  if (!panel) return false;
  try { if (panel.hasAttribute('popover')) return panel.matches(':popover-open'); } catch { /* old engines */ }
  return !panel.hidden;
}
function placeOverlay(trigger, panel, opts = {}) {
  const r = trigger.getBoundingClientRect(), vw = document.documentElement.clientWidth, vh = window.innerHeight;
  const below = vh - r.bottom - OVERLAY_GAP - OVERLAY_MARGIN, above = r.top - OVERLAY_GAP - OVERLAY_MARGIN;
  panel.style.maxHeight = 'none';
  const natural = Math.min(panel.scrollHeight || OVERLAY_MAX, opts.maxHeight || OVERLAY_MAX);
  const flip = below < Math.min(natural, opts.minHeight || 180) && above > below;
  const room = Math.max(96, flip ? above : below);
  const width = Math.min(Math.max(r.width, opts.minWidth || 240), vw - 2 * OVERLAY_MARGIN);
  const left = Math.min(Math.max(OVERLAY_MARGIN, r.left), vw - OVERLAY_MARGIN - width);
  Object.assign(panel.style, {position: 'fixed', margin: '0', inset: 'auto', width: width + 'px', left: left + 'px', maxHeight: Math.min(natural, room) + 'px'});
  if (flip) panel.style.bottom = (vh - r.top + OVERLAY_GAP) + 'px'; else panel.style.top = (r.bottom + OVERLAY_GAP) + 'px';
  panel.dataset.placement = flip ? 'top' : 'bottom';
}
function openOverlay(trigger, panel, opts = {}) {
  if (panel.hasAttribute('popover') && typeof panel.showPopover === 'function') {
    if (!overlayIsOpen(panel)) panel.showPopover();
  } else {
    panel.hidden = false; panel.classList.add('overlay-fallback');
  }
  placeOverlay(trigger, panel, opts);
  if (panel._overlayCleanup) return;
  const follow = event => {
    if (!overlayIsOpen(panel) || !trigger.isConnected) return closeOverlay(panel, opts.onClose);
    if (event && event.type === 'scroll' && panel.contains(event.target)) return;
    const r = trigger.getBoundingClientRect();
    if (r.bottom < 0 || r.top > window.innerHeight) return closeOverlay(panel, opts.onClose);
    placeOverlay(trigger, panel, opts);
  };
  window.addEventListener('scroll', follow, true);
  window.addEventListener('resize', follow);
  panel._overlayCleanup = () => { window.removeEventListener('scroll', follow, true); window.removeEventListener('resize', follow); panel._overlayCleanup = null; };
}
function closeOverlay(panel, onClose) {
  if (!panel) return;
  if (panel._overlayCleanup) panel._overlayCleanup();
  if (panel.hasAttribute('popover') && typeof panel.hidePopover === 'function') { if (overlayIsOpen(panel)) panel.hidePopover(); }
  else panel.hidden = true;
  if (typeof onClose === 'function') onClose();
}
