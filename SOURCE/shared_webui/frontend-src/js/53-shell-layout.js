/* Text enlargement and translated labels can make a sticky header occupy most
   of the viewport. Observe its rendered height rather than guessing a device
   width; a tall header stays in document flow and scrolls out of the way. */
function initializeShellLayout() {
  const header = document.querySelector('.topbar');
  if (!header) return;
  function fitHeader() {
    const height = header.getBoundingClientRect().height;
    const flowing = height > Math.max(96, window.innerHeight * .28);
    header.classList.toggle('flowing', flowing);
    document.documentElement.style.setProperty('--topbar-clearance', flowing ? '0px' : Math.ceil(height) + 'px');
  }
  new ResizeObserver(fitHeader).observe(header);
  window.addEventListener('resize', fitHeader);
  fitHeader();
}
initializeShellLayout();
