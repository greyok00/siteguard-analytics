/* SiteGuard admin: turns the section strip into tabs.
 *
 * The page is complete without this file. Every section is already in the
 * document and the strip is a set of real anchors, so a browser that never
 * runs the script still shows everything and still jumps to each section.
 * When the script does run, it hides all but the selected panel, keeps the
 * address bar in step, and honours the hash left by a form redirect.
 */
(function () {
  'use strict';

  var wrap = document.querySelector('.sg-wrap');
  if (!wrap) return;

  var tabs = Array.prototype.slice.call(wrap.querySelectorAll('[data-sg-tab]'));
  if (!tabs.length) return;

  var panels = tabs.map(function (tab) {
    return document.getElementById(tab.getAttribute('data-sg-tab'));
  });

  var ids = tabs.map(function (tab) {
    return tab.getAttribute('data-sg-tab');
  });

  wrap.classList.add('sg-tabbed');

  function indexOf(id) {
    return ids.indexOf(id);
  }

  function show(id, options) {
    var wanted = indexOf(id);
    if (wanted < 0) wanted = 0;

    tabs.forEach(function (tab, i) {
      var on = i === wanted;
      tab.classList.toggle('is-on', on);
      tab.setAttribute('aria-selected', on ? 'true' : 'false');
      tab.setAttribute('tabindex', on ? '0' : '-1');
      if (panels[i]) panels[i].hidden = !on;
    });

    if (!options || options.updateHash !== false) {
      var hash = '#' + ids[wanted];
      if (window.location.hash !== hash) {
        // replaceState keeps the back button out of the tab history.
        window.history.replaceState(null, '', hash);
      }
    }
  }

  tabs.forEach(function (tab, i) {
    tab.addEventListener('click', function (event) {
      event.preventDefault();
      show(ids[i]);
      if (panels[i]) panels[i].focus({ preventScroll: true });
    });

    tab.addEventListener('keydown', function (event) {
      var next = null;
      if (event.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = tabs.length - 1;
      if (next === null) return;
      event.preventDefault();
      show(ids[next]);
      tabs[next].focus();
    });
  });

  // A redirect from a form handler lands on the page with an #anchor; a
  // hand-typed or bookmarked hash should select the same tab.
  window.addEventListener('hashchange', function () {
    var id = window.location.hash.replace('#', '');
    if (indexOf(id) >= 0) show(id, { updateHash: false });
  });

  var start = window.location.hash.replace('#', '');
  show(indexOf(start) >= 0 ? start : ids[0], { updateHash: false });

  // Give the selected panel a programmatic focus target without showing an
  // outline; screen readers announce the tab change through aria-selected.
  panels.forEach(function (panel) {
    if (panel) panel.setAttribute('tabindex', '-1');
  });
})();
