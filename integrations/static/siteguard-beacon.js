/*
 * SiteGuard beacon for static sites.
 *
 * Add before </body>:
 *   <script>window.SiteGuardConfig={endpoint:"https://stats.example.com/collect.php"};</script>
 *   <script src="/siteguard-beacon.js" defer></script>
 *
 * This reports pageviews only. A static host cannot rate-limit a request it
 * never routes; use the edge for that.
 */
(function () {
  'use strict';

  var cfg = window.SiteGuardConfig || null;
  if (!cfg || !cfg.endpoint) {
    return;
  }

  function hex(bytes) {
    var out = '';
    var view = new Uint8Array(bytes);
    for (var i = 0; i < view.length; i++) {
      out += (view[i] < 16 ? '0' : '') + view[i].toString(16);
    }
    return out;
  }

  function newId() {
    if (window.crypto && window.crypto.getRandomValues) {
      return hex(window.crypto.getRandomValues(new Uint8Array(16)));
    }
    return null;
  }

  var VALID = /^[a-f0-9]{32}$/;

  function read(kind, key) {
    try {
      var store = window[kind];
      if (!store) {
        return '';
      }
      var value = store.getItem(key);
      if (value && VALID.test(value)) {
        return value;
      }
      var fresh = newId();
      if (fresh) {
        store.setItem(key, fresh);
      }
      return fresh || '';
    } catch (e) {
      return '';
    }
  }

  var visitor = read('localStorage', 'sg_v');
  var session = read('sessionStorage', 'sg_s');
  if (!visitor || !session) {
    return;
  }

  function send(type) {
    var body = JSON.stringify({
      v: 1,
      type: type,
      path: location.pathname,
      referrer: document.referrer || '',
      visitor: visitor,
      session: session,
      fp: {
        lang: navigator.language || '',
        touch: navigator.maxTouchPoints > 0 ? 1 : 0
      }
    });
    if (navigator.sendBeacon) {
      navigator.sendBeacon(cfg.endpoint, new Blob([body], { type: 'application/json' }));
      return;
    }
    if (window.fetch) {
      window.fetch(cfg.endpoint, {
        method: 'POST',
        body: body,
        headers: { 'Content-Type': 'application/json' },
        keepalive: true
      }).catch(function () {});
    }
  }

  send('pageview');
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') {
      send('leave');
    }
  });
})();
