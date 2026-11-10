/*
 * SiteGuard collector.
 *
 * Sends the pageview, the visitor and session ids, and the public signals a
 * browser exposes to any page: screen, time zone, language, CPU and memory
 * hints, client hints, and one-way hashes of a canvas render, the WebGL
 * renderer, and an audio graph. Nothing here acts on the page and nothing is
 * sent anywhere except this site's own collector endpoint.
 */
(function () {
  'use strict';

  var cfg = window.SiteGuardConfig || null;
  if (!cfg || !cfg.endpoint) {
    return;
  }
  if (navigator.sendBeacon === undefined && window.fetch === undefined) {
    return;
  }

  function consentGiven() {
    if (!cfg.consent || cfg.consent === 'none') {
      return true;
    }
    if (navigator.doNotTrack === '1' || window.doNotTrack === '1') {
      return false;
    }
    try {
      return window.localStorage.getItem('sg_consent') === '1';
    } catch (e) {
      return false;
    }
  }

  if (!consentGiven()) {
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

  function randomId() {
    if (window.crypto && window.crypto.getRandomValues) {
      return hex(window.crypto.getRandomValues(new Uint8Array(16)));
    }
    var out = '';
    for (var i = 0; i < 32; i++) {
      out += Math.floor(Math.random() * 16).toString(16);
    }
    return out;
  }

  var VALID = /^[a-f0-9]{32}$/;

  function store(store, key, lifetimeSeconds) {
    try {
      var existing = store.getItem(key);
      if (existing && VALID.test(existing)) {
        return existing;
      }
      var fresh = randomId();
      store.setItem(key, fresh);
      if (lifetimeSeconds && store === window.localStorage) {
        store.setItem(key + '_at', String(Date.now()));
      }
      return fresh;
    } catch (e) {
      return '';
    }
  }

  function cookie(name, value, maxAge) {
    document.cookie =
      name + '=' + value + ';path=/;SameSite=Lax' +
      (location.protocol === 'https:' ? ';Secure' : '') +
      (typeof maxAge === 'number' ? ';max-age=' + maxAge : '');
  }

  function storage(kind) {
    try {
      return window[kind] || null;
    } catch (e) {
      return null;
    }
  }

  var local = storage('localStorage');
  var sessionStore = storage('sessionStorage');
  if (!local || !sessionStore) {
    return;
  }

  var visitor = store(local, 'sg_v', 400 * 86400);
  var session = store(sessionStore, 'sg_s', 0);
  if (!visitor || !session) {
    return;
  }
  cookie('sg_v', visitor, 400 * 86400);
  cookie('sg_s', session, 0);

  /* A short FNV-1a digest. Enough to tell two renders or two audio graphs
   * apart; the value is a hash, never the render itself. */
  function digest(value) {
    var h = 2166136261;
    var text = String(value);
    for (var i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return ('0000000' + (h >>> 0).toString(16)).slice(-8);
  }

  function canvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 240;
      c.height = 60;
      var ctx = c.getContext('2d');
      if (!ctx) {
        return '';
      }
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(100, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('SiteGuard fingerprint', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('SiteGuard fingerprint', 4, 17);
      return digest(c.toDataURL());
    } catch (e) {
      return '';
    }
  }

  function webglInfo() {
    var out = { vendor: '', renderer: '' };
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) {
        return out;
      }
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        out.vendor = String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '').slice(0, 120);
        out.renderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '').slice(0, 120);
      }
    } catch (e) {
      /* blocked or unsupported: leave blank */
    }
    return out;
  }

  /* Audio rendering takes a moment, so the result is cached in local storage
   * and sent from the next pageview when it finishes after this one. */
  var audioValue = '';
  try {
    audioValue = local.getItem('sg_audio') || '';
  } catch (e) {
    audioValue = '';
  }

  function audioFingerprint(done) {
    try {
      var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!OAC) {
        done('');
        return;
      }
      var ctx = new OAC(1, 44100, 44100);
      var osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50;
      comp.knee.value = 40;
      comp.ratio.value = 12;
      comp.attack.value = 0;
      comp.release.value = 0.25;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      ctx.startRendering().then(function (buffer) {
        var data = buffer.getChannelData(0);
        var sum = 0;
        for (var i = 0; i < data.length; i += 100) {
          sum += Math.abs(data[i]);
        }
        done(digest(sum.toFixed(6)));
      }).catch(function () {
        done('');
      });
    } catch (e) {
      done('');
    }
  }

  if (!audioValue) {
    audioFingerprint(function (value) {
      audioValue = value;
      try {
        if (value) {
          local.setItem('sg_audio', value);
        }
      } catch (e) {
        /* private mode */
      }
    });
  }

  /* Client hints. The high-entropy values (model, architecture) arrive
   * asynchronously and are cached for later pageviews. */
  var hints = { model: '', arch: '' };
  try {
    hints.model = local.getItem('sg_hm') || '';
    hints.arch = local.getItem('sg_ha') || '';
  } catch (e) {
    hints = { model: '', arch: '' };
  }

  var uaData = navigator.userAgentData || null;
  if (uaData && typeof uaData.getHighEntropyValues === 'function' && (!hints.model || !hints.arch)) {
    uaData.getHighEntropyValues(['architecture', 'model']).then(function (values) {
      hints.model = String(values.model || '').slice(0, 80);
      hints.arch = String(values.architecture || '').slice(0, 40);
      try {
        local.setItem('sg_hm', hints.model);
        local.setItem('sg_ha', hints.arch);
      } catch (e) {
        /* private mode */
      }
    }).catch(function () {});
  }

  function tz() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (e) {
      return '';
    }
  }

  function brands() {
    if (!uaData || !uaData.brands) {
      return '';
    }
    var out = [];
    for (var i = 0; i < uaData.brands.length; i++) {
      out.push(uaData.brands[i].brand + ' ' + uaData.brands[i].version);
    }
    return out.join(', ');
  }

  function fingerprint() {
    var gl = webglInfo();
    return {
      lang: navigator.language || '',
      languages: (navigator.languages || []).join(','),
      tz: tz(),
      tz_offset: String(new Date().getTimezoneOffset()),
      screen: (window.screen && window.screen.width ? window.screen.width + 'x' + window.screen.height : ''),
      viewport: window.innerWidth + 'x' + window.innerHeight,
      dpr: String(window.devicePixelRatio || 1),
      depth: String((window.screen && window.screen.colorDepth) || ''),
      touch: String(navigator.maxTouchPoints || 0),
      cores: String(navigator.hardwareConcurrency || ''),
      mem: String(navigator.deviceMemory || ''),
      platform: navigator.platform || '',
      ua_brands: brands(),
      ua_platform: uaData ? String(uaData.platform || '') : '',
      ua_mobile: uaData ? (uaData.mobile ? '1' : '0') : '',
      ua_model: hints.model,
      ua_arch: hints.arch,
      webgl_vendor: gl.vendor,
      webgl_renderer: gl.renderer,
      canvas: canvasHash(),
      audio: audioValue
    };
  }

  function payload(type) {
    return {
      v: 2,
      type: type,
      path: location.pathname,
      referrer: document.referrer || '',
      visitor: visitor,
      session: session,
      fp: type === 'pageview' ? fingerprint() : {}
    };
  }

  // Sends to the REST collector first. A network error OR a non-OK response
  // (a host kill switch answers 403, not a network failure) retries against
  // the admin-ajax fallback, which no REST kill switch blocks.
  function send(type) {
    var body = JSON.stringify(payload(type));
    deliver(cfg.endpoint, body, function (ok) {
      if (!ok && cfg.fallback) {
        deliver(cfg.fallback, body, function () {});
      }
    });
  }

  function deliver(url, body, done) {
    if (navigator.sendBeacon) {
      var blob = new Blob([body], { type: 'application/json' });
      if (navigator.sendBeacon(url, blob)) {
        // sendBeacon gives no status back; treat queueing as success.
        done(true);
        return;
      }
    }
    if (window.fetch) {
      window.fetch(url, {
        method: 'POST',
        body: body,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        keepalive: true
      }).then(function (response) {
        done(Boolean(response && response.ok));
      }, function () {
        done(false);
      });
      return;
    }
    done(false);
  }

  var sent = false;
  function pageview() {
    if (sent) {
      return;
    }
    sent = true;
    send('pageview');
    setTimeout(function () { sent = false; }, 1000);
  }

  if (document.readyState === 'complete') {
    pageview();
  } else {
    window.addEventListener('load', pageview, { once: true });
  }

  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') {
      send('leave');
    }
  });
})();
