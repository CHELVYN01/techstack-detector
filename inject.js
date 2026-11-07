/**
 * TechStack Detector — inject.js (MAIN world).
 * Berjalan di konteks JavaScript halaman agar bisa membaca variabel window
 * (window.React, __NEXT_DATA__, odoo, jQuery.fn.jquery, dst).
 * Komunikasi dengan content.js lewat window.postMessage.
 */
(() => {
  if (window.__tsdInjectReady) return;
  Object.defineProperty(window, '__tsdInjectReady', { value: true });

  const MAX_LEN = 300;
  const SCAN_LIMIT = 1500;

  // Telusuri path "a.b.c" dari window, aman terhadap getter yang melempar error
  function resolvePath(path) {
    let cur = window;
    for (const key of path.split('.')) {
      if (cur === null || cur === undefined) return undefined;
      try {
        cur = cur[key];
      } catch {
        return undefined;
      }
    }
    return cur;
  }

  // Ubah nilai jadi string pendek yang aman dikirim lewat postMessage
  function serialize(v) {
    if (v === undefined || v === null) return undefined;
    // window.<id> bisa menunjuk ke elemen DOM (named access) → bukan variabel JS sungguhan
    if (v instanceof Element || v instanceof HTMLCollection || v instanceof NodeList) return undefined;
    switch (typeof v) {
      case 'string':
        return v.slice(0, MAX_LEN);
      case 'number':
      case 'boolean':
      case 'bigint':
        return String(v);
      case 'function':
        return '[function]';
      default:
        return Array.isArray(v) ? '[array]' : '[object]';
    }
  }

  // Jalankan `test` pada elemen-elemen halaman sampai ada yang mengembalikan nilai
  function scanElements(test) {
    const els = document.querySelectorAll('body, body *');
    const n = Math.min(els.length, SCAN_LIMIT);
    for (let i = 0; i < n; i++) {
      try {
        const r = test(els[i]);
        if (r) return r;
      } catch {
        /* abaikan elemen bermasalah */
      }
    }
    return null;
  }

  // Probe khusus: deteksi yang tidak bisa dilakukan dengan path sederhana
  const PROBES = {
    '@react'() {
      const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
      if (hook && hook.renderers && hook.renderers.size) {
        for (const r of hook.renderers.values()) if (r && r.version) return r.version;
      }
      if (window.React && window.React.version) return window.React.version;
      const hit = scanElements((el) => {
        if (el._reactRootContainer) return true;
        return Object.keys(el).some(
          (k) => k.startsWith('__reactFiber$') || k.startsWith('__reactContainer$') || k.startsWith('__reactInternalInstance$')
        );
      });
      return hit ? 'true' : undefined;
    },
    '@vue'() {
      if (window.Vue && window.Vue.version) return window.Vue.version;
      const v = scanElements((el) => {
        if (el.__vue_app__) return el.__vue_app__.version || 'true';
        if (el.__vue__) {
          const base = el.__vue__.$root && el.__vue__.$root.$options && el.__vue__.$root.$options._base;
          return (base && base.version) || 'true';
        }
        return null;
      });
      return v || (window.__VUE__ ? 'true' : undefined);
    },
    '@svelte'() {
      const s = window.__svelte;
      if (!s) return undefined;
      const v = s.v ? Array.from(s.v).join(', ') : '';
      return v || 'true';
    },
    '@sveltekit'() {
      return Object.keys(window).some((k) => k.startsWith('__sveltekit_')) ? 'true' : undefined;
    },
    '@gtm'() {
      const g = window.google_tag_manager;
      if (!g || typeof g !== 'object') return undefined;
      const ids = Object.keys(g).filter((k) => /^(?:GTM|G|AW|DC|UA)-/.test(k));
      return ids.length ? ids.join(',') : 'true';
    },
  };

  function collect(paths) {
    const out = {};
    for (const path of paths) {
      let value;
      try {
        value = path.startsWith('@') ? PROBES[path] && PROBES[path]() : serialize(resolvePath(path));
      } catch {
        value = undefined;
      }
      if (value !== undefined) out[path] = String(value).slice(0, MAX_LEN);
    }
    return out;
  }

  window.addEventListener('message', (e) => {
    const d = e.data;
    if (e.source !== window || !d || d.source !== 'tsd-content' || d.type !== 'collect' || !Array.isArray(d.paths)) return;
    window.postMessage({ source: 'tsd-inject', type: 'result', id: d.id, js: collect(d.paths) }, '*');
  });
})();
