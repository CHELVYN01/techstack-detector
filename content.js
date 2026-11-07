/**
 * TechStack Detector — content script (isolated world).
 * Mengumpulkan data halaman (meta, script, link, DOM, CSS variable, banner CSS,
 * variabel window via inject.js, versi Odoo via JSON-RPC) lalu mengirimkannya
 * ke background.js untuk dicocokkan dengan SIGNATURES.
 */
(() => {
  const MAX_HTML = 500000;
  const MAX_URLS = 400;
  const MAX_CSS_FILES = 6;
  // CDN yang mengirim header CORS sehingga file CSS-nya bisa dibaca
  const CORS_CSS_HOSTS = /(?:^|\.)(?:jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|bootstrapcdn\.com|stackpath\.bootstrapcdn\.com)$/;

  let odooRpcCache = null;

  // Kumpulkan kebutuhan (selector DOM, path JS, CSS var) dari semua signature
  function requirements() {
    const dom = new Map();
    const js = new Set();
    const cssVars = new Set();
    for (const sig of SIGNATURES) {
      for (const d of sig.dom || []) {
        const e = typeof d === 'string' ? { selector: d } : d;
        if (!dom.has(e.selector)) dom.set(e.selector, new Set());
        if (e.attr) dom.get(e.selector).add(e.attr);
      }
      Object.keys(sig.js || {}).forEach((p) => js.add(p));
      Object.values(sig.extra || {}).forEach((p) => js.add(p));
      (sig.collect || []).forEach((p) => js.add(p));
      (sig.cssVars || []).forEach((v) => cssVars.add(v));
    }
    return { dom, js: [...js], cssVars: [...cssVars] };
  }

  const uniq = (arr) => [...new Set(arr.filter(Boolean))].slice(0, MAX_URLS);

  function collectMeta() {
    const meta = {};
    for (const m of document.querySelectorAll('meta')) {
      const key = (m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || '').toLowerCase();
      if (!key) continue;
      (meta[key] ||= []).push((m.getAttribute('content') || '').slice(0, 300));
    }
    return meta;
  }

  // src <script> / href <link> + resource yang dimuat dinamis (mis. oleh GTM)
  function collectUrls() {
    const resources = performance.getEntriesByType('resource');
    const scripts = uniq([
      ...Array.from(document.scripts, (s) => s.src),
      ...resources.filter((r) => r.initiatorType === 'script').map((r) => r.name),
    ]);
    const links = uniq([
      ...Array.from(document.querySelectorAll('link[href]'), (l) => l.href),
      ...resources.filter((r) => r.initiatorType === 'link' || r.initiatorType === 'css').map((r) => r.name),
    ]);
    return { scripts, links };
  }

  function collectDom(domReq) {
    const out = {};
    for (const [selector, attrs] of domReq) {
      let nodes;
      try {
        nodes = document.querySelectorAll(selector);
      } catch {
        continue; // selector tidak valid
      }
      if (!nodes.length) continue;
      const entry = { count: nodes.length };
      if (attrs.size) {
        entry.attrs = {};
        for (const a of attrs) {
          const v = nodes[0].getAttribute(a);
          if (v !== null) entry.attrs[a] = v.slice(0, 200);
        }
      }
      out[selector] = entry;
    }
    return out;
  }

  function collectCssVars(names) {
    const out = {};
    const styles = [document.documentElement, document.body].filter(Boolean).map((el) => getComputedStyle(el));
    for (const name of names) {
      for (const cs of styles) {
        const v = cs.getPropertyValue(name).trim();
        if (v) {
          out[name] = v.slice(0, 100);
          break;
        }
      }
    }
    return out;
  }

  // Baca potongan awal file CSS (banner seperti "Bootstrap v5.3.2"), hanya same-origin / CDN ber-CORS
  async function collectCssBanners() {
    const urls = Array.from(document.querySelectorAll('link[rel~="stylesheet"][href]'), (l) => l.href)
      .filter((u) => {
        try {
          const url = new URL(u);
          return url.origin === location.origin || CORS_CSS_HOSTS.test(url.hostname);
        } catch {
          return false;
        }
      })
      .slice(0, MAX_CSS_FILES);
    const heads = await Promise.all(urls.map(readHead));
    return heads.filter(Boolean);
  }

  async function readHead(url) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    try {
      const res = await fetch(url, { credentials: 'omit', cache: 'force-cache', signal: ctrl.signal });
      if (!res.ok || !res.body) return null;
      const reader = res.body.getReader();
      const { value } = await reader.read();
      reader.cancel().catch(() => {});
      return value ? new TextDecoder().decode(value.slice(0, 4000)) : null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  // Minta inject.js (MAIN world) membaca variabel window; retry karena urutan load tidak dijamin
  function requestMainWorld(paths) {
    return new Promise((resolve) => {
      const id = Math.random().toString(36).slice(2);
      let tries = 0;
      const onMessage = (e) => {
        const d = e.data;
        if (e.source !== window || !d || d.source !== 'tsd-inject' || d.id !== id) return;
        cleanup();
        resolve(d.js || {});
      };
      const post = () => window.postMessage({ source: 'tsd-content', type: 'collect', id, paths }, '*');
      const timer = setInterval(() => {
        if (++tries > 8) {
          cleanup();
          resolve({});
        } else post();
      }, 250);
      function cleanup() {
        clearInterval(timer);
        window.removeEventListener('message', onMessage);
      }
      window.addEventListener('message', onMessage);
      post();
    });
  }

  function looksLikeOdoo(data) {
    return (
      'odoo' in data.js ||
      (data.meta.generator || []).some((g) => /odoo/i.test(g)) ||
      Boolean(data.dom['.o_web_client'] || data.dom['#wrapwrap'] || data.dom['[data-oe-model]']) ||
      data.scripts.concat(data.links).some((u) => /\/web\/(?:assets|static)\//.test(u))
    );
  }

  // Odoo: endpoint JSON-RPC publik (auth='none') yang mengembalikan versi server (same-origin)
  async function fetchOdooVersionInfo() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    try {
      const res = await fetch(`${location.origin}/web/webclient/version_info`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'call', params: {}, id: Date.now() }),
        credentials: 'same-origin',
        signal: ctrl.signal,
      });
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
      const json = await res.json();
      if (json && json.result) return { ok: true, ...json.result };
      return { ok: false, error: (json && json.error && (json.error.data?.message || json.error.message)) || 'respons tanpa result' };
    } catch (e) {
      return { ok: false, error: e.name === 'AbortError' ? 'timeout' : String(e.message || e) };
    } finally {
      clearTimeout(timer);
    }
  }

  async function scan() {
    const req = requirements();
    const { scripts, links } = collectUrls();
    const [js, css] = await Promise.all([requestMainWorld(req.js), collectCssBanners()]);
    const data = {
      url: location.href,
      title: document.title,
      timeOrigin: performance.timeOrigin,
      meta: collectMeta(),
      scripts,
      links,
      js,
      css,
      dom: collectDom(req.dom),
      cssVars: collectCssVars(req.cssVars),
      cookies: document.cookie.split(';').map((c) => c.split('=')[0].trim()).filter(Boolean),
      html: document.documentElement.outerHTML.slice(0, MAX_HTML),
    };
    if (looksLikeOdoo(data)) {
      if (!odooRpcCache || !odooRpcCache.ok) odooRpcCache = await fetchOdooVersionInfo();
      data.odooRpc = odooRpcCache;
    }
    await chrome.runtime.sendMessage({ type: 'TSD_PAGE_DATA', data });
  }

  function safeScan() {
    return scan().catch(() => {
      /* extension di-reload / context invalid → abaikan */
    });
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === 'TSD_RESCAN') {
      safeScan().then(() => sendResponse({ ok: true }));
      return true; // respons async
    }
    return false;
  });

  // Scan awal + scan ulang untuk menangkap script yang dimuat belakangan (lazy / tag manager)
  safeScan();
  setTimeout(safeScan, 3000);
})();
