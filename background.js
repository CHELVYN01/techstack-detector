/**
 * TechStack Detector — background service worker.
 * - Menangkap response headers main_frame (chrome.webRequest)
 * - Menerima data halaman dari content.js, membaca cookies, menjalankan engine deteksi
 * - Menyimpan hasil per tab di chrome.storage.session & memperbarui badge
 */
importScripts('signatures.js');

const MIN_CONFIDENCE = 30;

// Bobot default (0–100) per sumber bukti; bisa di-override per pola di signatures.js
const WEIGHTS = {
  headers: 80,
  cookies: 50,
  meta: 90,
  scripts: 70,
  links: 60,
  js: 85,
  dom: 60,
  cssVars: 70,
  css: 90,
  html: 40,
  url: 40,
};

// Urutan prioritas sumber saat memilih versi
const VERSION_ORDER = ['js', 'meta', 'css', 'headers', 'dom', 'scripts', 'links', 'cookies', 'html', 'url'];

const SECURITY_HEADERS = [
  { name: 'HSTS', header: 'strict-transport-security' },
  { name: 'CSP', header: 'content-security-policy', reportOnly: 'content-security-policy-report-only', meta: 'content-security-policy' },
  { name: 'X-Frame-Options', header: 'x-frame-options' },
  { name: 'X-Content-Type-Options', header: 'x-content-type-options' },
  { name: 'Referrer-Policy', header: 'referrer-policy' },
  { name: 'Permissions-Policy', header: 'permissions-policy' },
];

/* -------------------------------- Utilitas -------------------------------- */

const storageKey = (tabId) => `tab_${tabId}`;
const cut = (s, n = 140) => {
  s = String(s).replace(/\s+/g, ' ').trim();
  return s.length > n ? `${s.slice(0, n)}…` : s;
};
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const wildcardRe = (name) => new RegExp(`^${name.split('*').map(escapeRe).join('.*')}$`, 'i');

function toRegex(p) {
  if (p instanceof RegExp) return p;
  if (typeof p === 'string' && p) return new RegExp(p, 'i');
  return null; // '' / undefined → cukup "ada"
}

function toPattern(p, source) {
  if (p && typeof p === 'object' && !(p instanceof RegExp)) {
    return { re: toRegex(p.pattern), conf: p.confidence ?? WEIGHTS[source] };
  }
  return { re: toRegex(p), conf: WEIGHTS[source] };
}

function cleanVersion(v) {
  if (v === undefined || v === null) return null;
  v = String(v).trim();
  return /\d/.test(v) && v.length <= 40 ? v : null;
}

// Uji pola terhadap nilai → { version, match } atau null
function test(pat, value) {
  if (!pat.re) return { version: null, match: value };
  const m = pat.re.exec(String(value));
  return m ? { version: cleanVersion(m[1]), match: m[0] } : null;
}

/* ---------------------------- Kompilasi signature ---------------------------- */

// Ubah setiap signature menjadi daftar "rule" seragam agar matching cepat
function compile(sig) {
  const rules = [];
  const add = (source, extra, p) => rules.push({ source, ...extra, pat: toPattern(p, source) });

  for (const [k, p] of Object.entries(sig.headers || {})) add('headers', { key: k.toLowerCase() }, p);
  for (const [k, p] of Object.entries(sig.cookies || {})) add('cookies', { key: k, re: wildcardRe(k) }, p);
  for (const [k, p] of Object.entries(sig.meta || {})) add('meta', { key: k.toLowerCase() }, p);
  for (const [k, p] of Object.entries(sig.js || {})) add('js', { key: k }, p);
  for (const src of ['scripts', 'links', 'css', 'html', 'url']) {
    for (const p of sig[src] || []) add(src, {}, p);
  }
  for (const d of sig.dom || []) {
    const e = typeof d === 'string' ? { selector: d } : d;
    add('dom', { key: e.selector, attr: e.attr }, { pattern: e.pattern, confidence: e.confidence });
  }
  for (const v of sig.cssVars || []) add('cssVars', { key: v }, '');
  return { sig, rules };
}

const COMPILED = SIGNATURES.map(compile);
const SIG_BY_NAME = new Map(SIGNATURES.map((s) => [s.name, s]));

/* ------------------------------ Engine deteksi ------------------------------ */

function jsEvidence(path, v) {
  if (path.startsWith('@')) return `probe runtime ${path.slice(1)}: ${v === 'true' ? 'terdeteksi' : `"${cut(v, 80)}"`}`;
  if (v === '[object]' || v === '[array]' || v === 'true') return `window.${path} ditemukan`;
  if (v === '[function]') return `window.${path}() ditemukan (function)`;
  return `window.${path} = "${cut(v, 80)}"`;
}

const LIST_LABEL = {
  scripts: (item) => `script src: ${cut(item)}`,
  links: (item) => `link href: ${cut(item)}`,
  css: (_item, m) => `banner CSS: "${cut(m, 80)}"`,
  html: (_item, m) => `HTML mengandung "${cut(m, 80)}"`,
  url: (item) => `URL halaman: ${cut(item)}`,
};

// Evaluasi satu rule terhadap konteks → hit { source, evidence, confidence, version } | null
function evaluate(rule, ctx, sig) {
  const { source, pat } = rule;
  const hit = (evidence, version = null) => ({ source, evidence, confidence: pat.conf, version });

  switch (source) {
    case 'headers': {
      const v = ctx.headers[rule.key];
      if (v === undefined) return null;
      const m = test(pat, v);
      return m && hit(`header ${ctx.headerNames[rule.key] || rule.key}: ${cut(v)}`, m.version);
    }
    case 'cookies': {
      const name = ctx.cookies.find((n) => rule.re.test(n));
      return name ? hit(`cookie "${name}" ada`) : null;
    }
    case 'meta': {
      for (const v of ctx.meta[rule.key] || []) {
        const m = test(pat, v);
        if (m) return hit(`meta ${rule.key}="${cut(v, 80)}"`, m.version);
      }
      return null;
    }
    case 'js': {
      const v = ctx.js[rule.key];
      if (v === undefined) return null;
      const m = test(pat, v);
      if (!m) return null;
      const vr = sig.versionRegex && sig.versionRegex.exec(v);
      return hit(jsEvidence(rule.key, v), m.version || cleanVersion(vr && vr[1]));
    }
    case 'dom': {
      const d = ctx.dom[rule.key];
      if (!d || !d.count) return null;
      if (!rule.attr) return hit(`DOM ${rule.key} ditemukan (${d.count}×)`);
      const av = d.attrs && d.attrs[rule.attr];
      if (av === undefined) return null;
      const m = test(pat, av);
      if (!m) return null;
      const vr = sig.versionRegex && sig.versionRegex.exec(av);
      return hit(`DOM ${rule.key} → ${rule.attr}="${cut(av, 60)}"`, m.version || cleanVersion(vr && vr[1]));
    }
    case 'cssVars': {
      const v = ctx.cssVars[rule.key];
      return v ? hit(`CSS variable ${rule.key}: ${cut(v, 40)}`) : null;
    }
    default: {
      // scripts / links / css / html / url → daftar string
      if (!pat.re) return null;
      const list = source === 'html' ? [ctx.html] : source === 'url' ? [ctx.url] : ctx[source];
      for (const item of list || []) {
        const m = test(pat, item);
        if (m) return hit(LIST_LABEL[source](item, m.match), m.version);
      }
      return null;
    }
  }
}

// Gabungkan beberapa bukti: 1 − Π(1 − c)
const combine = (confs) => Math.min(100, Math.round(100 * (1 - confs.reduce((acc, c) => acc * (1 - c / 100), 1))));

function pickVersion(hits) {
  const sorted = [...hits].sort((a, b) => VERSION_ORDER.indexOf(a.source) - VERSION_ORDER.indexOf(b.source));
  const h = sorted.find((x) => x.version);
  return h ? h.version : null;
}

function buildExtra(sig, ctx) {
  const extra = {};
  for (const [label, path] of Object.entries(sig.extra || {})) {
    const v = ctx.js[path];
    if (v !== undefined && !v.startsWith('[')) extra[label] = v;
  }
  if (sig.ids) {
    const re = new RegExp(sig.ids.source, sig.ids.flags.includes('g') ? sig.ids.flags : `${sig.ids.flags}g`);
    const text = [ctx.html, ...ctx.scripts, ...Object.values(ctx.js)].join('\n');
    const ids = new Set();
    for (const m of text.matchAll(re)) {
      ids.add(m[1] || m[0]);
      if (ids.size >= 10) break;
    }
    if (ids.size) extra.ID = [...ids].join(', ');
  }
  return extra;
}

// Tambahkan teknologi yang di-"imply" oleh teknologi lain (mis. Next.js → React)
function applyImplies(found) {
  let changed = true;
  while (changed) {
    changed = false;
    for (const tech of [...found.values()]) {
      for (const name of SIG_BY_NAME.get(tech.name)?.implies || []) {
        const target = found.get(name);
        const note = `diimplikasikan oleh ${tech.name}`;
        if (target) {
          if (!target.evidence.includes(note)) target.evidence.push(note);
          continue;
        }
        const sig = SIG_BY_NAME.get(name);
        if (!sig) continue;
        found.set(name, {
          name,
          category: sig.category,
          version: null,
          confidence: Math.round(tech.confidence * 0.9),
          evidence: [note],
          extra: {},
        });
        changed = true;
      }
    }
  }
}

// Odoo: versi & edisi (Community / Enterprise) dari JSON-RPC, variabel window, atau path aset
function enrichOdoo(tech, ctx) {
  const rpc = ctx.odooRpc;
  let edition = null;

  if (rpc && rpc.ok) {
    const info = Array.isArray(rpc.server_version_info) ? rpc.server_version_info : null;
    tech.evidence.unshift(`JSON-RPC /web/webclient/version_info → server_version "${rpc.server_version}"`);
    tech.version = cleanVersion(rpc.server_serie) || cleanVersion(rpc.server_version) || tech.version;
    tech.confidence = 100;
    tech.extra['Server version'] = String(rpc.server_version);
    if (info) tech.extra['Version info'] = JSON.stringify(info);
    if (rpc.protocol_version !== undefined) tech.extra['Protocol'] = String(rpc.protocol_version);
    if (info && info[5] === 'e') edition = 'Enterprise (server_version_info → "e")';
    else if (/\+e\b|e$/.test(String(rpc.server_version))) edition = 'Enterprise (server_version berakhiran "+e")';
    else edition = 'Community (tanpa flag enterprise)';
  } else if (rpc && rpc.error) {
    tech.extra['version_info RPC'] = `gagal: ${rpc.error}`;
  }

  if (!edition || edition.startsWith('Community')) {
    const js = ctx.js;
    const sv = js['odoo.info.server_version'] || js['odoo.__session_info__.server_version'];
    const enterpriseHint =
      (js['odoo.info.isEnterprise'] === 'true' && 'Enterprise (odoo.info.isEnterprise = true)') ||
      ((js['odoo.info.server_version_info.5'] === 'e' || js['odoo.__session_info__.server_version_info.5'] === 'e') &&
        'Enterprise (server_version_info → "e")') ||
      (sv && /\+e\b|e$/.test(sv) && `Enterprise (server_version "${sv}")`) ||
      (ctx.scripts.concat(ctx.links).some((u) => /\/web_enterprise\//.test(u)) && 'Enterprise (aset /web_enterprise/ dimuat)');
    if (enterpriseHint) edition = enterpriseHint;
    else if (!edition && sv) edition = 'Community (server_version tanpa "+e")';
  }

  const db = ctx.js['odoo.info.db'] || ctx.js['odoo.__session_info__.db'];
  if (db && !tech.extra.Database) tech.extra.Database = db;
  if (edition) {
    tech.extra.Edition = edition.split(' (')[0];
    tech.evidence.push(`edisi: ${edition}`);
  }
}

function detect(ctx) {
  const found = new Map();
  for (const { sig, rules } of COMPILED) {
    const hits = rules.map((r) => evaluate(r, ctx, sig)).filter(Boolean);
    if (!hits.length) continue;
    const confidence = combine(hits.map((h) => h.confidence));
    if (confidence < (sig.minConfidence ?? MIN_CONFIDENCE)) continue;
    found.set(sig.name, {
      name: sig.name,
      category: sig.category,
      version: pickVersion(hits),
      confidence,
      evidence: [...new Set(hits.map((h) => h.evidence))],
      extra: buildExtra(sig, ctx),
    });
  }
  applyImplies(found);
  if (found.has('Odoo')) enrichOdoo(found.get('Odoo'), ctx);

  const order = (c) => {
    const i = TSD_CATEGORIES.indexOf(c);
    return i === -1 ? 99 : i;
  };
  return [...found.values()].sort(
    (a, b) => order(a.category) - order(b.category) || b.confidence - a.confidence || a.name.localeCompare(b.name)
  );
}

function securityReport(ctx, headersCaptured) {
  return SECURITY_HEADERS.map((s) => {
    let value = ctx.headers[s.header];
    let note = null;
    if (value === undefined && s.reportOnly && ctx.headers[s.reportOnly] !== undefined) {
      value = ctx.headers[s.reportOnly];
      note = 'report-only';
    }
    if (value === undefined && s.meta && ctx.meta[s.meta]) {
      value = ctx.meta[s.meta][0];
      note = 'via <meta http-equiv>';
    }
    const present = value !== undefined ? true : headersCaptured ? false : null; // null = tidak diketahui
    return { name: s.name, header: s.header, present, value: value ?? null, note };
  });
}

/* ------------------------------ Audit keamanan ------------------------------ */
// Audit pasif: hanya dari respons yang sudah diterima browser, tanpa request tambahan ke server.

const SEVERITY_PENALTY = { high: 25, medium: 10, low: 4, info: 0 };
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
const EDGE_PROVIDERS = ['Cloudflare', 'Akamai', 'Fastly', 'AWS CloudFront', 'Vercel', 'Netlify'];
const SESSION_COOKIE = /sess|sid$|^sid|auth|token|login|jwt|remember/i;
const NON_SESSION_COOKIE = /csrf|xsrf|^_ga|^_gid|^_gat|^_fbp|^_fbc|^_hj|^_cl|^_uet|^__utm|^_gcl|^ajs_|^amplitude/i;

// Bandingkan versi "1.2.3" (awalan non-angka seperti "saas~" diabaikan)
function compareVersions(a, b) {
  const parse = (v) => (String(v).match(/\d+(?:\.\d+)*/) || ['0'])[0].split('.').map(Number);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

function vulnMatches(rule, version) {
  if (rule.any) return true;
  if (!version) return false;
  if (rule.below && compareVersions(version, rule.below) < 0) return true;
  return (rule.ranges || []).some(([from, to]) => compareVersions(version, from) >= 0 && compareVersions(version, to) < 0);
}

function parseCsp(value) {
  const dirs = {};
  for (const part of String(value).split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) dirs[name.toLowerCase()] = sources.map((s) => s.toLowerCase());
  }
  return dirs;
}

const gradeOf = (score) => (score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F');

function auditHeaders(H, ctx, https, add, pass) {
  const label = (name) => ctx.headerNames[name] || name;

  // HSTS
  if (https) {
    const hsts = H['strict-transport-security'];
    if (!hsts) {
      add('medium', 'HSTS tidak aktif', 'Tanpa Strict-Transport-Security, pengguna bisa diarahkan ke versi HTTP (SSL stripping). Contoh: max-age=31536000; includeSubDomains');
    } else {
      const maxAge = Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0);
      if (maxAge < 15552000) add('low', 'max-age HSTS terlalu pendek', `max-age=${maxAge} detik (< 180 hari). Disarankan ≥ 31536000.`, hsts);
      else pass('HSTS aktif', hsts);
    }
  }

  // Content-Security-Policy
  const cspHeader = H['content-security-policy'];
  const cspValue = cspHeader || (ctx.meta['content-security-policy'] || [])[0];
  if (!cspValue) {
    const ro = H['content-security-policy-report-only'];
    if (ro) add('low', 'CSP hanya report-only', 'Pelanggaran CSP hanya dilaporkan, tidak diblokir.', cut(ro, 200));
    else add('medium', 'Tidak ada Content-Security-Policy', 'Tanpa CSP, dampak serangan XSS / injeksi script tidak dibatasi.');
  } else {
    const csp = parseCsp(cspValue);
    const script = csp['script-src'] || csp['default-src'];
    if (!script) {
      add('medium', 'CSP tidak membatasi script', 'Tidak ada direktif script-src maupun default-src.', cut(cspValue, 200));
    } else {
      const strict = script.some((s) => /^'(?:nonce-|sha(?:256|384|512)-|strict-dynamic)/.test(s));
      const issues = [];
      if (script.includes("'unsafe-inline'") && !strict) issues.push("'unsafe-inline'");
      if (script.some((s) => ['*', 'http:', 'https:', 'data:'].includes(s))) issues.push('sumber wildcard (*, http:, https:, data:)');
      if (issues.length) add('medium', 'CSP script-src terlalu longgar', `Mengizinkan ${issues.join(' & ')} sehingga tidak efektif menahan XSS.`, `script-src ${script.join(' ')}`);
      else pass('CSP membatasi script', cut(cspValue, 200));
      if (script.includes("'unsafe-eval'")) add('low', "CSP mengizinkan 'unsafe-eval'", 'eval() / new Function() tetap diizinkan.', `script-src ${script.join(' ')}`);
    }
  }

  // Clickjacking (frame-ancestors hanya berlaku dari header, bukan <meta>)
  const xfo = H['x-frame-options'];
  const frameAncestors = cspHeader && parseCsp(cspHeader)['frame-ancestors'];
  if (frameAncestors) pass('Proteksi clickjacking (CSP frame-ancestors)', `frame-ancestors ${frameAncestors.join(' ')}`);
  else if (xfo && /deny|sameorigin/i.test(xfo)) pass('Proteksi clickjacking (X-Frame-Options)', `X-Frame-Options: ${xfo}`);
  else add('medium', 'Rentan clickjacking', 'Tidak ada X-Frame-Options (DENY/SAMEORIGIN) maupun CSP frame-ancestors, jadi halaman bisa di-embed dalam iframe situs lain.', xfo ? `X-Frame-Options: ${xfo}` : null);

  // MIME sniffing
  if (/nosniff/i.test(H['x-content-type-options'] || '')) pass('X-Content-Type-Options: nosniff');
  else add('low', 'X-Content-Type-Options tidak ada', 'Browser bisa menebak MIME type (MIME sniffing). Set ke: nosniff.');

  // Referrer-Policy
  const rp = H['referrer-policy'];
  if (!rp) add('low', 'Referrer-Policy tidak di-set', 'URL lengkap bisa bocor ke situs lain lewat header Referer. Contoh: strict-origin-when-cross-origin.');
  else if (/unsafe-url|no-referrer-when-downgrade/i.test(rp)) add('low', 'Referrer-Policy lemah', 'Kebijakan ini mengirim URL lengkap ke situs lain.', `Referrer-Policy: ${rp}`);
  else pass('Referrer-Policy', rp);

  // Permissions-Policy
  if (H['permissions-policy']) pass('Permissions-Policy', cut(H['permissions-policy'], 160));
  else add('info', 'Permissions-Policy tidak di-set', 'Akses fitur browser (kamera, mikrofon, geolokasi) tidak dibatasi untuk iframe / script pihak ketiga.');

  // CORS
  if (H['access-control-allow-origin'] === '*') {
    add('low', 'CORS terbuka (*)', 'Dokumen ini boleh dibaca oleh origin mana pun.', 'Access-Control-Allow-Origin: *');
  }

  // Information disclosure
  if (H.server && /\d/.test(H.server)) {
    add('low', 'Versi web server terekspos', 'Header Server menampilkan versi sehingga penyerang mudah mencocokkan CVE. Nginx: server_tokens off; Apache: ServerTokens Prod.', `${label('server')}: ${H.server}`);
  } else if (H.server) {
    pass('Header Server tanpa versi', `${label('server')}: ${H.server}`);
  }
  for (const name of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
    if (H[name]) add('low', `Header ${label(name)} terekspos`, 'Membocorkan teknologi / versi backend. Hapus header ini di konfigurasi server.', `${label(name)}: ${cut(H[name], 100)}`);
  }
}

function auditCookies(cookies, https, add, pass) {
  if (!cookies.length) return;
  const names = (list) => list.map((c) => c.name).join(', ');
  const session = cookies.filter((c) => SESSION_COOKIE.test(c.name) && !NON_SESSION_COOKIE.test(c.name));
  const noHttpOnly = session.filter((c) => !c.httpOnly);
  const noSecure = https ? cookies.filter((c) => !c.secure) : [];
  const sessionNoSecure = noSecure.filter((c) => session.includes(c));
  const otherNoSecure = noSecure.filter((c) => !session.includes(c));
  const sameSiteNone = session.filter((c) => c.sameSite === 'no_restriction');

  if (noHttpOnly.length) add('medium', 'Cookie sesi tanpa HttpOnly', 'Cookie ini bisa dicuri lewat JavaScript bila ada celah XSS.', names(noHttpOnly));
  if (sessionNoSecure.length) add('medium', 'Cookie sesi tanpa flag Secure', 'Cookie bisa ikut terkirim lewat koneksi HTTP yang tidak terenkripsi.', names(sessionNoSecure));
  if (sameSiteNone.length) add('low', 'Cookie sesi SameSite=None', 'Cookie ikut terkirim pada request lintas situs, jadi perlindungan CSRF bergantung pada token.', names(sameSiteNone));
  if (otherNoSecure.length) add('info', 'Cookie lain tanpa flag Secure', `${otherNoSecure.length} cookie non-sesi (umumnya analytics) tidak memakai Secure.`, names(otherNoSecure.slice(0, 10)));
  if (session.length && !noHttpOnly.length && !sessionNoSecure.length) pass('Cookie sesi memakai HttpOnly & Secure', names(session));
}

function auditSecurity(ctx, { url, headersCaptured, technologies, cookies }) {
  const findings = [];
  const passed = [];
  const add = (severity, title, detail, evidence = null) => findings.push({ severity, title, detail, evidence });
  const pass = (title, evidence = null) => passed.push({ title, evidence });
  const techList = (filter) => technologies.filter(filter).map((t) => (t.version ? `${t.name} ${t.version}` : t.name));
  const https = /^https:/i.test(url);

  if (https) pass('Halaman dimuat lewat HTTPS');
  else add('high', 'Tidak memakai HTTPS', 'Data (termasuk login & cookie) dikirim tanpa enkripsi dan bisa disadap atau dimodifikasi.', url);

  if (https) {
    const insecure = [...ctx.scripts, ...ctx.links].filter((u) => /^http:\/\//i.test(u));
    if (insecure.length) add('medium', 'Mixed content', `${insecure.length} resource dimuat lewat HTTP di halaman HTTPS.`, insecure.slice(0, 3).join('\n'));
  }

  if (headersCaptured) auditHeaders(ctx.headers, ctx, https, add, pass);
  else add('info', 'Headers tidak tertangkap', 'Reload halaman agar pengecekan security headers & info disclosure bisa dilakukan.');

  auditCookies(cookies, https, add, pass);

  const generator = (ctx.meta.generator || []).find((g) => /\d/.test(g));
  if (generator) add('info', 'Versi CMS terekspos di meta generator', 'Tag <meta name="generator"> menampilkan versi platform.', generator);

  // Versi rentan / End-of-Life
  for (const rule of TSD_VULN_RULES) {
    const t = technologies.find((x) => x.name === rule.tech);
    if (t && vulnMatches(rule, t.version)) add(rule.severity, rule.title, rule.detail, t.version ? `${t.name} ${t.version}` : t.name);
  }

  // WAF / lapisan proteksi
  const waf = techList((t) => t.category === 'WAF/Proteksi');
  const edge = techList((t) => EDGE_PROVIDERS.includes(t.name));
  if (waf.length) pass(`Proteksi terdeteksi: ${waf.join(', ')}`);
  else if (edge.length) add('info', 'WAF tidak terkonfirmasi', `Situs berada di belakang ${edge.join(', ')}. WAF mungkin aktif, tapi tidak bisa dipastikan secara pasif.`);
  else add('low', 'Tidak terdeteksi WAF / CDN', 'Server kemungkinan terekspos langsung ke internet tanpa lapisan proteksi (WAF, rate limiting, DDoS).');

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + SEVERITY_PENALTY[f.severity], 0));

  return {
    score,
    grade: gradeOf(score),
    complete: headersCaptured,
    counts,
    findings,
    passed,
    infrastructure: {
      'Server header': ctx.headers.server || null,
      'Web server': techList((t) => t.category === 'Web Server'),
      'CDN/Hosting': techList((t) => t.category === 'CDN/Hosting'),
      'WAF/Proteksi': waf,
      Backend: techList((t) => t.category === 'Backend'),
      Platform: techList((t) => t.category === 'CMS/Platform' || t.category === 'ERP'),
    },
  };
}

/* ------------------------------ Konteks & data ------------------------------ */

function buildContext(rec, page, cookies) {
  const headers = {};
  const headerNames = {};
  for (const { name, value } of rec.headers || []) {
    const k = name.toLowerCase();
    headers[k] = headers[k] !== undefined ? `${headers[k]}\n${value}` : value;
    headerNames[k] = name;
  }
  return {
    headers,
    headerNames,
    cookies,
    meta: page?.meta || {},
    scripts: page?.scripts || [],
    links: page?.links || [],
    js: page?.js || {},
    dom: page?.dom || {},
    cssVars: page?.cssVars || {},
    css: page?.css || [],
    html: page?.html || '',
    url: page?.url || rec.url || '',
    odooRpc: page?.odooRpc || null,
  };
}

// Cookie dari chrome.cookies (termasuk HttpOnly) + header Set-Cookie + document.cookie.
// Hanya nama & flag yang disimpan — nilai cookie tidak pernah dibaca.
async function collectCookies(url, rec, page) {
  const details = new Map();
  try {
    for (const c of await chrome.cookies.getAll({ url })) {
      details.set(c.name, { name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite });
    }
  } catch {
    /* URL tidak valid untuk cookies API */
  }
  for (const h of rec.headers || []) {
    if (h.name.toLowerCase() !== 'set-cookie') continue;
    for (const line of h.value.split('\n')) {
      const name = line.split('=')[0].trim();
      if (!name || details.has(name)) continue;
      const sameSite = ((/;\s*samesite=(\w+)/i.exec(line) || [])[1] || 'unspecified').toLowerCase();
      details.set(name, {
        name,
        secure: /;\s*secure\b/i.test(line),
        httpOnly: /;\s*httponly\b/i.test(line),
        sameSite: sameSite === 'none' ? 'no_restriction' : sameSite,
      });
    }
  }
  const names = new Set([...(page?.cookies || []), ...details.keys()]);
  return { names: [...names], details: [...details.values()] };
}

async function analyze(rec, page) {
  const url = page?.url || rec.url;
  const cookies = await collectCookies(url, rec, page);
  const ctx = buildContext(rec, page, cookies.names);
  const technologies = detect(ctx);
  const headersCaptured = Boolean(rec.headers);
  let domain = '';
  try {
    domain = new URL(url).hostname;
  } catch {
    /* biarkan kosong */
  }
  return {
    url,
    domain,
    title: page?.title || '',
    scannedAt: new Date().toISOString(),
    pageScanned: Boolean(page),
    headersCaptured,
    statusCode: rec.statusCode ?? null,
    technologies,
    security: securityReport(ctx, headersCaptured),
    audit: auditSecurity(ctx, { url, headersCaptured, technologies, cookies: cookies.details }),
  };
}

/* --------------------------- Storage, lock & badge --------------------------- */

// Serialisasi operasi per tab agar event headers & data halaman tidak saling menimpa
const locks = new Map();
function withLock(tabId, fn) {
  const next = (locks.get(tabId) || Promise.resolve()).catch(() => {}).then(fn);
  locks.set(tabId, next);
  next.finally(() => {
    if (locks.get(tabId) === next) locks.delete(tabId);
  });
  return next;
}

async function loadRecord(tabId) {
  const key = storageKey(tabId);
  return (await chrome.storage.session.get(key))[key] || null;
}

const saveRecord = (tabId, rec) => chrome.storage.session.set({ [storageKey(tabId)]: rec });

function updateBadge(tabId, result) {
  const n = result ? result.technologies.length : 0;
  chrome.action.setBadgeText({ tabId, text: n ? String(n) : '' }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#4f46e5' }).catch(() => {});
  chrome.action.setBadgeTextColor?.({ tabId, color: '#ffffff' })?.catch?.(() => {});
}

const stripHash = (u) => String(u || '').split('#')[0];

// Headers valid jika berasal dari navigasi dokumen yang sama (bukan sisa halaman sebelumnya)
function headersMatchPage(rec, page) {
  if (!rec || !rec.headers || !rec.headersTime) return false;
  if (page.timeOrigin && rec.headersTime < page.timeOrigin - 2000) return false;
  try {
    return new URL(rec.url).host === new URL(page.url).host;
  } catch {
    return false;
  }
}

/* ---------------------------------- Events ---------------------------------- */

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const headers = (details.responseHeaders || []).map((h) => ({
      name: h.name,
      value: h.value ?? (h.binaryValue ? '[binary]' : ''),
    }));
    // Navigasi baru → rekam ulang dari nol (otomatis menghapus hasil halaman lama)
    withLock(details.tabId, async () => {
      const rec = {
        url: stripHash(details.url),
        statusCode: details.statusCode,
        statusLine: details.statusLine || '',
        headers,
        headersTime: details.timeStamp,
      };
      rec.result = await analyze(rec, null);
      await saveRecord(details.tabId, rec);
      updateBadge(details.tabId, rec.result);
    });
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders', 'extraHeaders']
);

// IP server hanya tersedia setelah respons mulai diterima
chrome.webRequest.onResponseStarted.addListener(
  (details) => {
    if (details.tabId < 0 || !details.ip) return;
    withLock(details.tabId, async () => {
      const rec = await loadRecord(details.tabId);
      if (!rec || rec.url !== stripHash(details.url)) return;
      rec.ip = details.ip;
      await saveRecord(details.tabId, rec);
    });
  },
  { urls: ['<all_urls>'], types: ['main_frame'] }
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'TSD_PAGE_DATA' || !sender.tab || sender.frameId !== 0) return false;
  const tabId = sender.tab.id;
  const page = msg.data;
  withLock(tabId, async () => {
    let rec = await loadRecord(tabId);
    if (!headersMatchPage(rec, page)) {
      // Headers tidak tertangkap (extension baru dipasang, bfcache, service worker, dll)
      rec = { url: stripHash(page.url), statusCode: null, statusLine: '', headers: null, headersTime: null };
    }
    rec.result = await analyze(rec, page);
    await saveRecord(tabId, rec);
    updateBadge(tabId, rec.result);
  })
    .then(() => sendResponse({ ok: true }))
    .catch((e) => sendResponse({ ok: false, error: String(e) }));
  return true;
});

// Badge per-tab di-reset Chrome saat navigasi commit → pasang lagi setelah halaman selesai dimuat
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status !== 'complete') return;
  loadRecord(tabId).then((rec) => rec && updateBadge(tabId, rec.result));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  locks.delete(tabId);
  chrome.storage.session.remove(storageKey(tabId));
});
