/**
 * TechStack Detector — popup.
 * Membaca hasil deteksi tab aktif dari chrome.storage.session lalu merendernya.
 */
const state = { tab: null, rec: null, expanded: new Set(), scanning: false };
const $ = (id) => document.getElementById(id);
const storageKey = (tabId) => `tab_${tabId}`;

// Helper pembuat elemen (pakai textContent → aman dari HTML milik halaman)
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

const chevron = () => {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '14');
  svg.setAttribute('height', '14');
  svg.classList.add('chev');
  svg.innerHTML = '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M9 6l6 6-6 6"/>';
  return svg;
};

const confLevel = (c) => (c >= 80 ? 'high' : c >= 50 ? 'mid' : 'low');
const SEV_LABEL = { high: 'Tinggi', medium: 'Sedang', low: 'Rendah', info: 'Info', pass: 'OK' };

function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 1600);
}

function isScannable(url) {
  return /^https?:\/\//.test(url || '');
}

const hostOf = (u) => {
  try {
    return new URL(u).host;
  } catch {
    return '';
  }
};

/* --------------------------------- Render --------------------------------- */

function renderItem(id, name, chips, details) {
  const item = h('div', { class: `item${state.expanded.has(id) ? ' open' : ''}` });
  const row = h('button', { class: 'row', 'aria-expanded': String(state.expanded.has(id)) }, h('span', { class: 'name' }, name), chips, chevron());
  row.addEventListener('click', () => {
    const open = item.classList.toggle('open');
    row.setAttribute('aria-expanded', String(open));
    if (open) state.expanded.add(id);
    else state.expanded.delete(id);
  });
  item.append(row, h('div', { class: 'details' }, details));
  return item;
}

function renderTech(t) {
  const extraEntries = Object.entries(t.extra || {});
  const chips = [
    t.extra && t.extra.Edition ? h('span', { class: 'chip edition' }, t.extra.Edition) : null,
    t.version ? h('span', { class: 'chip', title: 'Versi' }, t.version) : null,
    h('span', { class: `conf ${confLevel(t.confidence)}`, title: 'Confidence' }, `${t.confidence}%`),
  ];
  const details = [
    h('h4', {}, 'Evidence'),
    h('ul', { class: 'evidence' }, t.evidence.map((e) => h('li', {}, e))),
    extraEntries.length
      ? [h('h4', {}, 'Detail'), h('dl', { class: 'kv' }, extraEntries.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]))]
      : null,
  ];
  return renderItem(`t:${t.name}`, t.name, chips, details);
}

function renderSecurity(s) {
  const label = s.present === true ? 'Ada' : s.present === false ? 'Tidak ada' : '?';
  const cls = s.present === true ? 'yes' : s.present === false ? 'no' : 'unknown';
  const chips = [h('span', { class: `sec-state ${cls}` }, s.note ? `${label} · ${s.note}` : label)];
  const details = h('dl', { class: 'kv' }, [
    h('dt', {}, 'Header'),
    h('dd', {}, s.header),
    h('dt', {}, 'Nilai'),
    h('dd', {}, s.value ?? (s.present === null ? 'headers tidak tertangkap' : '—')),
  ]);
  return renderItem(`s:${s.name}`, s.name, chips, details);
}

function renderGroup(title, nodes) {
  return h(
    'div',
    { class: 'group' },
    h('div', { class: 'group-title' }, h('span', {}, title), h('span', {}, String(nodes.length))),
    h('div', { class: 'items' }, nodes)
  );
}

function renderTechPanel(result) {
  const list = $('techList');
  const notice = $('notice');
  list.replaceChildren();
  notice.replaceChildren();

  if (!result) {
    list.append(h('div', { class: 'empty' }, state.scanning ? 'Memindai halaman…' : 'Belum ada data. Klik ↻ untuk memindai.'));
    return;
  }
  if (!result.headersCaptured) {
    notice.append(
      h('div', { class: 'notice' }, 'Response headers tidak tertangkap (dimuat sebelum extension aktif / dari cache / service worker). Reload halaman untuk analisis header lengkap.')
    );
  }
  if (!result.pageScanned) {
    notice.append(h('div', { class: 'notice' }, 'Hanya berdasarkan headers — konten halaman belum dipindai.'));
  }

  const byCat = new Map();
  for (const t of result.technologies) {
    if (!byCat.has(t.category)) byCat.set(t.category, []);
    byCat.get(t.category).push(t);
  }
  const cats = [...byCat.keys()].sort((a, b) => {
    const ia = TSD_CATEGORIES.indexOf(a);
    const ib = TSD_CATEGORIES.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
  for (const c of cats) list.append(renderGroup(c, byCat.get(c).map(renderTech)));
  if (!result.technologies.length) list.append(h('div', { class: 'empty' }, 'Tidak ada teknologi yang terdeteksi.'));
}

function renderFinding(f) {
  const details = [
    h('p', { class: 'finding-detail' }, f.detail),
    f.evidence ? [h('h4', {}, 'Evidence'), h('pre', { class: 'ev-pre' }, f.evidence)] : null,
  ];
  return renderItem(`f:${f.title}`, f.title, h('span', { class: `sev sev-${f.severity}` }, SEV_LABEL[f.severity]), details);
}

function renderSecurityPanel(rec) {
  const box = $('secPanel');
  box.replaceChildren();
  const result = rec && rec.result;
  const audit = result && result.audit;
  if (!audit) {
    box.append(h('div', { class: 'empty' }, state.scanning ? 'Memindai halaman…' : 'Belum ada data audit.'));
    return;
  }

  box.append(
    h(
      'div',
      { class: 'score-card' },
      h('div', { class: `grade grade-${audit.grade}`, title: audit.complete ? 'Grade' : 'Belum lengkap' }, audit.complete ? audit.grade : `${audit.grade}?`),
      h(
        'div',
        { class: 'score-info' },
        h('div', { class: 'score-title' }, `Skor keamanan ${audit.score}/100`),
        h('div', { class: 'sev-counts' }, ['high', 'medium', 'low'].map((s) => h('span', { class: `sev sev-${s}` }, `${audit.counts[s]} ${SEV_LABEL[s]}`))),
        audit.complete ? null : h('div', { class: 'summary' }, 'Belum lengkap: headers tidak tertangkap, reload halaman.')
      )
    )
  );

  // Infrastruktur: server, CDN, WAF, backend
  const infra = Object.entries(audit.infrastructure).filter(([, v]) => (Array.isArray(v) ? v.length : v));
  if (rec.ip) infra.unshift(['IP server', rec.ip]);
  if (infra.length) {
    box.append(
      h(
        'div',
        { class: 'group' },
        h('div', { class: 'group-title' }, h('span', {}, 'Infrastruktur')),
        h('dl', { class: 'kv infra' }, infra.map(([k, v]) => [h('dt', {}, k), h('dd', {}, Array.isArray(v) ? v.join(', ') : v)]))
      )
    );
  }

  if (audit.findings.length) box.append(renderGroup('Temuan', audit.findings.map(renderFinding)));
  box.append(renderGroup('Security headers', result.security.map(renderSecurity)));
  if (audit.passed.length) {
    box.append(
      renderGroup(
        'Lolos',
        audit.passed.map((p) =>
          renderItem(`p:${p.title}`, p.title, h('span', { class: 'sev sev-pass' }, SEV_LABEL.pass), p.evidence ? h('pre', { class: 'ev-pre' }, p.evidence) : h('p', { class: 'finding-detail' }, 'Tidak ada detail tambahan.'))
        )
      )
    );
  }
  box.append(
    h(
      'p',
      { class: 'footnote' },
      'Audit pasif: hanya dari respons yang sudah diterima browser, tanpa memindai server. Sertifikat TLS, port terbuka, dan path sensitif tidak dicek. Data versi rentan ada di TSD_VULN_RULES (signatures.js).'
    )
  );
}

function renderHeadersPanel(rec) {
  const box = $('hdrList');
  const q = $('hdrFilter').value.trim().toLowerCase();
  box.replaceChildren();
  $('statusLine').textContent = rec && rec.headers ? rec.statusLine || `HTTP ${rec.statusCode}` : '';

  if (!rec || !rec.headers) {
    box.append(h('div', { class: 'empty' }, 'Headers belum tertangkap. Reload halaman lalu buka popup lagi.'));
    return;
  }
  const rows = rec.headers.filter((x) => !q || x.name.toLowerCase().includes(q) || x.value.toLowerCase().includes(q));
  for (const x of rows) box.append(h('div', { class: 'hdr' }, h('span', { class: 'hdr-name' }, x.name), ': ', x.value));
  if (!rows.length) box.append(h('div', { class: 'empty' }, 'Tidak ada header yang cocok.'));
}

function render() {
  const rec = state.rec;
  const result = rec && rec.result;
  const n = result ? result.technologies.length : 0;

  $('domain').textContent = (result && result.domain) || hostOf(state.tab?.url) || '—';
  const audit = result && result.audit;
  $('summary').textContent =
    state.scanning && !result
      ? 'Memindai…'
      : result
        ? `${n} teknologi terdeteksi${audit ? ` · keamanan ${audit.grade}${audit.complete ? '' : '?'} (${audit.score})` : ''}`
        : 'Belum dipindai';
  $('techCount').textContent = result ? String(n) : '';
  $('secCount').textContent = audit ? String(audit.counts.high + audit.counts.medium + audit.counts.low) : '';
  $('hdrCount').textContent = rec && rec.headers ? String(rec.headers.length) : '';
  $('btnCopy').disabled = $('btnExport').disabled = !result;
  $('btnRescan').classList.toggle('spinning', state.scanning);

  renderTechPanel(result);
  renderSecurityPanel(rec);
  renderHeadersPanel(rec);
}

/* --------------------------------- Actions -------------------------------- */

function exportData() {
  const rec = state.rec;
  const r = rec.result;
  return {
    tool: 'TechStack Detector',
    url: r.url,
    domain: r.domain,
    title: r.title,
    scannedAt: r.scannedAt,
    statusCode: r.statusCode,
    ip: rec.ip || null,
    audit: r.audit || null,
    technologies: r.technologies.map(({ name, category, version, confidence, evidence, extra }) => ({
      name,
      category,
      version,
      confidence,
      evidence,
      extra,
    })),
    security: r.security,
    headers: rec.headers || [],
  };
}

async function copyJson() {
  try {
    await navigator.clipboard.writeText(JSON.stringify(exportData(), null, 2));
    toast('JSON disalin ke clipboard');
  } catch {
    toast('Gagal menyalin');
  }
}

function exportJson() {
  const data = exportData();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const a = h('a', { href: url, download: `techstack-${data.domain || 'site'}-${stamp}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Minta content script memindai ulang; jika belum ada (tab lama), suntikkan dulu
async function rescan() {
  const tab = state.tab;
  if (!tab || !isScannable(tab.url)) return;
  state.scanning = true;
  render();
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'TSD_RESCAN' });
  } catch {
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['inject.js'], world: 'MAIN' });
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['signatures.js', 'content.js'] });
      await new Promise((r) => setTimeout(r, 1500)); // beri waktu scan awal selesai
    } catch (e) {
      toast(`Tidak bisa memindai: ${e.message || e}`);
    }
  }
  state.scanning = false;
  render();
}

/* ---------------------------------- Init ---------------------------------- */

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.tab = tab;

  if (tab.favIconUrl && /^(https?:|data:)/.test(tab.favIconUrl)) {
    $('favicon').src = tab.favIconUrl;
    $('favicon').hidden = false;
  }

  document.querySelectorAll('.tab').forEach((btn) =>
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${btn.dataset.tab}`));
    })
  );
  $('hdrFilter').addEventListener('input', () => renderHeadersPanel(state.rec));
  $('btnCopy').addEventListener('click', copyJson);
  $('btnExport').addEventListener('click', exportJson);
  $('btnRescan').addEventListener('click', rescan);

  if (!isScannable(tab.url)) {
    $('domain').textContent = hostOf(tab.url) || 'Halaman internal';
    $('summary').textContent = 'Halaman ini tidak bisa dipindai';
    $('btnRescan').disabled = $('btnCopy').disabled = $('btnExport').disabled = true;
    $('techList').replaceChildren(h('div', { class: 'empty' }, 'Buka website http/https untuk mendeteksi tech stack.'));
    return;
  }

  // Update otomatis saat background menyimpan hasil baru
  chrome.storage.onChanged.addListener((changes, area) => {
    const change = changes[storageKey(tab.id)];
    if (area !== 'session' || !change) return;
    state.rec = change.newValue || null;
    render();
  });

  const key = storageKey(tab.id);
  state.rec = (await chrome.storage.session.get(key))[key] || null;
  // Abaikan record milik halaman lain (navigasi tanpa header baru)
  if (state.rec && hostOf(state.rec.url) !== hostOf(tab.url)) state.rec = null;
  render();

  if (!state.rec || !state.rec.result || !state.rec.result.pageScanned) rescan();
}

init();
