# TechStack Detector (Chrome Extension, Manifest V3)

Deteksi tech stack website secara detail: CMS, ERP (Odoo + versi & edisi), JS framework, backend,
web server, CDN/hosting, UI library, analytics, dan security headers. Vanilla JS, tanpa build step.

## Instalasi
1. Buka `chrome://extensions`
2. Aktifkan **Developer mode** (pojok kanan atas)
3. Klik **Load unpacked** → pilih folder ini (`D:\Project\extension`)
4. Pin extension, buka website apa pun, **reload halamannya** (supaya response headers tertangkap), lalu klik icon.

## Struktur
| File | Fungsi |
|---|---|
| `manifest.json` | Konfigurasi MV3 |
| `background.js` | Service worker: tangkap headers (webRequest), baca cookies, engine deteksi, simpan ke `storage.session`, badge |
| `content.js` | Kumpulkan meta, script/link, DOM, CSS var, banner CSS, cookie, JSON-RPC Odoo |
| `inject.js` | Jalan di MAIN world: baca variabel `window` + probe (React fiber, Vue app, Svelte, GTM) |
| `signatures.js` | Database signature |
| `popup.*` | UI popup |

## Alur
```
webRequest.onHeadersReceived ──► background (record baru per tab, hapus yang lama)
content.js ──postMessage──► inject.js (MAIN) ──► nilai window.*
content.js ──runtime.sendMessage(TSD_PAGE_DATA)──► background ──► detect() ──► storage.session + badge
popup ◄── storage.session (live update via storage.onChanged)
```

## Audit keamanan (tab "Keamanan")
Audit **pasif**: hanya dari respons yang sudah diterima browser, tanpa request tambahan ke server.
- Infrastruktur: IP server, header Server, web server, CDN, WAF/proteksi, backend, platform
- Skor 0–100 + grade A–F (penalti: tinggi 25, sedang 10, rendah 4, info 0)
- Cek: HTTPS, mixed content, HSTS, kualitas CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy,
  CORS `*`, versi server/backend yang terekspos, flag cookie sesi (HttpOnly/Secure/SameSite), versi rentan/EOL, WAF
- Tidak dicek: sertifikat TLS, port terbuka, path sensitif (butuh scanning aktif)

Aturan versi rentan ada di `TSD_VULN_RULES` (`signatures.js`), contoh:
```js
{ tech: 'jQuery', below: '3.5.0', severity: 'medium', title: '...', detail: 'CVE-...' }
{ tech: 'Next.js', ranges: [['14.0.0', '14.2.25']], severity: 'high', title: '...', detail: '...' }
{ tech: 'AngularJS', any: true, severity: 'medium', title: 'EOL', detail: '...' }
```
Data ini statis, jadi perbarui berkala.

## Menambah signature baru
Tambahkan object ke array `SIGNATURES` di `signatures.js`, lalu klik **Reload** di `chrome://extensions`.

```js
{
  name: 'Laravel Livewire',
  category: 'JS Framework',                       // salah satu TSD_CATEGORIES (atau tambah kategori baru)
  headers: { 'x-livewire': '' },                  // '' = cukup ada
  cookies: { 'livewire_*': { confidence: 40 } },  // wildcard * + override bobot
  meta:    { generator: /Livewire ?([\d.]+)?/i },  // grup #1 = versi
  scripts: [/livewire(?:\.min)?\.js(?:\?id=)?/],
  links:   [],
  js:      { 'Livewire': '', 'Livewire.version': /([\d.]+)/ },
  dom:     ['[wire\\:id]', { selector: '[data-lw-version]', attr: 'data-lw-version' }],
  cssVars: [],
  css:     [],
  html:    [/wire:snapshot/],
  versionRegex: /^(\d+\.\d+\.\d+)/,
  implies: ['Laravel'],
  extra:   { 'Versi (window)': 'Livewire.version' },
}
```

Jenis pola: `RegExp` (grup tangkap #1 = versi), string regex, `''` (cukup ada), atau `{ pattern, confidence }`.
Bobot default per sumber ada di `WEIGHTS` (`background.js`); bukti digabung dengan rumus `1 − Π(1 − bobot)`.
Butuh deteksi yang tidak bisa lewat path biasa? Tambah probe di `PROBES` (`inject.js`) dan rujuk dengan `js: { '@namaprobe': '' }`.

## Lisensi
[MIT](LICENSE)
