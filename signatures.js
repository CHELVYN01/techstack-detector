/**
 * TechStack Detector — database signature.
 * Dimuat oleh background.js (importScripts), content.js (content script) dan popup.html.
 *
 * Format satu signature (semua field opsional kecuali name & category):
 *   name          : nama teknologi (unik, dipakai juga oleh `implies`)
 *   category      : salah satu dari TSD_CATEGORIES
 *   headers       : { 'nama-header': pola }      dicocokkan dengan nilai response header (nama huruf kecil)
 *   cookies       : { 'nama_cookie': pola }      nama boleh pakai wildcard '*', mis. '_shopify_*' (nilai cookie tidak dibaca)
 *   meta          : { 'nama-meta': pola }        <meta name|property|http-equiv="..."> → atribut content
 *   scripts       : [pola]                       src <script> + resource script yang dimuat (Performance API)
 *   links         : [pola]                       href <link> + resource CSS
 *   js            : { 'path.global': pola }      variabel window, dibaca di MAIN world oleh inject.js.
 *                                                Path diawali '@' = probe khusus di inject.js (mis. '@react')
 *   dom           : ['selector' | { selector, attr, pattern }]   attr → nilai atribut dipakai untuk versi
 *   cssVars       : ['--custom-prop']            CSS custom property yang terdefinisi di :root / body
 *   css           : [pola]                       awal isi file CSS (banner, mis. "Bootstrap v5.3.2")
 *   html          : [pola]                       source HTML halaman (maks 500 KB)
 *   url           : [pola]                       URL halaman
 *   versionRegex  : RegExp                       ambil versi dari nilai `js` / atribut `dom` jika pola tidak punya grup
 *   implies       : ['Nama']                     teknologi lain yang otomatis ikut terdeteksi
 *   extra         : { 'Label': 'path.global' }   info tambahan dari variabel window (ditampilkan di detail)
 *   collect       : ['path.global']              variabel tambahan yang dibaca untuk enrichment (tanpa scoring)
 *   ids           : RegExp                       ekstrak ID (mis. G-XXXX) dari HTML/script → extra.ID
 *   minConfidence : angka                        ambang minimal agar ditampilkan (default 30)
 *
 * Pola boleh berupa:
 *   - RegExp            → grup tangkap #1 (jika ada) dianggap versi
 *   - string            → diubah jadi RegExp case-insensitive
 *   - ''                → cukup "ada" (untuk headers / cookies / meta / js)
 *   - { pattern, confidence } → override bobot default sumber tsb (0–100)
 *
 * Bobot default per sumber ada di background.js (WEIGHTS). Beberapa bukti digabung:
 * confidence = 1 − Π(1 − bobot_i).
 */

var TSD_CATEGORIES = [
  'CMS/Platform',
  'ERP',
  'JS Framework',
  'UI Library',
  'Backend',
  'Web Server',
  'CDN/Hosting',
  'WAF/Proteksi',
  'Analytics',
];

var SIGNATURES = [
  /* ============================ CMS / Platform ============================ */
  {
    name: 'WordPress',
    category: 'CMS/Platform',
    headers: { 'x-pingback': /xmlrpc\.php/, link: /rel="https:\/\/api\.w\.org\/"/ },
    cookies: { 'wordpress_*': '', 'wp-settings-*': '', wordpress_test_cookie: '' },
    meta: { generator: /^WordPress ?([\d.]+)?/i },
    scripts: [/\/wp-(?:content|includes)\//, /\/wp-includes\/js\/[^?]+\?ver=(\d+\.\d+(?:\.\d+)?)/],
    links: [/\/wp-(?:content|includes)\//],
    js: { wp: { confidence: 50 }, wpApiSettings: '' },
    dom: ['link[rel="https://api.w.org/"]'],
    html: [/\/wp-json\//],
    implies: ['PHP'],
  },
  {
    name: 'Shopify',
    category: 'CMS/Platform',
    headers: { 'x-shopid': '', 'x-shopify-stage': '', 'powered-by': /Shopify/i },
    cookies: { '_shopify_*': '', secure_customer_sig: '', cart_sig: '' },
    meta: { 'shopify-checkout-api-token': '', 'shopify-digital-wallet': '' },
    scripts: [/cdn\.shopify\.com/, /\/cdn\/shop\//],
    links: [/cdn\.shopify\.com/],
    js: { Shopify: '', 'Shopify.shop': '', ShopifyAnalytics: '' },
    url: [/\.myshopify\.com/],
    extra: { Shop: 'Shopify.shop', Theme: 'Shopify.theme.name', Currency: 'Shopify.currency.active' },
  },
  {
    name: 'Wix',
    category: 'CMS/Platform',
    headers: { 'x-wix-request-id': '', server: /Pepyaka/i },
    meta: { generator: /Wix\.com/i },
    scripts: [/static\.parastorage\.com/, /static\.wixstatic\.com/],
    js: { wixBiSession: '', wixPerformanceMeasurements: '' },
  },
  {
    name: 'Webflow',
    category: 'CMS/Platform',
    meta: { generator: /Webflow/i },
    scripts: [/webflow(?:\.[a-f0-9]+)?\.js/, /(?:assets|cdn\.prod)\.website-files\.com/],
    links: [/(?:assets|cdn\.prod)\.website-files\.com/],
    js: { Webflow: '' },
    dom: ['html[data-wf-page]', 'html[data-wf-site]'],
  },
  {
    name: 'Ghost',
    category: 'CMS/Platform',
    headers: { 'x-ghost-cache-status': '' },
    cookies: { 'ghost-members-ssr': '' },
    meta: { generator: /^Ghost ?([\d.]+)?/i },
    scripts: [/\/ghost\/(?:api|portal)|ghost\.io|@tryghost\//],
    html: [/data-ghost=|ghost-portal|data-portal=/],
    implies: ['Node.js'],
  },
  {
    name: 'Joomla',
    category: 'CMS/Platform',
    meta: { generator: /Joomla!?(?: ?- ?Open Source Content Management)?(?: ?(\d[\d.]*))?/i },
    scripts: [/\/media\/(?:jui|system|vendor)\/js\//],
    js: { Joomla: '' },
    html: [/\/components\/com_[a-z]+/, /option=com_[a-z]+/],
    implies: ['PHP'],
  },
  {
    name: 'Drupal',
    category: 'CMS/Platform',
    headers: { 'x-generator': /Drupal ?(\d+)?/i, 'x-drupal-cache': '', 'x-drupal-dynamic-cache': '' },
    meta: { generator: /Drupal ?(\d+)?/i },
    scripts: [/\/core\/misc\/drupal\.js/, /\/sites\/(?:default|all)\/(?:files|modules|themes)\//],
    js: { Drupal: '', drupalSettings: '' },
    dom: ['[data-drupal-selector]', '[data-drupal-link-system-path]'],
    implies: ['PHP'],
  },

  /* ================================= ERP ================================== */
  {
    name: 'Odoo',
    category: 'ERP',
    cookies: {
      session_id: { confidence: 25 },
      frontend_lang: { confidence: 45 },
      cids: { confidence: 35 },
    },
    meta: { generator: /Odoo/i },
    scripts: [
      /\/web\/assets\//,
      /\/web\/static\//,
      /\/website\/static\//,
      { pattern: /\/web_enterprise\//, confidence: 90 },
    ],
    links: [/\/web\/assets\//, /\/web\/static\//, /\/web\/image\/website\//, /\/web\/content\//],
    js: {
      odoo: { confidence: 70 },
      'odoo.define': '',
      'odoo.__session_info__': '',
      'odoo.info.server_version': /^((?:saas~)?\d+(?:\.\d+)?)/,
      'odoo.__session_info__.server_version': /^((?:saas~)?\d+(?:\.\d+)?)/,
    },
    dom: [
      '.o_web_client',
      '.o_action_manager',
      '.o_main_navbar',
      '#wrapwrap',
      '[data-oe-model]',
      'html[data-website-id]',
      { selector: 'a[href*="/web/login"]', confidence: 30 },
    ],
    html: [/odoo\.__session_info__/, /odoo\.define\(/, { pattern: /Powered by\s*<a[^>]*odoo\.com/i, confidence: 70 }],
    url: [{ pattern: /\/(?:web|odoo)(?:[#?/]|$)/, confidence: 20 }],
    extra: {
      'Server version (window)': 'odoo.info.server_version',
      'Server version (session)': 'odoo.__session_info__.server_version',
      Database: 'odoo.info.db',
    },
    collect: [
      'odoo.info.isEnterprise',
      'odoo.info.server_version_info.5',
      'odoo.__session_info__.server_version_info.5',
      'odoo.__session_info__.db',
    ],
    implies: ['Python'],
  },

  /* ============================= JS Framework ============================= */
  {
    name: 'React',
    category: 'JS Framework',
    js: { 'React.version': /([\d.]+)/, '@react': '' },
    versionRegex: /^(\d+\.\d+\.\d+)/,
    dom: ['[data-reactroot]', '[data-reactid]'],
    scripts: [/react(?:-dom)?(?:\.production)?(?:\.min)?\.js/, /react(?:-dom)?@([\d.]+)/],
  },
  {
    name: 'Next.js',
    category: 'JS Framework',
    headers: {
      'x-powered-by': /Next\.js ?([\d.]+)?/i,
      'x-nextjs-cache': '',
      'x-nextjs-prerender': '',
      'x-nextjs-stale-time': '',
    },
    js: { __NEXT_DATA__: '', 'next.version': /([\d.]+)/, __next_f: '' },
    dom: ['#__next', 'script#__NEXT_DATA__', 'next-route-announcer'],
    scripts: [/\/_next\/static\//],
    implies: ['React'],
  },
  {
    name: 'Remix',
    category: 'JS Framework',
    js: { __remixContext: '', __remixManifest: '', __remixRouteModules: '' },
    implies: ['React'],
  },
  {
    name: 'React Router',
    category: 'JS Framework',
    js: { __reactRouterContext: '', __reactRouterManifest: '', __reactRouterVersion: /([\d.]+)/ },
    implies: ['React'],
  },
  {
    name: 'Gatsby',
    category: 'JS Framework',
    meta: { generator: /^Gatsby ?([\d.]+)?/i },
    js: { ___loader: '', ___gatsby: '' },
    dom: ['#___gatsby'],
    scripts: [/\/webpack-runtime-[a-f0-9]+\.js/],
    implies: ['React'],
  },
  {
    name: 'Vue.js',
    category: 'JS Framework',
    js: { 'Vue.version': /([\d.]+)/, '@vue': '', __VUE__: { confidence: 70 } },
    versionRegex: /^(\d+\.\d+\.\d+)/,
    dom: ['[data-v-app]'],
    html: [/\sdata-v-[0-9a-f]{8}[\s=>]/],
    scripts: [/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js/, /vue@([\d.]+)/],
  },
  {
    name: 'Nuxt',
    category: 'JS Framework',
    js: { __NUXT__: '', $nuxt: '', useNuxtApp: '' },
    dom: ['#__nuxt', 'script#__NUXT_DATA__'],
    scripts: [/\/_nuxt\//],
    implies: ['Vue.js'],
  },
  {
    name: 'Angular',
    category: 'JS Framework',
    dom: [{ selector: '[ng-version]', attr: 'ng-version', pattern: /([\d.]+)/, confidence: 95 }],
    js: { getAllAngularRootElements: '', ngDevMode: { confidence: 50 } },
    html: [/_nghost-[a-z0-9-]+|_ngcontent-[a-z0-9-]+/],
  },
  {
    name: 'AngularJS',
    category: 'JS Framework',
    js: { 'angular.version.full': /([\d.]+)/ },
    dom: ['[ng-app]', '[data-ng-app]', '.ng-scope'],
    scripts: [/angular(?:\.min)?\.js/, /angular(?:js)?[@/]1\.([\d.]+)/],
  },
  {
    name: 'Svelte',
    category: 'JS Framework',
    js: { '@svelte': '' },
    versionRegex: /^(\d+(?:\.\d+)*)/,
    html: [/class="[^"]*\bsvelte-[a-z0-9]{5,}\b/],
  },
  {
    name: 'SvelteKit',
    category: 'JS Framework',
    js: { '@sveltekit': '' },
    dom: ['[data-sveltekit-preload-data]', '[data-sveltekit-reload]', '[data-sveltekit-hydrate]'],
    scripts: [/\/_app\/immutable\//],
    implies: ['Svelte'],
  },
  {
    name: 'Astro',
    category: 'JS Framework',
    meta: { generator: /^Astro v?([\d.]+)?/i },
    dom: ['astro-island', 'astro-slot'],
    scripts: [/\/_astro\//],
    links: [/\/_astro\//],
  },
  {
    name: 'Alpine.js',
    category: 'JS Framework',
    js: { 'Alpine.version': /([\d.]+)/ },
    dom: ['[x-data]', '[x-init]'],
    scripts: [/alpine(?:js)?(?:\.min)?\.js/, /alpinejs@([\d.]+)/],
  },
  {
    name: 'jQuery',
    category: 'JS Framework',
    js: { 'jQuery.fn.jquery': /([\d.]+)/, 'jQuery': { confidence: 60 } },
    scripts: [
      /jquery[.-]([\d.]*\d)(?:\.slim)?(?:\.min)?\.js/,
      /jquery(?:\.min)?\.js\?ver=([\d.]+)/,
      /jquery(?:\.min)?\.js/,
      /jquery@([\d.]+)/,
    ],
  },

  /* ============================== UI Library ============================== */
  {
    name: 'Tailwind CSS',
    category: 'UI Library',
    cssVars: ['--tw-ring-offset-width', '--tw-border-spacing-x', '--tw-translate-x'],
    css: [/tailwindcss v?([\d.]+)/i],
    scripts: [/cdn\.tailwindcss\.com/, /@tailwindcss\/browser/],
    links: [/tailwind(?:css)?[^/]*\.css/],
    html: [{ pattern: /class="[^"]*\b(?:sm|md|lg|xl|2xl|hover|focus|dark):[a-z][a-z0-9-]*/, confidence: 35 }],
  },
  {
    name: 'Bootstrap',
    category: 'UI Library',
    cssVars: ['--bs-blue', '--bs-primary', '--bs-body-font-family'],
    css: [/Bootstrap\s+v([\d.]+)/i],
    js: {
      'bootstrap.Tooltip.VERSION': /([\d.]+)/,
      'jQuery.fn.tooltip.Constructor.VERSION': /([\d.]+)/,
    },
    scripts: [/bootstrap(?:\.bundle)?(?:\.min)?\.js/, /bootstrap@([\d.]+)/, /bootstrap\/([\d.]+)\//],
    links: [/bootstrap(?:\.min)?\.css/, /bootstrap@([\d.]+)/, /bootstrap\/([\d.]+)\//],
  },
  {
    name: 'MUI',
    category: 'UI Library',
    dom: ['[class*="MuiBox-root"]', '[class*="MuiButton-root"]', '[class*="MuiTypography-root"]', '[class*="MuiPaper-root"]'],
    html: [/class="[^"]*\bMui[A-Z][a-zA-Z]+-root/],
    implies: ['React'],
  },
  {
    name: 'Chakra UI',
    category: 'UI Library',
    cssVars: ['--chakra-colors-blue-500', '--chakra-ring-color', '--chakra-fonts-body'],
    dom: ['[class*="chakra-"]'],
    implies: ['React'],
  },

  /* ================================ Backend =============================== */
  {
    name: 'PHP',
    category: 'Backend',
    headers: { 'x-powered-by': /PHP\/?([\d.]+)?/i },
    cookies: { PHPSESSID: { confidence: 80 } },
    url: [{ pattern: /\.php(?:$|[?#/])/, confidence: 60 }],
  },
  {
    name: 'Laravel',
    category: 'Backend',
    cookies: { laravel_session: { confidence: 90 }, 'XSRF-TOKEN': { confidence: 20 } },
    js: { Laravel: '', Livewire: { confidence: 70 } },
    html: [{ pattern: /wire:(?:id|snapshot|click|model)/, confidence: 50 }],
    implies: ['PHP'],
  },
  {
    name: 'Django',
    category: 'Backend',
    cookies: { csrftoken: { confidence: 55 }, django_language: { confidence: 70 }, sessionid: { confidence: 15 } },
    html: [{ pattern: /name=["']csrfmiddlewaretoken["']/, confidence: 85 }],
    dom: [{ selector: 'input[name="csrfmiddlewaretoken"]', confidence: 85 }],
    implies: ['Python'],
  },
  {
    name: 'Express',
    category: 'Backend',
    headers: { 'x-powered-by': /^Express$/i },
    cookies: { 'connect.sid': { confidence: 60 } },
    implies: ['Node.js'],
  },
  {
    name: 'Ruby on Rails',
    category: 'Backend',
    headers: {
      'x-runtime': { pattern: /^[\d.]+$/, confidence: 30 },
      'x-powered-by': { pattern: /Phusion Passenger/i, confidence: 40 },
    },
    cookies: { '_*_session': { confidence: 30 } },
    meta: { 'csrf-param': /^authenticity_token$/ },
    js: { Rails: { confidence: 50 } },
    scripts: [/rails-ujs/, /\/assets\/application-[0-9a-f]{32,}\.js/],
    implies: ['Ruby'],
  },
  {
    name: 'ASP.NET',
    category: 'Backend',
    headers: {
      'x-aspnet-version': /([\d.]+)/,
      'x-aspnetmvc-version': /([\d.]+)/,
      'x-powered-by': { pattern: /ASP\.NET/i, confidence: 90 },
    },
    cookies: {
      'ASP.NET_SessionId': { confidence: 90 },
      '.AspNetCore.*': { confidence: 90 },
      '__RequestVerificationToken*': { confidence: 60 },
    },
    dom: [{ selector: 'input[name="__VIEWSTATE"]', confidence: 90 }],
    html: [/__VIEWSTATE|__EVENTVALIDATION/],
    url: [{ pattern: /\.aspx?(?:$|[?#])/, confidence: 70 }],
  },
  { name: 'Python', category: 'Backend', headers: { server: /Python\/([\d.]+)/i } },
  { name: 'Werkzeug', category: 'Backend', headers: { server: /Werkzeug\/([\d.]+)/i }, implies: ['Python'] },
  { name: 'Gunicorn', category: 'Backend', headers: { server: /gunicorn(?:\/([\d.]+))?/i }, implies: ['Python'] },
  { name: 'Node.js', category: 'Backend' },
  { name: 'Ruby', category: 'Backend' },

  /* ============================== Web Server ============================== */
  { name: 'Nginx', category: 'Web Server', headers: { server: /nginx(?:\/([\d.]+))?/i } },
  { name: 'OpenResty', category: 'Web Server', headers: { server: /openresty(?:\/([\d.]+))?/i }, implies: ['Nginx'] },
  { name: 'Apache', category: 'Web Server', headers: { server: /Apache(?:\/([\d.]+))?(?!-Coyote)/i } },
  {
    name: 'LiteSpeed',
    category: 'Web Server',
    headers: { server: /LiteSpeed/i, 'x-litespeed-cache': '', 'x-turbo-charged-by': /LiteSpeed/i },
  },
  { name: 'IIS', category: 'Web Server', headers: { server: /Microsoft-IIS(?:\/([\d.]+))?/i } },
  { name: 'Caddy', category: 'Web Server', headers: { server: /Caddy/i } },

  /* ============================== CDN/Hosting ============================= */
  {
    name: 'Cloudflare',
    category: 'CDN/Hosting',
    headers: { 'cf-ray': '', 'cf-cache-status': '', server: /^cloudflare$/i },
    cookies: { __cf_bm: '', cf_clearance: '', __cflb: '' },
    scripts: [{ pattern: /\/cdn-cgi\//, confidence: 60 }],
  },
  {
    name: 'Vercel',
    category: 'CDN/Hosting',
    headers: { 'x-vercel-id': '', 'x-vercel-cache': '', server: /^Vercel$/i },
  },
  {
    name: 'Netlify',
    category: 'CDN/Hosting',
    headers: { 'x-nf-request-id': '', server: /^Netlify$/i },
  },
  {
    name: 'AWS CloudFront',
    category: 'CDN/Hosting',
    headers: { 'x-amz-cf-id': '', 'x-amz-cf-pop': '', via: /CloudFront/i, 'x-cache': /cloudfront/i },
  },
  {
    name: 'Fastly',
    category: 'CDN/Hosting',
    headers: {
      'x-fastly-request-id': '',
      'fastly-debug-digest': '',
      'x-served-by': { pattern: /cache-[a-z0-9]+-[A-Z]{3,}/, confidence: 60 },
    },
  },
  {
    name: 'Akamai',
    category: 'CDN/Hosting',
    headers: {
      server: /AkamaiGHost|AkamaiNetStorage/i,
      'x-akamai-transformed': '',
      'x-akamai-request-id': '',
      'akamai-grn': '',
      'akamai-cache-status': '',
    },
    cookies: { ak_bmsc: { confidence: 70 }, bm_sz: { confidence: 45 } },
  },

  /* ============================= WAF / Proteksi ============================ */
  {
    name: 'Cloudflare Bot Management',
    category: 'WAF/Proteksi',
    cookies: { __cf_bm: { confidence: 70 }, cf_clearance: { confidence: 90 } },
    html: [{ pattern: /\/cdn-cgi\/challenge-platform\//, confidence: 80 }],
  },
  {
    name: 'Cloudflare Turnstile',
    category: 'WAF/Proteksi',
    scripts: [/challenges\.cloudflare\.com\/turnstile/],
    dom: ['.cf-turnstile'],
    js: { turnstile: { confidence: 60 } },
  },
  {
    name: 'Sucuri WAF',
    category: 'WAF/Proteksi',
    headers: { server: /Sucuri\/Cloudproxy/i, 'x-sucuri-id': '', 'x-sucuri-cache': '' },
  },
  {
    name: 'Imperva Incapsula',
    category: 'WAF/Proteksi',
    headers: { 'x-iinfo': '', 'x-cdn': /Incapsula|Imperva/i },
    cookies: { 'visid_incap_*': { confidence: 90 }, 'incap_ses_*': { confidence: 90 } },
  },
  {
    name: 'AWS WAF',
    category: 'WAF/Proteksi',
    headers: { 'x-amzn-waf-action': '' },
    cookies: { 'aws-waf-token': { confidence: 90 } },
    scripts: [/\.awswaf\.com\//],
  },
  {
    name: 'F5 BIG-IP',
    category: 'WAF/Proteksi',
    headers: { server: /BIG-?IP/i, 'x-wa-info': { pattern: '', confidence: 60 } },
    cookies: { 'BIGipServer*': { confidence: 90 }, 'TS01*': { confidence: 50 } },
  },
  {
    name: 'Akamai Bot Manager',
    category: 'WAF/Proteksi',
    cookies: { _abck: { confidence: 90 }, bm_sz: { confidence: 50 } },
    implies: ['Akamai'],
  },
  {
    name: 'DDoS-Guard',
    category: 'WAF/Proteksi',
    headers: { server: /ddos-guard/i },
    cookies: { '__ddg1_': { confidence: 80 }, '__ddg2_': { confidence: 80 } },
  },
  { name: 'ModSecurity', category: 'WAF/Proteksi', headers: { server: /mod_security|NOYB/i } },
  {
    name: 'Wordfence',
    category: 'WAF/Proteksi',
    scripts: [/\/wp-content\/plugins\/wordfence\//],
    cookies: { 'wfwaf-authcookie-*': { confidence: 90 } },
    implies: ['WordPress'],
  },
  {
    name: 'Google reCAPTCHA',
    category: 'WAF/Proteksi',
    scripts: [/(?:google\.com|recaptcha\.net)\/recaptcha\/|gstatic\.com\/recaptcha\//],
    js: { grecaptcha: '' },
    dom: ['.g-recaptcha'],
  },
  {
    name: 'hCaptcha',
    category: 'WAF/Proteksi',
    scripts: [/(?:js\.)?hcaptcha\.com\/1\/api\.js/],
    js: { hcaptcha: '' },
    dom: ['.h-captcha'],
  },

  /* =============================== Analytics ============================== */
  {
    name: 'Google Analytics 4',
    category: 'Analytics',
    scripts: [/googletagmanager\.com\/gtag\/js\?id=G-/],
    cookies: { '_ga_*': { confidence: 70 } },
    js: { gtag: { confidence: 50 } },
    html: [/gtag\(\s*['"]config['"]\s*,\s*['"]G-[A-Z0-9]+/],
    ids: /\b(G-[A-Z0-9]{6,12})\b/,
  },
  {
    name: 'Universal Analytics',
    category: 'Analytics',
    scripts: [/google-analytics\.com\/(?:analytics|ga)\.js/, /googletagmanager\.com\/gtag\/js\?id=UA-/],
    cookies: { _gat: { confidence: 50 }, __utma: { confidence: 60 } },
    js: { GoogleAnalyticsObject: '', _gaq: '' },
    html: [/['"]UA-\d{4,10}-\d{1,4}['"]/],
    ids: /\b(UA-\d{4,10}-\d{1,4})\b/,
  },
  {
    name: 'Google Tag Manager',
    category: 'Analytics',
    scripts: [/googletagmanager\.com\/gtm\.js/],
    js: { google_tag_manager: '', '@gtm': '', dataLayer: { confidence: 30 } },
    dom: ['iframe[src*="googletagmanager.com/ns.html"]'],
    html: [/googletagmanager\.com\/(?:gtm\.js|ns\.html)/],
    ids: /\b(GTM-[A-Z0-9]{4,10})\b/,
  },
  {
    name: 'Meta Pixel',
    category: 'Analytics',
    scripts: [/connect\.facebook\.net\/[\w-]+\/fbevents\.js/],
    js: { fbq: '', _fbq: { confidence: 60 } },
    html: [/fbq\(\s*['"]init['"]/, /facebook\.com\/tr\?id=/],
    ids: /fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,20})/,
  },
  {
    name: 'Hotjar',
    category: 'Analytics',
    scripts: [/static\.hotjar\.com/],
    js: { hj: { confidence: 50 }, _hjSettings: '', hjSiteSettings: '' },
    cookies: { '_hjSession*': '', '_hjid': '' },
    extra: { 'Site ID': '_hjSettings.hjid' },
  },
  {
    name: 'Microsoft Clarity',
    category: 'Analytics',
    scripts: [/clarity\.ms\/tag\//],
    js: { clarity: { confidence: 60 } },
    cookies: { _clck: '', _clsk: '' },
    ids: /clarity\.ms\/tag\/([a-z0-9]{6,})/,
  },
];

/**
 * Aturan versi rentan / End-of-Life untuk audit keamanan.
 *   tech     : nama teknologi (sama dengan `name` di SIGNATURES)
 *   below    : versi < nilai ini dianggap rentan
 *   ranges   : [[dari (inklusif), sampai (eksklusif)], ...]
 *   any      : true → semua versi (mis. framework yang sudah EOL)
 *   severity : 'high' | 'medium' | 'low' | 'info'
 * Perbarui berkala — data ini statis dan tidak mengambil database CVE online.
 */
var TSD_VULN_RULES = [
  {
    tech: 'jQuery',
    below: '3.5.0',
    severity: 'medium',
    title: 'jQuery < 3.5.0 rentan XSS',
    detail: 'CVE-2020-11022 & CVE-2020-11023: HTML yang dimasukkan lewat .html()/.append() bisa mengeksekusi script. Update ke jQuery ≥ 3.5.0.',
  },
  {
    tech: 'Bootstrap',
    ranges: [['0', '3.4.1'], ['4.0.0', '4.3.1']],
    severity: 'low',
    title: 'Bootstrap versi rentan XSS',
    detail: 'CVE-2019-8331 / CVE-2018-14040-14042 (tooltip, popover, data-target). Update ke 3.4.1+ atau 4.3.1+.',
  },
  {
    tech: 'AngularJS',
    any: true,
    severity: 'medium',
    title: 'AngularJS sudah End-of-Life',
    detail: 'AngularJS (1.x) tidak lagi menerima patch keamanan sejak 1 Januari 2022.',
  },
  {
    tech: 'Vue.js',
    ranges: [['2.0.0', '3.0.0']],
    severity: 'low',
    title: 'Vue 2 sudah End-of-Life',
    detail: 'Vue 2 berhenti didukung sejak 31 Desember 2023.',
  },
  {
    tech: 'Next.js',
    ranges: [['11.1.4', '12.3.5'], ['13.0.0', '13.5.9'], ['14.0.0', '14.2.25'], ['15.0.0', '15.2.3']],
    severity: 'high',
    title: 'Next.js rentan bypass middleware',
    detail: 'CVE-2025-29927: header x-middleware-subrequest bisa melewati middleware (mis. pengecekan auth). Update ke 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3+.',
  },
  {
    tech: 'React',
    ranges: [['19.0.0', '19.0.1'], ['19.1.0', '19.1.2'], ['19.2.0', '19.2.1']],
    severity: 'high',
    title: 'React Server Components rentan RCE',
    detail: 'CVE-2025-55182 ("React2Shell"): berlaku jika situs memakai React Server Components (mis. Next.js App Router). Update ke 19.0.1 / 19.1.2 / 19.2.1+.',
  },
  {
    tech: 'PHP',
    below: '8.2.0',
    severity: 'medium',
    title: 'Versi PHP sudah End-of-Life',
    detail: 'PHP < 8.2 tidak lagi menerima patch keamanan (dukungan PHP 8.1 berakhir 31 Desember 2025).',
  },
  {
    tech: 'Odoo',
    below: '17.0',
    severity: 'medium',
    title: 'Versi Odoo sudah tidak didukung',
    detail: 'Odoo hanya memberi patch keamanan untuk 3 versi major terakhir. Versi < 17 sudah di luar dukungan.',
  },
  {
    tech: 'IIS',
    below: '10.0',
    severity: 'medium',
    title: 'IIS versi lama (Windows Server EOL)',
    detail: 'IIS < 10 berjalan di Windows Server 2012 R2 atau lebih lama, yang sudah EOL sejak Oktober 2023.',
  },
  {
    tech: 'Apache',
    below: '2.4.60',
    severity: 'medium',
    title: 'Apache HTTP Server versi lama',
    detail: 'Versi < 2.4.60 terdampak beberapa CVE (mis. CVE-2024-38474/38475/38476). Update ke rilis 2.4 terbaru.',
  },
  {
    tech: 'Nginx',
    below: '1.26.0',
    severity: 'low',
    title: 'Nginx versi lama',
    detail: 'Versi < 1.26 sudah keluar dari jalur stable/mainline; bisa terdampak CVE yang sudah diperbaiki (mis. CVE-2023-44487 HTTP/2 Rapid Reset di < 1.25.3).',
  },
];
