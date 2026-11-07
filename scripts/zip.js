import { zipSync } from 'fflate'
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'

// Extension source: the v.0.1 branch checked out somewhere (CI uses ./extension).
const src = resolve(process.env.EXT_DIR ?? 'extension')
const files = [
  'manifest.json', 'background.js', 'content.js', 'inject.js', 'signatures.js',
  'popup.html', 'popup.css', 'popup.js', 'README.md', 'LICENSE',
]

const entries = {}
for (const f of files) entries[`techstack-detector/${f}`] = readFileSync(join(src, f))
for (const f of readdirSync(join(src, 'icons'))) {
  entries[`techstack-detector/icons/${f}`] = readFileSync(join(src, 'icons', f))
}

const out = join(import.meta.dir, '..', 'public', 'techstack-detector.zip')
mkdirSync(join(out, '..'), { recursive: true })
writeFileSync(out, zipSync(entries))
console.log(`zip: ${Object.keys(entries).length} files from ${src} -> ${out}`)
