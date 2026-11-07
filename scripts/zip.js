import { unzipSync, zipSync } from 'fflate'
import { existsSync, readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'

// Extension source: a local v.0.1 checkout (EXT_DIR, or ./extension in CI),
// otherwise the v.0.1 branch archive downloaded from GitHub (Vercel, fresh clones).
const REPO = 'CHELVYN01/techstack-detector'
const BRANCH = 'v.0.1'
const local = resolve(process.env.EXT_DIR ?? 'extension')
const wanted = (p) =>
  /^(manifest\.json|background\.js|content\.js|inject\.js|signatures\.js|popup\.(html|css|js)|README\.md|LICENSE|icons\/[^/]+)$/.test(p)

const files = {}
if (existsSync(join(local, 'manifest.json'))) {
  const add = (p) => (files[p] = readFileSync(join(local, p)))
  for (const f of readdirSync(local)) if (wanted(f)) add(f)
  for (const f of readdirSync(join(local, 'icons'))) add(`icons/${f}`)
  console.log(`zip: using local checkout ${local}`)
} else {
  const res = await fetch(`https://github.com/${REPO}/archive/refs/heads/${BRANCH}.zip`)
  if (!res.ok) throw new Error(`download ${BRANCH} failed: ${res.status}`)
  const archive = unzipSync(new Uint8Array(await res.arrayBuffer()))
  for (const [name, data] of Object.entries(archive)) {
    const p = name.split('/').slice(1).join('/') // drop the top-level folder
    if (wanted(p)) files[p] = data
  }
  console.log(`zip: downloaded ${BRANCH} from github.com/${REPO}`)
}

if (!files['manifest.json']) throw new Error('manifest.json not found in extension source')

const entries = Object.fromEntries(Object.entries(files).map(([p, d]) => [`techstack-detector/${p}`, d]))
const out = join(import.meta.dir, '..', 'public', 'techstack-detector.zip')
mkdirSync(join(out, '..'), { recursive: true })
writeFileSync(out, zipSync(entries))
console.log(`zip: ${Object.keys(entries).length} files -> ${out}`)
