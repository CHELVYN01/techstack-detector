# TechStack Detector — website

Landing page for the TechStack Detector Chrome extension. Built with Vite, vanilla JS.

The extension source lives on the [`v.0.1`](../../tree/v.0.1) branch. The download zip is generated
from that branch at build time, so it is not committed here.

```
bun install
bun run dev      # zips the extension, then starts Vite
bun run build
```

`scripts/zip.js` downloads the `v.0.1` branch from GitHub. To use a local checkout instead, set
`EXT_DIR=/path/to/extension`. This also makes the build work on hosts that only clone `main` (Vercel, GitHub Pages).

`.github/workflows/deploy.yml` deploys to GitHub Pages on every push to `main`. After changing the extension,
redeploy (Actions → Deploy site → Run workflow, or redeploy on Vercel) to refresh the zip.

MIT licensed.
