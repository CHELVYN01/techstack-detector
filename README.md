# TechStack Detector — website

Landing page for the TechStack Detector Chrome extension. Built with Vite, vanilla JS.

The extension source lives on the [`v.0.1`](../../tree/v.0.1) branch. The download zip is generated
from that branch at build time, so it is not committed here.

```
EXT_DIR=/path/to/extension-checkout bun run dev    # extension = v.0.1 checkout
EXT_DIR=/path/to/extension-checkout bun run build
```

CI (`.github/workflows/deploy.yml`) checks out `v.0.1` into `./extension` and deploys to GitHub Pages
on every push to `main`. After changing the extension, re-run the workflow (Actions → Deploy site → Run workflow).

MIT licensed.
