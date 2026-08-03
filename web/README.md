# Argus web UI

React + Vite + Tailwind frontend for Archon's control plane. Built by the repo's
Dockerfile into static assets and served directly by the Python backend — there is no
separate Node process at runtime.

## Development

```bash
npm install
npm run dev
```

Proxies `/api` and `/mcp` to a locally-running Argus backend (`python -m argus` from the
repo root) — see `vite.config.ts`.

## Building

```bash
npm run build
```

Outputs to `dist/`, which `argus/app.py`'s `_mount_web_ui` serves if present.
