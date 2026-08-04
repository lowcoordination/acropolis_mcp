# Putting Acropolis behind TLS

Read this before you expose Acropolis to anything beyond `localhost` or a network you fully
trust — including a home LAN with guests, IoT devices, or anyone else's laptop on it.

## Why this matters

Acropolis, by default, serves plain HTTP. Two things travel over that connection that matter:

- **Your admin session cookie** — set once you complete the first-run wizard or log in.
  Anyone who can see this cookie in transit can use it to reach the control plane: read your
  audit log, create API keys, change policy, add or remove servers.
- **MCP API keys**, if you've set `auth_mode: keyed` (the default and the recommended
  setting) — sent as a bearer token on every `/mcp/*` request. Anyone who can see one in
  transit can use it exactly as your own client would.

On plain HTTP, both of these are readable by anything between the client and Acropolis: a
shared Wi-Fi network, a compromised router, an ISP, a proxy you don't control. TLS
(HTTPS) encrypts the connection so that traffic is unreadable in transit.

If you're only ever accessing Acropolis from `localhost` on the same machine it runs on, this
isn't a concern — traffic never leaves the box. The moment you expose it on your LAN, a VPN,
or the public internet, put it behind TLS first.

The Settings page shows a warning banner exactly for this: if `auth_mode` is `open` and the
page detects it's being served over plain HTTP, it tells you so directly. That warning is a
reminder, not a substitute for actually fixing it.

## The shape of the fix

Acropolis doesn't terminate TLS itself — it expects a reverse proxy in front of it to handle
certificates and HTTPS, then forward plain HTTP to Acropolis over a connection the proxy
controls (usually `localhost` or a private network). This is the standard shape for
self-hosted apps and lets you reuse whatever proxy you already run, if any.

```
Internet / LAN  --HTTPS-->  reverse proxy  --HTTP-->  Acropolis (localhost:8000)
```

Below are two options. Caddy is the simplest if you're starting from nothing — it gets you
automatic certificates with almost no configuration. nginx is worth using if you already run
it for other services.

### Option 1: Caddy (recommended if you have nothing else running)

Caddy issues and renews TLS certificates automatically via Let's Encrypt, as long as your
domain's DNS points at the machine running Caddy and ports 80/443 are reachable from the
internet (needed once, for the initial certificate challenge).

Install Caddy, then create `/etc/caddy/Caddyfile`:

```
acropolis.yourdomain.com {
    reverse_proxy localhost:8000
}
```

Reload Caddy (`sudo systemctl reload caddy` or equivalent for your install). That's the
whole configuration — Caddy handles the certificate, the redirect from HTTP to HTTPS, and
proxying every request (including the SSE audit tail, which needs the connection kept
open — Caddy does this correctly by default).

If you don't have a domain, Caddy can also serve a self-signed certificate for local/LAN
use — see [Caddy's docs on internal TLS](https://caddyserver.com/docs/automatic-https#local-https)
for that variant.

### Option 2: nginx

If you're managing certificates yourself (e.g. via `certbot`) or already have nginx running:

```nginx
server {
    listen 443 ssl;
    server_name acropolis.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/acropolis.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/acropolis.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # The audit log's live tail is a long-lived SSE stream — don't let nginx buffer or
        # time it out early.
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}

server {
    listen 80;
    server_name acropolis.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

Get a certificate with `certbot --nginx -d acropolis.yourdomain.com` (or your preferred ACME
client), then reload nginx.

## After TLS is in place

- Update how you (and any MCP clients) reach Acropolis to use `https://` instead of `http://`.
- If you're running the docker-compose setup, Acropolis itself still only needs to listen on
  `localhost` or an internal Docker network reachable by the proxy — you don't need to
  expose port 8000 outside the host at all. Remove the `ports:` mapping in
  `deploy/docker-compose.yml` (or bind it to `127.0.0.1:8000:8000`) once the proxy is the only
  thing reaching Acropolis directly.
- Re-check the Settings page — the open-mode-over-HTTP warning should disappear once you're
  accessing Acropolis via `https://`.
- Add `Strict-Transport-Security` at the proxy, not in Acropolis itself. Acropolis sets a small
  set of security headers on every response (CSP, `X-Frame-Options`, `X-Content-Type-Options`),
  but deliberately does *not* set HSTS — that's a proxy-layer decision, since Acropolis itself
  always speaks plain HTTP and doesn't know whether the deployment in front of it terminates
  TLS. Once you're running behind TLS, add it in your proxy config, e.g. for Caddy:
  `header Strict-Transport-Security "max-age=31536000"`, or for nginx:
  `add_header Strict-Transport-Security "max-age=31536000" always;`.

## What TLS does *not* fix

TLS protects data in transit. It doesn't change who's allowed to log in, what an API key can
do, or what `auth_mode: open` means. If you want defense in depth beyond TLS:

- Use `auth_mode: keyed` (the default) rather than `open`, even on a private network.
- Scope API keys to specific servers when a client only needs one (see the Keys page).
- Put the reverse proxy itself behind your network's normal access controls (firewall rules,
  VPN-only access, etc.) if Acropolis is managing anything sensitive.
