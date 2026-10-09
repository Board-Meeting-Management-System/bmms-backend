# Testing from another computer (LAN, opt-in)

`localhost` means "this machine" to whichever computer evaluates it. A laptop
opening `http://localhost:3000` reaches *its own* port 3000, not the server's.
And Keycloak's issuer, the OIDC callback, CORS origins, cookies and email
links all contain a hostname, so every component must agree on one name that
all machines resolve to the server.

This setup gives the server one HTTPS hostname and puts a reverse proxy in
front of the three browser-facing services. PostgreSQL, the API, the
frontend and Keycloak keep listening on loopback only.

Placeholders — replace everywhere:

| Placeholder | Meaning |
|---|---|
| `<SERVER_IP>` | the server's LAN address, e.g. `192.168.1.20` |
| `bmms.lan` | the hostname you choose (any name you control on your LAN) |

```
browser ──https://bmms.lan──────▶ Caddy :443  ──▶ 127.0.0.1:3000 (Next.js)
        ──https://bmms.lan:8443─▶ Caddy :8443 ──▶ 127.0.0.1:3001 (API)
        ──https://bmms.lan:9443─▶ Caddy :9443 ──▶ 127.0.0.1:8080 (Keycloak)
Next.js server ──http://127.0.0.1:3001──▶ API          (server-side calls)
API/worker ──────────────────────────────▶ 127.0.0.1:5433 (PostgreSQL, private)
```

Why one hostname on three ports: cookies are scoped to the hostname, not the
port. The API sets `bmms_session` on `bmms.lan`; the browser then sends it to
the frontend at `bmms.lan` too, which forwards it server-side — exactly how
`localhost:3000`/`localhost:3001` work today. Using the same site also keeps
`SameSite=Lax` cookies working. (Separate hostnames would need cookie domain
changes; a path prefix like `/api` would break the login cookie's path.)

## 1. Name resolution (every machine, including the server)

Add to `/etc/hosts` (Windows: `C:\Windows\System32\drivers\etc\hosts`):

```
<SERVER_IP>  bmms.lan
```

Or add one record on your router's DNS. The server itself must resolve
`bmms.lan` too: the API fetches Keycloak's JWKS from the issuer URL.

## 2. TLS with a reverse proxy (server)

Example with [Caddy](https://caddyserver.com/), `Caddyfile`:

```caddyfile
bmms.lan {
	tls internal
	reverse_proxy 127.0.0.1:3000
}

bmms.lan:8443 {
	tls internal
	reverse_proxy 127.0.0.1:3001
}

bmms.lan:9443 {
	tls internal
	reverse_proxy 127.0.0.1:8080
}
```

`tls internal` issues certificates from Caddy's local CA. Caddy forwards the
original `Host` and sets `X-Forwarded-For`/`-Proto`.

**Trust the CA — never disable certificate verification:**

- Each browser machine: import Caddy's root certificate
  (`~/.local/share/caddy/pki/authorities/local/root.crt` on the server, or the
  path `caddy trust` reports) into the OS/browser trust store.
- The API and worker (Node.js) on the server: start them with
  `NODE_EXTRA_CA_CERTS=/path/to/root.crt` so they can verify Keycloak's
  certificate when fetching keys and exchanging codes.

## 3. Keycloak (manual, admin console)

1. Run Keycloak with a fixed public hostname behind the proxy, e.g. for
   Keycloak ≥ 25: `--hostname=https://bmms.lan:9443 --proxy-headers=xforwarded
   --http-enabled=true --http-host=127.0.0.1`. Check that
   `https://bmms.lan:9443/realms/bmms/.well-known/openid-configuration`
   reports `"issuer": "https://bmms.lan:9443/realms/bmms"`.
2. Realm `bmms` → Clients → your client:
   - Valid redirect URIs: add `https://bmms.lan:8443/auth/callback`
   - Valid post logout redirect URIs: add `https://bmms.lan:8443/auth/logged-out`
   - Keep the existing `localhost` entries if you switch back and forth.

Tokens carry the issuer they were issued under, so after switching every
browser (including the server's) must use `https://bmms.lan`, and existing
sessions need a fresh sign-in.

## 4. Environment

`bmms-backend/.env` (only these change; keep everything else):

```bash
HOST=127.0.0.1                       # still loopback: Caddy is the only way in
FRONTEND_ORIGIN=https://bmms.lan     # exact origin: CORS, CSRF, email links
TRUST_PROXY=127.0.0.1                # per-client rate limits behind Caddy
OIDC_ISSUER=https://bmms.lan:9443/realms/bmms
OIDC_JWKS_URL=https://bmms.lan:9443/realms/bmms/protocol/openid-connect/certs
OIDC_REDIRECT_URI=https://bmms.lan:8443/auth/callback
```

`bmms-frontend/.env.local`:

```bash
BMMS_API_URL=http://127.0.0.1:3001           # server-side calls stay local
BMMS_API_PUBLIC_URL=https://bmms.lan:8443    # browser-facing API
DEV_ALLOWED_HOSTS=bmms.lan                   # lets Next.js dev serve this host
```

Start the frontend on loopback so only Caddy exposes it:
`npx next dev -p 3000 -H 127.0.0.1`.

What stays protected, unchanged:

- The API's development-only `http://localhost` allowances don't apply:
  everything is HTTPS, so cookies are `Secure` and the HTTPS callback check
  passes. Nothing is disabled.
- CORS and the CSRF Origin check allow exactly `https://bmms.lan` — no
  wildcards with credentials.
- PKCE, state, nonce, issuer and audience validation, HttpOnly cookies and TLS
  verification all stay as they are.

## 5. Firewall (server, manual)

Open only the proxy's ports; keep 3000, 3001, 5433 and 8080 closed to the
network (they already bind to 127.0.0.1). On Fedora, for example:

```bash
sudo firewall-cmd --add-port=443/tcp --add-port=8443/tcp --add-port=9443/tcp
# add --permanent and repeat to keep the rules after a reboot
```

Remove the rules when you're done testing. Don't expose this setup to the
internet: it uses development credentials and a local CA.

## 6. Check

From another computer:

1. `https://bmms.lan` opens without a certificate warning.
2. `https://bmms.lan:8443/health` → `{"status":"ok",…}`.
3. `/master` → Sign in → Keycloak at `bmms.lan:9443` → back on
   `https://bmms.lan/master/dashboard`.
4. A sent invitation's email links to `https://bmms.lan/invitation#token=…`.

If login loops back with `?login=failed`, check the API log: usually an
issuer mismatch (Keycloak hostname) or an untrusted certificate
(`NODE_EXTRA_CA_CERTS`).

## Switching back

Restore the `localhost` values in both env files, restart the API, worker
and frontend, and sign in again.
