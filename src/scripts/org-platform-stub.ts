// Development stand-in for the organization platform (the separate
// Next.js + Go app), until it exists. It serves every organization hostname
// on ORG_PLATFORM_ORIGIN (default http://localhost:3100) and answers what
// the control plane's domain check needs, using the internal API exactly as
// the real platform must:
//
//   GET /bmms-routing  → { hostname, organizationId } | 404 TENANT_NOT_FOUND
//   GET /              → a placeholder page for the organization
//
//   npm run dev:org-platform-stub

import http from "node:http";

if (process.env.NODE_ENV !== "development") {
  throw new Error("The organization platform stub only runs with NODE_ENV=development.");
}

const token = process.env.ORG_PLATFORM_SERVICE_TOKEN?.trim();
if (!token) throw new Error("Set ORG_PLATFORM_SERVICE_TOKEN (the same value the API uses).");

const origin = new URL(process.env.ORG_PLATFORM_ORIGIN?.trim() || "http://localhost:3100");
const api = `http://127.0.0.1:${process.env.PORT ?? 3001}`;

type Resolved = { organizationId: string; name: string; hostname: string; ready: boolean };

async function resolve(host: string): Promise<Resolved | null> {
  const response = await fetch(`${api}/internal/v1/tenants/resolve?hostname=${encodeURIComponent(host)}`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(5_000),
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`Internal API returned ${response.status}`);
  return (await response.json()) as Resolved;
}

const escape = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const server = http.createServer(async (request, response) => {
  const host = (request.headers.host ?? "").split(":")[0]!.toLowerCase();
  const path = new URL(request.url ?? "/", "http://x").pathname;

  try {
    const tenant = await resolve(host);

    if (path === "/bmms-routing") {
      response.writeHead(tenant ? 200 : 404, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(
        JSON.stringify(
          tenant
            ? { hostname: tenant.hostname, organizationId: tenant.organizationId }
            : { error: "TENANT_NOT_FOUND", message: "No organization is registered at this address." },
        ),
      );
      return;
    }

    // Serve an organization only once it's ready; never a default one.
    const status = tenant?.ready ? 200 : 404;
    const body = tenant?.ready
      ? `<h1>${escape(tenant.name)}</h1><p>${escape(tenant.hostname)}</p><p>The organization platform isn't built yet; this is a development stand-in.</p>`
      : `<h1>No organization here</h1><p>This address isn't an active BMMS organization.</p>`;
    response.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    response.end(`<!doctype html><meta charset="utf-8"><title>BMMS</title><body style="font-family:system-ui;margin:3rem">${body}</body>`);
  } catch {
    response.writeHead(503, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "CONTROL_PLANE_UNAVAILABLE" }));
  }
});

server.listen(Number(origin.port || 80), "127.0.0.1", () => {
  console.log(`Organization platform stub on ${origin.origin} (e.g. http://<slug>.localhost:${origin.port || 80})`);
});
