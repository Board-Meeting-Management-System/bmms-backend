import type { FastifyInstance } from "fastify";
import * as oidc from "openid-client";

import { authConfig } from "../auth/auth.config.js";
import { exchangeHandoff } from "../auth/handoff.repository.js";
import { getOidcClient } from "../auth/oidc.client.js";
import { revokeSessionById } from "../auth/session.repository.js";
import { authenticateSessionRecord } from "../auth/session-auth.service.js";
import { resolveTenantByHostname } from "../domains/domain.repository.js";
import {
  authenticateTenantSession,
  requestHostname,
  requireTenantMember,
  resolveTenant,
} from "./tenant-context.js";
import { tenantDatabase } from "./tenant-database.js";

// Routes served for an organization hostname. The frontend's server calls
// them with X-Forwarded-Host set to the browser's host; the API trusts that
// header only from TRUST_PROXY addresses.

export async function tenantRoutes(app: FastifyInstance) {
  // Used by domain checks: does this hostname reach the app, and which
  // organization does it map to? Registered (not necessarily active) domains.
  app.get("/tenant/routing-probe", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const hostname = requestHostname(request);
    const tenant = hostname ? await resolveTenantByHostname(hostname, "registered") : null;
    if (!tenant) {
      return reply.code(404).send({ error: "TENANT_NOT_FOUND", message: "No organization is registered at this address." });
    }
    return { hostname: tenant.hostname, organizationId: tenant.tenantId };
  });

  // Public: just enough to render the organization's sign-in page.
  app.get("/tenant/context", { onRequest: [resolveTenant] }, async (request) => ({
    hostname: request.tenant!.hostname,
    organization: { name: request.tenant!.name, slug: request.tenant!.slug },
  }));

  app.get(
    "/tenant/me",
    { onRequest: [resolveTenant, authenticateTenantSession, requireTenantMember] },
    async (request) => ({
      user: { email: request.authUser!.email },
      organization: { name: request.tenant!.name, slug: request.tenant!.slug },
      membership: request.membership,
    }),
  );

  // Reads the organization's own database as its runtime role.
  app.get(
    "/tenant/overview",
    { onRequest: [resolveTenant, authenticateTenantSession, requireTenantMember] },
    async (request, reply) => {
      try {
        const db = await tenantDatabase(request.tenant!.tenantId);
        const result = await db.query<{ tenantId: string }>(
          `SELECT tenant_id AS "tenantId" FROM bmms.tenant_metadata WHERE singleton`,
        );
        const stored = result.rows[0]?.tenantId ?? null;
        // A mismatch would mean the wrong database: refuse rather than show it.
        if (stored !== request.tenant!.tenantId) throw new Error("Tenant database identity mismatch.");
        return { organization: { name: request.tenant!.name }, database: { organizationId: stored } };
      } catch {
        request.log.error({ event: "tenant_database_failed" }, "Tenant database unavailable");
        return reply.code(503).send({ error: "TENANT_DATABASE_UNAVAILABLE", message: "This organization's data is temporarily unavailable." });
      }
    },
  );

  // Second half of login on an organization domain: the frontend server
  // trades the one-time code for a session bound to this hostname.
  app.post<{ Body: { code: string } }>(
    "/tenant/auth/handoff",
    {
      onRequest: [resolveTenant],
      config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["code"],
          properties: { code: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" } },
        },
      },
    },
    async (request, reply) => {
      const session = await exchangeHandoff(request.body.code, request.tenant!.hostname);
      if (!session) {
        return reply.code(401).send({ error: "HANDOFF_INVALID", message: "This sign-in link has expired. Sign in again." });
      }
      return { sessionToken: session.sessionToken, expiresAt: session.expiresAt.toISOString() };
    },
  );

  app.post("/tenant/auth/logout", { onRequest: [resolveTenant] }, async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const tenant = request.tenant!;
    const token = request.cookies.bmms_session;

    if (token) {
      const session = await authenticateSessionRecord(token).catch(() => null);
      if (session?.boundHost === tenant.hostname) await revokeSessionById(session.sessionId);
    }

    // Also end the Keycloak session; Keycloak returns via /auth/logged-out,
    // which sends the browser back here (state is re-validated there).
    try {
      const client = await getOidcClient();
      const logoutUrl = oidc.buildEndSessionUrl(client, {
        client_id: authConfig.client_id,
        post_logout_redirect_uri: new URL("/auth/logged-out", new URL(authConfig.redirectUri).origin).href,
        state: tenant.hostname,
      });
      return { localLogoutComplete: true, logoutUrl: logoutUrl.href };
    } catch {
      return { localLogoutComplete: true, logoutUrl: null };
    }
  });
}
