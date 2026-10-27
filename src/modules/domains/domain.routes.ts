import type { FastifyInstance } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { domainProvider } from "./domain-provider.js";
import {
  addCustomDomain,
  DomainConflictError,
  getCustomDomain,
  listCustomDomains,
  primaryPlatformDomain,
  recordDomainCheck,
} from "./domain.repository.js";
import { normalizeHostname } from "./hostname.js";

const admin = { onRequest: [authenticate, requirePlatformAdmin] };
const tenantParams = {
  type: "object",
  additionalProperties: false,
  required: ["tenantId"],
  properties: { tenantId: { type: "string", format: "uuid" } },
} as const;

export async function domainRoutes(app: FastifyInstance) {
  // Shared platform infrastructure (wildcard DNS, ingress, TLS), checked
  // separately from any one organization's mapping.
  app.get("/admin/platform/domain-check", admin, async (_request, reply) => {
    reply.header("Cache-Control", "no-store");
    return { platform: await domainProvider().checkPlatform() };
  });

  // Re-checks an organization's platform hostname now.
  app.post<{ Params: { tenantId: string } }>(
    "/admin/tenants/:tenantId/domains/check",
    { ...admin, schema: { params: tenantParams }, config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      const domain = await primaryPlatformDomain(request.params.tenantId);
      if (!domain) return reply.code(404).send({ error: "DOMAIN_NOT_FOUND", message: "Organization domain not found." });

      const check = await domainProvider().verifyHostname(domain.hostname, request.params.tenantId);
      await recordDomainCheck(domain.id, check);
      return { hostname: domain.hostname, check };
    },
  );

  app.get<{ Params: { tenantId: string } }>(
    "/admin/tenants/:tenantId/custom-domains",
    { ...admin, schema: { params: tenantParams } },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      return { customDomains: (await listCustomDomains(request.params.tenantId)).map(present) };
    },
  );

  // Registers a custom hostname as pending. It activates only after a
  // verification proves ownership, routing and TLS.
  app.post<{ Params: { tenantId: string }; Body: { hostname: string } }>(
    "/admin/tenants/:tenantId/custom-domains",
    {
      ...admin,
      schema: {
        params: tenantParams,
        body: {
          type: "object",
          additionalProperties: false,
          required: ["hostname"],
          properties: { hostname: { type: "string", maxLength: 253 } },
        },
      },
    },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      const provider = domainProvider();
      const hostname = normalizeHostname(request.body.hostname);

      if (!hostname || !hostname.includes(".")) {
        return reply.code(400).send({ error: "INVALID_HOSTNAME", message: "Enter a hostname such as board.example.com." });
      }
      if (hostname === provider.baseDomain || hostname.endsWith(`.${provider.baseDomain}`)) {
        return reply.code(400).send({
          error: "CUSTOM_DOMAIN_INSIDE_PLATFORM_DOMAIN",
          message: "Platform subdomains are assigned automatically; enter the organization's own domain.",
        });
      }

      try {
        return reply.code(201).send({ customDomain: present(await addCustomDomain(request.params.tenantId, hostname)) });
      } catch (error) {
        if (error instanceof DomainConflictError) {
          return reply.code(error.code === "TENANT_NOT_FOUND" ? 404 : 409).send({ error: error.code, message: error.message });
        }
        throw error;
      }
    },
  );

  app.post<{ Params: { tenantId: string; domainId: string } }>(
    "/admin/tenants/:tenantId/custom-domains/:domainId/verify",
    {
      ...admin,
      schema: {
        params: {
          type: "object",
          additionalProperties: false,
          required: ["tenantId", "domainId"],
          properties: { tenantId: { type: "string", format: "uuid" }, domainId: { type: "string", format: "uuid" } },
        },
      },
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      const domain = await getCustomDomain(request.params.tenantId, request.params.domainId);
      if (!domain) return reply.code(404).send({ error: "DOMAIN_NOT_FOUND", message: "Custom domain not found." });

      const check = await domainProvider().verifyCustomDomain(domain.hostname, request.params.tenantId, domain.ownershipToken);
      await recordDomainCheck(domain.id, check);
      const updated = await getCustomDomain(request.params.tenantId, domain.id);
      return { customDomain: present(updated!), check };
    },
  );
}

/** What an admin needs to configure DNS. The ownership value is public by design. */
function present(domain: Awaited<ReturnType<typeof listCustomDomains>>[number]) {
  return {
    id: domain.id,
    hostname: domain.hostname,
    status: domain.status,
    ownershipRecord: { type: "TXT", name: `_bmms-challenge.${domain.hostname}`, value: domain.ownershipToken },
    ownershipVerifiedAt: domain.ownershipVerifiedAt,
    routingVerifiedAt: domain.routingVerifiedAt,
    tlsReadyAt: domain.tlsReadyAt,
    lastCheckedAt: domain.lastCheckedAt,
    lastErrorCode: domain.lastErrorCode,
  };
}
