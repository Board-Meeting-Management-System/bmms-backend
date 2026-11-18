import type { FastifyInstance } from "fastify";

import { resolveTenantByHostname } from "../domains/domain.repository.js";
import { normalizeHostname } from "../domains/hostname.js";
import { acceptInvitationForIdentity } from "../invitations/email-otp.service.js";
import { InvitationError } from "../invitations/invitation.db.js";
import { requireOrganizationPlatform } from "./service-auth.js";
import { tenantDatabaseConnection, tenantStorageLocation } from "./tenant-resources.js";

// The internal API the organization platform's backend (Go) calls.
// Service-authenticated; never called from browsers. Contract:
// org-platform-handoff/CONTRACT.md.

const service = { onRequest: [requireOrganizationPlatform] };
const tenantParams = {
  type: "object",
  additionalProperties: false,
  required: ["tenantId"],
  properties: { tenantId: { type: "string", format: "uuid" } },
} as const;

export async function internalRoutes(app: FastifyInstance) {
  // Which organization a hostname belongs to. `ready` is true only when the
  // organization and its domain are active — serve the organization only
  // then. Registered-but-not-ready hosts still resolve, so /bmms-routing
  // can answer domain checks during provisioning. Unknown hosts: 404.
  app.get<{ Querystring: { hostname: string } }>(
    "/internal/v1/tenants/resolve",
    {
      ...service,
      schema: {
        querystring: {
          type: "object",
          additionalProperties: false,
          required: ["hostname"],
          properties: { hostname: { type: "string", maxLength: 260 } },
        },
      },
    },
    async (request, reply) => {
      const hostname = normalizeHostname(request.query.hostname);
      const tenant = hostname ? await resolveTenantByHostname(hostname, "registered") : null;
      if (!tenant) {
        return reply.code(404).send({ error: "TENANT_NOT_FOUND", message: "No organization is registered at this address." });
      }
      return {
        organizationId: tenant.tenantId,
        name: tenant.name,
        slug: tenant.slug,
        hostname: tenant.hostname,
        status: tenant.tenantStatus,
        domainStatus: tenant.domainStatus,
        ready: tenant.tenantStatus === "active" && tenant.domainStatus === "active",
      };
    },
  );

  // Connection for the organization's own database, as its runtime role.
  app.get<{ Params: { tenantId: string } }>(
    "/internal/v1/tenants/:tenantId/database",
    { ...service, schema: { params: tenantParams } },
    async (request, reply) => {
      const connection = await tenantDatabaseConnection(request.params.tenantId);
      if (!connection) {
        return reply.code(404).send({ error: "TENANT_DATABASE_UNAVAILABLE", message: "No active database for this organization." });
      }
      return { database: connection };
    },
  );

  app.get<{ Params: { tenantId: string } }>(
    "/internal/v1/tenants/:tenantId/storage",
    { ...service, schema: { params: tenantParams } },
    async (request, reply) => {
      const location = await tenantStorageLocation(request.params.tenantId);
      if (!location) {
        return reply.code(404).send({ error: "TENANT_STORAGE_UNAVAILABLE", message: "No active storage for this organization." });
      }
      return { storage: location };
    },
  );

  // The secretary accepts on the organization platform, signed in through
  // the organization realm. The platform verifies the token from its realm
  // and reports the identity; the control plane applies the invitation
  // rules and records who accepted. The platform then creates the member.
  app.post<{
    Body: {
      token: string;
      identity: { issuer: string; subject: string; email: string | null; emailVerified: boolean };
    };
  }>(
    "/internal/v1/invitations/accept",
    {
      ...service,
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["token", "identity"],
          properties: {
            token: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" },
            identity: {
              type: "object",
              additionalProperties: false,
              required: ["issuer", "subject", "email", "emailVerified"],
              properties: {
                issuer: { type: "string", minLength: 1, maxLength: 500 },
                subject: { type: "string", minLength: 1, maxLength: 255 },
                email: { type: ["string", "null"], maxLength: 254 },
                emailVerified: { type: "boolean" },
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      // Only identities from the organization realm — never the admin realm.
      const issuer = process.env.ORG_OIDC_ISSUER?.trim();
      if (!issuer) {
        return reply.code(503).send({ error: "ORG_REALM_NOT_CONFIGURED", message: "ORG_OIDC_ISSUER is not configured." });
      }
      if (request.body.identity.issuer !== issuer) {
        return reply.code(403).send({ error: "WRONG_IDENTITY_REALM", message: "The identity isn't from the organization realm." });
      }

      try {
        return await acceptInvitationForIdentity(request.body.token, request.body.identity);
      } catch (error) {
        if (error instanceof InvitationError) {
          return reply.code(error.statusCode).send({ error: error.code, message: error.message });
        }
        request.log.error({ event: "internal_accept_failed" }, "Invitation acceptance failed");
        return reply.code(503).send({ error: "INVITATION_SERVICE_UNAVAILABLE", message: "Try again shortly." });
      }
    },
  );
}
