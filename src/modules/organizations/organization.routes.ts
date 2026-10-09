import type { FastifyInstance } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";

import {
  createOrganizationSchema,
  type CreateOrganizationBody,
  type CreateOrganizationHeaders,
} from "./organization.schemas.js";

import {
  createOrganization,
  OrganizationRequestError,
} from "./organization.service.js";

import {
  RegistrationConflictError,
} from "./organization.repository.js";
import { getTenantOnboarding, listTenantSummaries } from "./onboarding.repository.js";

export async function organizationRoutes(app: FastifyInstance) {
  app.post<{
    Body: CreateOrganizationBody;
    Headers: CreateOrganizationHeaders;
  }>(
    "/admin/tenants",
    {
      schema: createOrganizationSchema,
      preHandler: [
        authenticate,
        requirePlatformAdmin,
      ],
    },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");

      const actor = request.authUser;

      if (!actor) {
        return reply.code(401).send({
          error: "UNAUTHORIZED",
          message: "Authentication is required.",
        });
      }

      try {
        const result = await createOrganization(
          request.body,
          request.headers["idempotency-key"],
          actor,
        );

        return reply.code(202).send(result);
      } catch (error) {
        if (error instanceof OrganizationRequestError) {
          return reply.code(error.statusCode).send({
            error: error.code,
            message: error.message,
          });
        }

        if (error instanceof RegistrationConflictError) {
          return reply.code(409).send({
            error: error.code,
            message: error.message,
          });
        }

        const details = error as {
          name?: string;
          code?: string;
        };

        request.log.error(
          {
            name: details.name,
            code: details.code,
          },
          "Organization registration failed",
        );

        return reply.code(500).send({
          error: "REGISTRATION_FAILED",
          message:
            "Unable to complete registration. Retry with the same Idempotency-Key.",
        });
      }
    },
  );

  // Every organization with its onboarding facts, newest first.
  app.get(
    "/admin/tenants",
    { onRequest: [authenticate, requirePlatformAdmin] },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");

      try {
        return { organizations: await listTenantSummaries() };
      } catch (error) {
        request.log.error(
          { event: "tenant_list_failed", code: (error as { code?: unknown }).code },
          "Unable to list organizations",
        );

        return reply.code(503).send({
          error: "ORGANIZATIONS_UNAVAILABLE",
          message: "Unable to retrieve organizations.",
        });
      }
    },
  );

  // Onboarding progress as separate facts: infrastructure, domain, secretary
  // email verification and membership. Contains no secret references.
  app.get<{ Params: { tenantId: string } }>(
    "/admin/tenants/:tenantId/onboarding",
    {
      schema: {
        params: {
          type: "object",
          additionalProperties: false,
          required: ["tenantId"],
          properties: { tenantId: { type: "string", format: "uuid" } },
        },
      },
      onRequest: [authenticate, requirePlatformAdmin],
    },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");

      try {
        const onboarding = await getTenantOnboarding(request.params.tenantId);

        if (!onboarding) {
          return reply.code(404).send({
            error: "TENANT_NOT_FOUND",
            message: "Organization not found.",
          });
        }

        return { onboarding };
      } catch (error) {
        request.log.error(
          { event: "onboarding_read_failed", code: (error as { code?: unknown }).code },
          "Unable to read onboarding status",
        );

        return reply.code(503).send({
          error: "ONBOARDING_UNAVAILABLE",
          message: "Unable to retrieve onboarding status.",
        });
      }
    },
  );
}
