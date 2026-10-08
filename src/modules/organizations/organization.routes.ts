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
}