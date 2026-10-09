import type { FastifyInstance } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { EmailOtpError } from "./email-otp.repository.js";
import {
  confirmSecretaryEmailOtp,
  requestSecretaryEmailOtp,
} from "./email-otp.service.js";

export async function emailOtpRoutes(app: FastifyInstance) {
  app.post<{ Params: { invitationId: string } }>(
    "/admin/invitations/:invitationId/email-verification",
    {
      schema: {
        params: {
          type: "object",
          additionalProperties: false,
          required: ["invitationId"],
          properties: {
            invitationId: {
              type: "string",
              format: "uuid",
            },
          },
        },
        response: {
          202: {
            type: "object",
            additionalProperties: false,
            required: ["challengeId", "message"],
            properties: {
              challengeId: {
                type: "string",
                format: "uuid",
              },
              message: {
                type: "string",
              },
            },
          },
        },
      },
      config: {
        rateLimit: {
          max: 10,
          timeWindow: "1 minute",
        },
      },
      preHandler: [authenticate, requirePlatformAdmin],
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
        const result = await requestSecretaryEmailOtp(
          request.params.invitationId,
          actor.id,
        );

        return reply.code(202).send(result);
      } catch (error) {
        if (error instanceof EmailOtpError) {
          return reply.code(error.statusCode).send({
            error: error.code,
            message: error.message,
          });
        }

        request.log.error(
          { event: "secretary_email_verification_request_failed" },
          "Unable to request secretary email verification",
        );

        return reply.code(503).send({
          error: "EMAIL_VERIFICATION_UNAVAILABLE",
          message: "Email verification is temporarily unavailable.",
        });
      }
    },
  );

  app.post<{
    Params: { invitationId: string };
    Body: { challengeId: string; code: string };
  }>(
    "/admin/invitations/:invitationId/email-verification/confirm",
    {
      schema: {
        params: {
          type: "object",
          additionalProperties: false,
          required: ["invitationId"],
          properties: {
            invitationId: {
              type: "string",
              format: "uuid",
            },
          },
        },
        body: {
          type: "object",
          additionalProperties: false,
          required: ["challengeId", "code"],
          properties: {
            challengeId: {
              type: "string",
              format: "uuid",
            },
            code: {
              type: "string",
              pattern: "^[0-9]{6}$",
            },
          },
        },
        response: {
          200: {
            type: "object",
            additionalProperties: false,
            required: ["verified", "email", "verifiedAt"],
            properties: {
              verified: { type: "boolean" },
              email: { type: "string" },
              verifiedAt: {
                type: "string",
                format: "date-time",
              },
            },
          },
        },
      },
      config: {
        rateLimit: {
          max: 10,
          timeWindow: "1 minute",
        },
      },
      preHandler: [authenticate, requirePlatformAdmin],
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
        const result = await confirmSecretaryEmailOtp(
          request.params.invitationId,
          request.body.challengeId,
          request.body.code,
          actor.id,
        );

        return reply.code(200).send(result);
      } catch (error) {
        if (error instanceof EmailOtpError) {
          return reply.code(error.statusCode).send({
            error: error.code,
            message: error.message,
          });
        }

        // Never log the submitted code.
        request.log.error(
          { event: "secretary_email_verification_confirm_failed" },
          "Unable to confirm secretary email verification",
        );

        return reply.code(503).send({
          error: "EMAIL_VERIFICATION_UNAVAILABLE",
          message: "Email verification is temporarily unavailable.",
        });
      }
    },
  );
}
