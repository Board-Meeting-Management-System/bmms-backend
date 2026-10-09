import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import {
  acceptInvitationByToken,
  confirmRecipientCode,
  lookupInvitation,
  resendRecipientCode,
  sendInvitationEmail,
} from "./email-otp.service.js";
import { InvitationError } from "./invitation.db.js";
import { changeInvitationEmail } from "./invitation.repository.js";

const uuid = { type: "string", format: "uuid" } as const;
const token = { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" } as const;

const invitationParams = {
  type: "object",
  additionalProperties: false,
  required: ["invitationId"],
  properties: { invitationId: uuid },
} as const;

const tokenBody = {
  type: "object",
  additionalProperties: false,
  required: ["token"],
  properties: { token },
} as const;

/** Sends InvitationErrors as { error, message }; logs anything else without detail. */
async function respond(
  request: FastifyRequest,
  reply: FastifyReply,
  event: string,
  work: () => Promise<{ status: number; body: unknown }>,
) {
  reply.header("Cache-Control", "no-store");

  try {
    const { status, body } = await work();
    return reply.code(status).send(body);
  } catch (error) {
    if (error instanceof InvitationError) {
      return reply.code(error.statusCode).send({ error: error.code, message: error.message });
    }

    // Never log tokens, codes or the error object itself.
    request.log.error({ event, code: (error as { code?: unknown }).code }, "Invitation request failed");

    return reply.code(503).send({
      error: "INVITATION_SERVICE_UNAVAILABLE",
      message: "This service is temporarily unavailable. Try again shortly.",
    });
  }
}

export async function invitationRoutes(app: FastifyInstance) {
  // ---- Platform administrators -------------------------------------------

  // Sends the secretary a new invitation link, plus a code while the
  // address is unverified. Earlier links stop working.
  app.post<{ Params: { invitationId: string } }>(
    "/admin/invitations/:invitationId/email-verification",
    {
      schema: { params: invitationParams },
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      onRequest: [authenticate, requirePlatformAdmin],
    },
    (request, reply) =>
      respond(request, reply, "invitation_email_failed", async () => ({
        status: 202,
        body: await sendInvitationEmail(request.params.invitationId, request.authUser!.id),
      })),
  );

  app.patch<{ Params: { invitationId: string }; Body: { email: string } }>(
    "/admin/invitations/:invitationId",
    {
      schema: {
        params: invitationParams,
        body: {
          type: "object",
          additionalProperties: false,
          required: ["email"],
          properties: { email: { type: "string", format: "email", maxLength: 254 } },
        },
      },
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      onRequest: [authenticate, requirePlatformAdmin],
    },
    (request, reply) =>
      respond(request, reply, "invitation_email_change_failed", async () => ({
        status: 200,
        body: await changeInvitationEmail(
          request.params.invitationId,
          request.body.email.trim().toLowerCase(),
          request.authUser!.id,
        ),
      })),
  );

  // ---- Invitation recipients (no session; the link token is the context) --

  app.post<{ Body: { token: string } }>(
    "/public/invitations/lookup",
    {
      schema: { body: tokenBody },
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    (request, reply) =>
      respond(request, reply, "invitation_lookup_failed", async () => ({
        status: 200,
        body: { invitation: await lookupInvitation(request.body.token) },
      })),
  );

  app.post<{ Body: { token: string } }>(
    "/public/invitations/email-verification/resend",
    {
      schema: { body: tokenBody },
      config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
    },
    (request, reply) =>
      respond(request, reply, "invitation_code_resend_failed", async () => ({
        status: 202,
        body: await resendRecipientCode(request.body.token),
      })),
  );

  app.post<{ Body: { token: string; challengeId?: string; code: string } }>(
    "/public/invitations/email-verification/confirm",
    {
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["token", "code"],
          properties: {
            token,
            challengeId: uuid,
            code: { type: "string", pattern: "^[0-9]{6}$" },
          },
        },
      },
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    },
    (request, reply) =>
      respond(request, reply, "invitation_code_confirm_failed", async () => ({
        status: 200,
        body: await confirmRecipientCode(
          request.body.token,
          request.body.challengeId ?? null,
          request.body.code,
        ),
      })),
  );

  // ---- Signed-in recipients ----------------------------------------------

  app.post<{ Body: { token: string } }>(
    "/invitations/accept",
    {
      schema: { body: tokenBody },
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      onRequest: [authenticate],
    },
    (request, reply) =>
      respond(request, reply, "invitation_accept_failed", async () => ({
        status: 200,
        body: await acceptInvitationByToken(request.body.token, request.authUser!.id),
      })),
  );
}
