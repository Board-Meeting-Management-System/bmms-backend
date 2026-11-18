import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { recordAuditSafely } from "../audit/audit.repository.js";
import { authenticate } from "../auth/authenticate.js";
import { listPlatformAdministrators } from "../auth/auth.repository.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { listSessions, revokeOtherSessions } from "../auth/session.repository.js";
import {
  addAdministrator,
  AdministratorError,
  cancelPendingAdministrator,
  listPendingAdministrators,
  revokeAdministrator,
  setAdministratorStatus,
} from "./administrators.repository.js";

const admin = { onRequest: [authenticate, requirePlatformAdmin] };
const idParams = {
  type: "object",
  additionalProperties: false,
  required: ["id"],
  properties: { id: { type: "string", format: "uuid" } },
} as const;

const actorOf = (request: FastifyRequest) => ({ id: request.authUser!.id, email: request.authUser!.email });

async function respond(reply: FastifyReply, work: () => Promise<unknown>) {
  reply.header("Cache-Control", "no-store");
  try {
    return (await work()) ?? { ok: true };
  } catch (error) {
    if (error instanceof AdministratorError) {
      return reply.code(error.statusCode).send({ error: error.code, message: error.message });
    }
    throw error;
  }
}

export async function administratorsRoutes(app: FastifyInstance) {
  app.get("/admin/administrators", admin, (request, reply) =>
    respond(reply, async () => ({
      administrators: await listPlatformAdministrators(),
      pending: await listPendingAdministrators(),
      currentId: request.authUser!.id,
    })),
  );

  app.post<{ Body: { email: string } }>(
    "/admin/administrators",
    {
      ...admin,
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["email"],
          properties: { email: { type: "string", format: "email", maxLength: 254 } },
        },
      },
      config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
    },
    (request, reply) => respond(reply, () => addAdministrator(request.body.email.trim().toLowerCase(), actorOf(request))),
  );

  app.delete<{ Params: { id: string } }>(
    "/admin/administrators/invitations/:id",
    { ...admin, schema: { params: idParams } },
    (request, reply) => respond(reply, () => cancelPendingAdministrator(request.params.id, actorOf(request))),
  );

  app.delete<{ Params: { id: string } }>(
    "/admin/administrators/:id",
    { ...admin, schema: { params: idParams } },
    (request, reply) => respond(reply, () => revokeAdministrator(request.params.id, actorOf(request))),
  );

  for (const [path, status] of [["disable", "disabled"], ["enable", "active"]] as const) {
    app.post<{ Params: { id: string } }>(
      `/admin/administrators/:id/${path}`,
      { ...admin, schema: { params: idParams } },
      (request, reply) => respond(reply, () => setAdministratorStatus(request.params.id, status, actorOf(request))),
    );
  }

  // The signed-in administrator's own sessions (My profile).
  app.get("/auth/sessions", admin, (request, reply) =>
    respond(reply, async () => ({ sessions: await listSessions(request.authUser!.id, request.cookies.bmms_session) })),
  );

  app.post("/auth/sessions/revoke-others", admin, (request, reply) =>
    respond(reply, async () => {
      const revoked = await revokeOtherSessions(request.authUser!.id, request.cookies.bmms_session!);
      await recordAuditSafely({ actor: actorOf(request), action: "administrator.sessions_revoked", metadata: { revoked } });
      return { revoked };
    }),
  );
}
