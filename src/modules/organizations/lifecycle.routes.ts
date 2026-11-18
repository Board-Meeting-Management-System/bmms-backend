import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { pool } from "../../db.js";
import { collectTenantUsage } from "../usage/usage.repository.js";
import {
  cancelDeletion,
  LifecycleError,
  reactivateOrganization,
  scheduleDeletion,
  suspendOrganization,
} from "./lifecycle.repository.js";

const admin = { onRequest: [authenticate, requirePlatformAdmin] };
const params = {
  type: "object",
  additionalProperties: false,
  required: ["tenantId"],
  properties: { tenantId: { type: "string", format: "uuid" } },
} as const;

async function respond(reply: FastifyReply, work: () => Promise<unknown>) {
  reply.header("Cache-Control", "no-store");
  try {
    return await work();
  } catch (error) {
    if (error instanceof LifecycleError) {
      return reply.code(error.statusCode).send({ error: error.code, message: error.message });
    }
    throw error;
  }
}

async function getTenantStatus(tenantId: string): Promise<string | null> {
  const result = await pool.query<{ status: string }>(`SELECT status FROM tenants WHERE id = $1`, [tenantId]);
  return result.rows[0]?.status ?? null;
}

const actorOf = (request: FastifyRequest) => ({ id: request.authUser!.id, email: request.authUser!.email });

export async function lifecycleRoutes(app: FastifyInstance) {
  app.post<{ Params: { tenantId: string }; Body: { reason?: string } }>(
    "/admin/tenants/:tenantId/suspend",
    {
      ...admin,
      schema: {
        params,
        body: {
          type: ["object", "null"],
          additionalProperties: false,
          properties: { reason: { type: "string", maxLength: 500 } },
        },
      },
    },
    (request, reply) =>
      respond(reply, () =>
        suspendOrganization(request.params.tenantId, actorOf(request), request.body?.reason?.trim() || null),
      ),
  );

  app.post<{ Params: { tenantId: string } }>(
    "/admin/tenants/:tenantId/reactivate",
    { ...admin, schema: { params } },
    (request, reply) => respond(reply, () => reactivateOrganization(request.params.tenantId, actorOf(request))),
  );

  // Schedules deletion after the grace period. Confirm with the slug.
  app.post<{ Params: { tenantId: string }; Body: { confirmSlug: string } }>(
    "/admin/tenants/:tenantId/deletion",
    {
      ...admin,
      schema: {
        params,
        body: {
          type: "object",
          additionalProperties: false,
          required: ["confirmSlug"],
          properties: { confirmSlug: { type: "string", maxLength: 63 } },
        },
      },
    },
    (request, reply) =>
      respond(reply, () => scheduleDeletion(request.params.tenantId, actorOf(request), request.body.confirmSlug)),
  );

  // Measures the organization's usage now (the worker also does it periodically).
  app.post<{ Params: { tenantId: string } }>(
    "/admin/tenants/:tenantId/usage/refresh",
    { ...admin, schema: { params }, config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    (request, reply) =>
      respond(reply, async () => {
        const exists = await getTenantStatus(request.params.tenantId);
        if (!exists) throw new LifecycleError(404, "TENANT_NOT_FOUND", "Organization not found.");
        return { usage: await collectTenantUsage(request.params.tenantId) };
      }),
  );

  app.delete<{ Params: { tenantId: string } }>(
    "/admin/tenants/:tenantId/deletion",
    { ...admin, schema: { params } },
    (request, reply) => respond(reply, () => cancelDeletion(request.params.tenantId, actorOf(request))),
  );
}
