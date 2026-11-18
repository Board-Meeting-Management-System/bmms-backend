import type { FastifyInstance } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { listAuditEvents } from "./audit.repository.js";

export async function auditRoutes(app: FastifyInstance) {
  // Newest first; ?tenantId= for one organization; ?before=<id> to page.
  app.get<{ Querystring: { tenantId?: string; limit?: number; before?: string } }>(
    "/admin/audit",
    {
      onRequest: [authenticate, requirePlatformAdmin],
      schema: {
        querystring: {
          type: "object",
          additionalProperties: false,
          properties: {
            tenantId: { type: "string", format: "uuid" },
            limit: { type: "integer", minimum: 1, maximum: 200 },
            before: { type: "string", pattern: "^[0-9]{1,18}$" },
          },
        },
      },
    },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      const events = await listAuditEvents(request.query);
      return { events, nextBefore: events.length ? events[events.length - 1]!.id : null };
    },
  );
}
