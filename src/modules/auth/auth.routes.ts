import type { FastifyInstance } from "fastify";

import {authenticate} from "./authenticate.js"
import { requirePlatformAdmin } from "./require-platform-admin.js";
import { listPlatformAdministrators } from "./auth.repository.js";

export async function authRoutes(app:FastifyInstance) {
    app.get(
        "/auth/me",
        { preHandler: [authenticate]},
        async (request) => ({
            user: request.authUser
        })
    )

    app.get(
        "/admin/check",
        {
            preHandler: [
                authenticate,
                requirePlatformAdmin,
            ]
        },
        async () => ({
            authorized: true,
            role: "platform_admin",
        })
    );

    // Platform administrators, for the admin portal. No tokens or session data.
    app.get(
        "/admin/administrators",
        { onRequest: [authenticate, requirePlatformAdmin] },
        async (request, reply) => {
            reply.header("Cache-Control", "no-store");
            return {
                administrators: await listPlatformAdministrators(),
                currentId: request.authUser!.id,
            };
        }
    );
}
