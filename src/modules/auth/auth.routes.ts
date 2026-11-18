import type { FastifyInstance } from "fastify";

import {authenticate} from "./authenticate.js"
import { requirePlatformAdmin } from "./require-platform-admin.js";

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
}
