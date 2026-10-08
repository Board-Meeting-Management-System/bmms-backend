import { error } from "console";
import type { FastifyReply, FastifyRequest } from "fastify";

export async function requirePlatformAdmin (
    request: FastifyRequest,
    reply: FastifyReply
) {
    if (!request.authUser) {
        return reply.code(401).send({
            error: "UNAUTHORIZED",
            message: "Authentication is required",
        });
    }

    if(!request.authUser.isPlatformAdmin) {
        return reply.code(403).send({
            error: "FORBIDDEN",
            message: "Platform administrator access is required",
        })
    }
}