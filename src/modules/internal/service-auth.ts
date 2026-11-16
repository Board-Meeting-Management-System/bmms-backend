import { createHash, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";

// Service-to-service authentication for the organization platform's
// backend. One shared bearer token (ORG_PLATFORM_SERVICE_TOKEN, ≥ 32
// characters); without it the internal API is disabled. In AWS, also keep
// these routes reachable only from the organization platform's network.

const MIN_TOKEN_LENGTH = 32;

const digest = (value: string) => createHash("sha256").update(value, "utf8").digest();

function configuredToken(): Buffer | null {
  const token = process.env.ORG_PLATFORM_SERVICE_TOKEN?.trim();
  return token && token.length >= MIN_TOKEN_LENGTH ? digest(token) : null;
}

export async function requireOrganizationPlatform(request: FastifyRequest, reply: FastifyReply) {
  reply.header("Cache-Control", "no-store");

  const expected = configuredToken();
  if (!expected) {
    return reply.code(503).send({ error: "INTERNAL_API_DISABLED", message: "The internal API is not configured." });
  }

  const match = /^Bearer (\S+)$/.exec(request.headers.authorization ?? "");
  // Compare digests: constant time, and independent of the token's length.
  if (!match || !timingSafeEqual(digest(match[1]!), expected)) {
    return reply.code(401).send({ error: "UNAUTHORIZED", message: "A valid service token is required." });
  }
}
