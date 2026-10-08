import type { FastifyReply, FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { authConfig } from "./auth.config.js";
import { upsertIdentity } from "./auth.repository.js";
import type { VerifiedIdentity } from "./auth.types.js";
import { authenticateSession } from "./session-auth.service.js";
import { config } from "../../config.js";

const trustedKeys = createRemoteJWKSet(
  new URL(authConfig.jwksUrl),
  {
    timeoutDuration: 5_000,
    cooldownDuration: 30_000,
    cacheMaxAge: 600_000,
  },
);

function unauthorized(reply: FastifyReply) {
  return reply
    .header("WWW-Authenticate", "Bearer")
    .code(401)
    .send({
      error: "UNAUTHORIZED",
      message: "Sign in or provide a valid access token.",
    });
}

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // Prevent caching of authenticated responses, including errors.
  reply.header("Cache-Control", "no-store");

  const authorization = request.headers.authorization;
  // Without an Authorization header, try the browser session.
if (authorization === undefined) {
  const sessionToken = request.cookies.bmms_session;

  if (!sessionToken) {
    return unauthorized(reply);
  }

  // Cookie-authenticated write requests need CSRF protection.
  // This implementation requires an exact trusted Origin.
  const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

  if (!safeMethods.has(request.method)) {
    const allowedOrigins = new Set([
      new URL(config.frontendOrigin).origin,
      new URL(authConfig.redirectUri).origin,
    ]);

    const origin = request.headers.origin;

    if (!origin || !allowedOrigins.has(origin)) {
      return reply.code(403).send({
        error: "ORIGIN_NOT_ALLOWED",
        message: "Request origin is not allowed.",
      });
    }
  }

  try {
    const user = await authenticateSession(sessionToken);

    if (!user) {
      reply.clearCookie("bmms_session", { path: "/" });
      return unauthorized(reply);
    }

    request.authUser = user;
    return;
  } catch (error) {
    const details = error as {
      name?: string;
      code?: string;
    };

    request.log.error(
      {
        name: details.name,
        code: details.code,
      },
      "Session authentication failed",
    );

    return reply.code(503).send({
      error: "AUTH_UNAVAILABLE",
      message: "Authentication is temporarily unavailable.",
    });
  }
}
  const match = authorization?.match(/^Bearer ([^\s]+)$/i);
  const token = match?.[1];

  request.log.info(
  {
    nodeEnv: process.env.NODE_ENV,
    hasAuthorizationHeader: Boolean(authorization),
    matchesBearerFormat: Boolean(match),
    tokenLength: token?.length ?? 0,
  },
  "Authentication input check",
);

  if (!token || token.length > 16_384) {
    return unauthorized(reply);
  }

  let identity: VerifiedIdentity;

  try {
    const { payload } = await jwtVerify(token, trustedKeys, {
      issuer: authConfig.issuer,
      audience: authConfig.audience,
      algorithms: ["RS256"],
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
      clockTolerance: 5,
    });

    if (
      typeof payload.sub !== "string" ||
      payload.sub.length === 0
    ) {
      return unauthorized(reply);
    }

    identity = {
      issuer: authConfig.issuer,
      subject: payload.sub,
      email:
        typeof payload.email === "string"
          ? payload.email
          : null,
      emailVerified: payload.email_verified === true,
    };
  } catch {
    // Never return token contents or detailed verification errors.
    return unauthorized(reply);
  }

  try {
    const user = await upsertIdentity(identity);

    if (user.status !== "active") {
      return reply.code(403).send({
        error: "ACCOUNT_DISABLED",
        message: "This account is disabled.",
      });
    }

    request.authUser = user;
  } catch {
    request.log.error(
      { event: "identity_persistence_failed" },
      "Authentication database operation failed",
    );

    return reply.code(503).send({
      error: "AUTH_UNAVAILABLE",
      message: "Authentication is temporarily unavailable.",
    });
  }
}