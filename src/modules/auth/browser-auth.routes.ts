import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import * as oidc from "openid-client";

import { authConfig } from "./auth.config.js";
import { getOidcClient } from "./oidc.client.js";
import { createLoginAttempt } from "./login-attempt.repository.js";

export async function browserAuthRoutes(app: FastifyInstance) {
  app.get(
    "/auth/login",
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: "1 minute",
        },
      },
    },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      reply.header("Referrer-Policy", "no-referrer");

      try {
        const client = await getOidcClient();

        const state = oidc.randomState();
        const nonce = oidc.randomNonce();
        const pkceVerifier = oidc.randomPKCECodeVerifier();

        const codeChallenge =
          await oidc.calculatePKCECodeChallenge(pkceVerifier);

        const browserBinding = randomBytes(32).toString("base64url");

        const redirectUri = new URL(authConfig.redirectUri);

        const allowLocalHttp =
          process.env.NODE_ENV === "development" &&
          redirectUri.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(
            redirectUri.hostname,
          );

        if (redirectUri.protocol !== "https:" && !allowLocalHttp) {
          throw new Error("HTTPS callback required");
        }

        const authorizationUrl = oidc.buildAuthorizationUrl(client, {
          response_type: "code",
          response_mode: "query",
          redirect_uri: authConfig.redirectUri,
          scope: "openid profile email",
          state,
          nonce,
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
        });

        await createLoginAttempt({
          browserBinding,
          state,
          pkceVerifier,
          nonce,
        });

        reply.setCookie("bmms_login_binding", browserBinding, {
          httpOnly: true,
          secure: !allowLocalHttp,
          sameSite: "lax",
          path: "/auth",
          maxAge: 5 * 60,
        });

        return reply.redirect(authorizationUrl.href);
      
        } catch (error) {
  const details = error as {
    name?: string;
    code?: string;
    message?: string;
    cause?: {
      code?: string;
    };
  };

  request.log.error(
    {
      name: details.name,
      code: details.code,
      message: details.message,
      causeCode: details.cause?.code,
    },
    "Browser login startup failed",
  );

  return reply.code(503).send({
    error: "LOGIN_UNAVAILABLE",
    message: "Unable to start login. Please try again.",
  });
}
    },
  );
}