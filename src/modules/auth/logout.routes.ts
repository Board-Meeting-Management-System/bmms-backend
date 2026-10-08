import type { FastifyInstance } from "fastify";
import * as oidc from "openid-client";

import { config } from "../../config.js";
import { authConfig } from "./auth.config.js";
import { getOidcClient } from "./oidc.client.js";
import { revokeSession } from "./session-repository.js";

export async function logoutRoutes(app: FastifyInstance) {
  const backendOrigin = new URL(authConfig.redirectUri).origin;

  const allowedOrigins = new Set([
    new URL(config.frontendOrigin).origin,
    backendOrigin,
  ]);

  const postLogoutRedirectUri = new URL(
    "/auth/logged-out",
    backendOrigin,
  ).href;

  app.post("/auth/logout", async (request, reply) => {
    reply.header("Cache-Control", "no-store");

    const origin = request.headers.origin;

    if (!origin || !allowedOrigins.has(origin)) {
      return reply.code(403).send({
        error: "ORIGIN_NOT_ALLOWED",
        message: "Request origin is not allowed.",
      });
    }

    // Complete local logout even if Keycloak is unavailable.
    try {
      const sessionToken = request.cookies.bmms_session;

      if (sessionToken) {
        await revokeSession(sessionToken);
      }

      reply.clearCookie("bmms_session", { path: "/" });
      reply.clearCookie("bmms_login_binding", { path: "/auth" });
    } catch {
      request.log.error(
        { event: "local_logout_failed" },
        "Unable to revoke BMMS session",
      );

      return reply.code(503).send({
        error: "LOGOUT_UNAVAILABLE",
        message: "Unable to complete logout. Please try again.",
      });
    }

    try {
      const client = await getOidcClient();

      const logoutUrl = oidc.buildEndSessionUrl(client, {
        client_id: authConfig.client_id,
        post_logout_redirect_uri: postLogoutRedirectUri,
      });

      return {
        localLogoutComplete: true,
        logoutUrl: logoutUrl.href,
      };
    } catch {
      request.log.warn(
        { event: "keycloak_logout_unavailable" },
        "BMMS logout completed, but Keycloak logout is unavailable",
      );

      return {
        localLogoutComplete: true,
        logoutUrl: null,
        message:
          "Signed out of BMMS. Keycloak logout could not be started.",
      };
    }
  });

  app.get("/auth/logged-out", async (_request, reply) => {
    reply.header("Cache-Control", "no-store");
    reply.header("Referrer-Policy", "no-referrer");

    return {
      message: "Logout return page. Visit /auth/login to sign in again.",
    };
  });
}