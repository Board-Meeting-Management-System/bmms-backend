import type { FastifyInstance } from "fastify";
import * as oidc from "openid-client";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { config } from "../../config.js";
import { authConfig } from "./auth.config.js";
import { getOidcClient } from "./oidc.client.js";
import { consumeLoginAttempt } from "./login-attempt.repository.js";
import { upsertIdentity } from "./auth.repository.js";
import { applyPendingAdministratorGrant } from "../administrators/administrators.repository.js";
import { recordAuditSafely } from "../audit/audit.repository.js";

// Authentication methods (OIDC "amr") that count as a second factor.
const MFA_METHODS = new Set(["otp", "mfa", "hwk", "swk", "webauthn", "totp"]);
import {
  createSession,
  revokeSession,
} from "./session.repository.js";

const trustedKeys = createRemoteJWKSet(
  new URL(authConfig.jwksUrl),
);

// Login returns the browser to the frontend: the allowlisted path stored
// with the login attempt, or the admin portal. Failures add
// ?login=<reason> for the frontend to show.
function loginSuccessUrl(returnPath: string | null): string {
  return new URL(returnPath ?? "/master", config.frontendOrigin).href;
}

function loginErrorUrl(
  reason: "invalid" | "expired" | "disabled" | "failed" | "mfa_required",
): string {
  const url = new URL("/master", config.frontendOrigin);
  url.searchParams.set("login", reason);
  return url.href;
}

export async function authCallbackRoutes(app: FastifyInstance) {
  app.get("/auth/callback", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    reply.header("Referrer-Policy", "no-referrer");

    let stage = "validate_callback";

    try {
      // Use our configured callback origin, not the incoming Host header.
      const callbackUrl = new URL(authConfig.redirectUri);
      const incomingUrl = new URL(
        request.url,
        callbackUrl.origin,
      );

      if (incomingUrl.pathname !== callbackUrl.pathname) {
        throw new Error("Unexpected callback path");
      }

      callbackUrl.search = incomingUrl.search;

      const states = callbackUrl.searchParams.getAll("state");
      const state = states[0];
      const browserBinding = request.cookies.bmms_login_binding;

      if (
        states.length !== 1 ||
        !state ||
        state.length > 256 ||
        !browserBinding ||
        !/^[A-Za-z0-9_-]{43}$/.test(browserBinding)
      ) {
        return reply.redirect(loginErrorUrl("invalid"));
      }

      const allowLocalHttp =
        process.env.NODE_ENV === "development" &&
        callbackUrl.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(
          callbackUrl.hostname,
        );

      if (
        callbackUrl.protocol !== "https:" &&
        !allowLocalHttp
      ) {
        throw new Error("HTTPS callback required");
      }

      stage = "consume_login_attempt";

      // Atomically remove the attempt so it cannot be reused.
      const attempt = await consumeLoginAttempt(
        state,
        browserBinding,
      );

      reply.clearCookie("bmms_login_binding", {
        path: "/auth",
      });

      if (!attempt) {
        return reply.redirect(loginErrorUrl("expired"));
      }

      stage = "exchange_code";

      const client = await getOidcClient();

      const tokens = await oidc.authorizationCodeGrant(
        client,
        callbackUrl,
        {
          pkceCodeVerifier: attempt.pkceVerifier,
          expectedState: attempt.state,
          expectedNonce: attempt.nonce,
          idTokenExpected: true,
        },
      );

      stage = "verify_tokens";

      if (!tokens.id_token) {
        throw new Error("Missing ID token");
      }

      // ID tokens are intended for the login client.
      const { payload: identityClaims } = await jwtVerify(
        tokens.id_token,
        trustedKeys,
        {
          issuer: authConfig.issuer,
          audience: authConfig.client_id,
          algorithms: ["RS256"],
          requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
        },
      );

      // Access tokens are intended for the BMMS API.
      const { payload: accessClaims } = await jwtVerify(
        tokens.access_token,
        trustedKeys,
        {
          issuer: authConfig.issuer,
          audience: authConfig.audience,
          algorithms: ["RS256"],
          requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
        },
      );

      if (
        typeof identityClaims.sub !== "string" ||
        identityClaims.sub.length === 0 ||
        identityClaims.sub !== accessClaims.sub ||
        typeof accessClaims.exp !== "number"
      ) {
        throw new Error("Invalid token identity");
      }

      stage = "save_identity";

      let user = await upsertIdentity({
        issuer: authConfig.issuer,
        subject: identityClaims.sub,
        email:
          typeof identityClaims.email === "string"
            ? identityClaims.email
            : null,
        emailVerified: identityClaims.email_verified === true,
      });

      if (user.status !== "active") {
        return reply.redirect(loginErrorUrl("disabled"));
      }

      // Access granted by email before this person's first sign-in.
      user = await applyPendingAdministratorGrant(user);

      // Optional: administrators must have signed in with a second factor.
      // Needs Keycloak's AMR mapper on the client (see docs).
      if (user.isPlatformAdmin && process.env.ADMIN_REQUIRE_MFA?.trim() === "true") {
        // A list per the OIDC spec; accept a single string too.
        const rawAmr: unknown = identityClaims.amr;
        const amr = Array.isArray(rawAmr) ? rawAmr.map(String) : typeof rawAmr === "string" ? rawAmr.split(/[\s,]+/).filter(Boolean) : [];
        if (!amr.some((method) => MFA_METHODS.has(method))) {
          await recordAuditSafely({
            actor: { id: user.id, email: user.email },
            action: "administrator.sign_in_refused",
            // What Keycloak reported (method names only), to diagnose the mapper setup.
            metadata: { reason: "mfa_required", amr: amr.join(" ") || null, acr: typeof identityClaims.acr === "string" ? identityClaims.acr : null },
          });
          return reply.redirect(loginErrorUrl("mfa_required"));
        }
      }

      stage = "create_session";

      // Replace this browser's previous session after successful login.
      const previousSession = request.cookies.bmms_session;

      if (previousSession) {
        await revokeSession(previousSession);
      }

      const session = await createSession({
        identityId: user.id,
        accessTokenExpiresAt: new Date(accessClaims.exp * 1000),
        tokens: {
          accessToken: tokens.access_token,
          ...(tokens.refresh_token
            ? { refreshToken: tokens.refresh_token }
            : {}),
          idToken: tokens.id_token,
        },
      });

      reply.setCookie("bmms_session", session.sessionToken, {
        httpOnly: true,
        secure: !allowLocalHttp,
        sameSite: "lax",
        path: "/",
        expires: session.expiresAt,
      });

      if (user.isPlatformAdmin) {
        await recordAuditSafely({ actor: { id: user.id, email: user.email }, action: "administrator.signed_in" });
      }

      // Move away from the URL containing the authorization code.
      return reply.redirect(loginSuccessUrl(attempt.returnPath));
    } catch (error) {
      const details = error as {
        name?: string;
        code?: string;
      };

      // Do not log tokens, authorization codes, or full error objects.
      request.log.error(
        {
          stage,
          name: details.name,
          code: details.code,
        },
        "Authentication callback failed",
      );

      reply.clearCookie("bmms_login_binding", {
        path: "/auth",
      });

      return reply.redirect(loginErrorUrl("failed"));
    }
  });
}