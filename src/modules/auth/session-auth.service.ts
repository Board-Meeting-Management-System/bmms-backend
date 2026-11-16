import { createHash } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import * as oidc from "openid-client";

import { pool } from "../../db.js";
import { authConfig } from "./auth.config.js";
import { getOidcClient } from "./oidc.client.js";
import {
  decryptSessionTokens,
  encryptSessionTokens,
} from "./session.cypto.js";
import type { AuthUser } from "./auth.types.js";
import type { SessionTokenBundle } from "./session.repository.js";

const trustedKeys = createRemoteJWKSet(
  new URL(authConfig.jwksUrl),
  { timeoutDuration: 5_000 },
);

interface SessionRow {
  sessionId: string;
  identityId: string;
  tokensEncrypted: string;
  accessTokenExpiresAt: Date;
  expiresAt: Date;
}

interface IdentityRow extends AuthUser {
  issuer: string;
  subject: string;
}

function parseTokenBundle(value: string): SessionTokenBundle {
  const parsed: unknown = JSON.parse(value);

  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid session token bundle");
  }

  const data = parsed as Record<string, unknown>;

  if (
    typeof data.accessToken !== "string" ||
    !data.accessToken ||
    (data.refreshToken !== undefined &&
      typeof data.refreshToken !== "string") ||
    (data.idToken !== undefined &&
      typeof data.idToken !== "string")
  ) {
    throw new Error("Invalid session token bundle");
  }

  return {
    accessToken: data.accessToken,
    ...(typeof data.refreshToken === "string"
      ? { refreshToken: data.refreshToken }
      : {}),
    ...(typeof data.idToken === "string"
      ? { idToken: data.idToken }
      : {}),
  };
}

export async function authenticateSession(
  sessionToken: string,
): Promise<AuthUser | null> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(sessionToken)) {
    return null;
  }

  const tokenHash = createHash("sha256")
    .update(sessionToken)
    .digest("hex");

  const db = await pool.connect();

  try {
    await db.query("BEGIN");
    await db.query("SET LOCAL lock_timeout = '5s'");

    // Lock this session so concurrent requests don't refresh it together.
    const result = await db.query<SessionRow>(
      `
      SELECT
        id AS "sessionId",
        identity_id AS "identityId",
        tokens_encrypted AS "tokensEncrypted",
        access_token_expires_at AS "accessTokenExpiresAt",
        expires_at AS "expiresAt"
      FROM auth_sessions
      WHERE session_token_hash = $1
        AND revoked_at IS NULL
        AND expires_at > clock_timestamp()
      FOR UPDATE
      `,
      [tokenHash],
    );

    const session = result.rows[0];

    if (!session) {
      await db.query("COMMIT");
      return null;
    }

    const rejectSession = async (): Promise<null> => {
      await db.query(
        `
        UPDATE auth_sessions
        SET revoked_at = now()
        WHERE id = $1
        `,
        [session.sessionId],
      );

      await db.query("COMMIT");
      return null;
    };

    // Read current BMMS permissions; don't take admin roles from tokens.
    const identities = await db.query<IdentityRow>(
      `
      SELECT
        id,
        issuer,
        subject,
        email,
        email_verified AS "emailVerified",
        status,
        is_platform_admin AS "isPlatformAdmin"
      FROM identities
      WHERE id = $1
      `,
      [session.identityId],
    );

    const identity = identities.rows[0];

    if (
      !identity ||
      identity.status !== "active" ||
      identity.issuer !== authConfig.issuer ||
      session.expiresAt.getTime() <= Date.now()
    ) {
      return await rejectSession();
    }

    let bundle = parseTokenBundle(
      decryptSessionTokens(
        session.tokensEncrypted,
        session.sessionId,
      ),
    );

    let refreshed = false;

    // Refresh shortly before access-token expiry.
    if (
      session.accessTokenExpiresAt.getTime() <=
      Date.now() + 30_000
    ) {
      if (!bundle.refreshToken) {
        return await rejectSession();
      }

      const client = await getOidcClient();

      try {
        const tokens = await oidc.refreshTokenGrant(
          client,
          bundle.refreshToken,
        );

        bundle = {
          accessToken: tokens.access_token,
          refreshToken:
            tokens.refresh_token ?? bundle.refreshToken,
          ...(tokens.id_token ?? bundle.idToken
            ? { idToken: tokens.id_token ?? bundle.idToken }
            : {}),
        };

        refreshed = true;
      } catch (error) {
        // Expired/revoked refresh token: require a new login.
        if (
          error instanceof oidc.ResponseBodyError &&
          error.error === "invalid_grant"
        ) {
          return await rejectSession();
        }

        // Provider/network failures become 503, preserving the session.
        throw error;
      }
    }

    const { payload } = await jwtVerify(
      bundle.accessToken,
      trustedKeys,
      {
        issuer: authConfig.issuer,
        audience: authConfig.audience,
        algorithms: ["RS256"],
        requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
      },
    );

    // The token must still belong to this session's identity.
    if (
      payload.sub !== identity.subject ||
      typeof payload.exp !== "number" ||
      session.expiresAt.getTime() <= Date.now()
    ) {
      return await rejectSession();
    }

    if (refreshed) {
      await db.query(
        `
        UPDATE auth_sessions
        SET
          tokens_encrypted = $2,
          access_token_expires_at = $3
        WHERE id = $1
        `,
        [
          session.sessionId,
          encryptSessionTokens(
            JSON.stringify(bundle),
            session.sessionId,
          ),
          new Date(payload.exp * 1000),
        ],
      );
    }

    await db.query("COMMIT");

    return {
      id: identity.id,
      email: identity.email,
      emailVerified: identity.emailVerified,
      status: identity.status,
      isPlatformAdmin: identity.isPlatformAdmin,
    };
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  } finally {
    db.release();
  }
}