import { createHash, randomBytes, randomUUID } from "node:crypto";
import { pool } from "../../db.js";
import { encryptSessionTokens } from "./session-cypto.js";

export interface SessionTokenBundle {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
}

interface CreateSessionInput {
  identityId: string;
  tokens: SessionTokenBundle;
  accessTokenExpiresAt: Date;
}

export interface StoredSession {
  id: string;
  identityId: string;
  tokensEncrypted: string;
  accessTokenExpiresAt: Date;
  expiresAt: Date;
}

const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;

function hashSessionToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export async function createSession(
  input: CreateSessionInput,
): Promise<{
  sessionToken: string;
  expiresAt: Date;
}> {
  const now = Date.now();

  if (
    !input.tokens.accessToken ||
    !Number.isFinite(input.accessTokenExpiresAt.getTime()) ||
    input.accessTokenExpiresAt.getTime() <= now
  ) {
    throw new Error("A valid, unexpired access token is required");
  }

  const sessionId = randomUUID();
  const sessionToken = randomBytes(32).toString("base64url");
  const expiresAt = new Date(now + SESSION_LIFETIME_MS);

  const tokensEncrypted = encryptSessionTokens(
    JSON.stringify(input.tokens),
    sessionId,
  );

  // Only active identities may receive a session.
  const result = await pool.query(
    `
    INSERT INTO auth_sessions (
      id,
      identity_id,
      session_token_hash,
      tokens_encrypted,
      access_token_expires_at,
      expires_at
    )
    SELECT $1, id, $3, $4, $5, $6
    FROM identities
    WHERE id = $2
      AND status = 'active'
    RETURNING id
    `,
    [
      sessionId,
      input.identityId,
      hashSessionToken(sessionToken),
      tokensEncrypted,
      input.accessTokenExpiresAt,
      expiresAt,
    ],
  );

  if (result.rows.length !== 1) {
    throw new Error("Cannot create a session for this identity");
  }

  // The raw token goes only into the browser's HttpOnly cookie.
  return { sessionToken, expiresAt };
}

export async function findSession(
  sessionToken: string,
): Promise<StoredSession | null> {
  // A 32-byte random value produces 43 base64url characters.
  if (!/^[A-Za-z0-9_-]{43}$/.test(sessionToken)) {
    return null;
  }

  const result = await pool.query<StoredSession>(
    `
    SELECT
      s.id,
      s.identity_id AS "identityId",
      s.tokens_encrypted AS "tokensEncrypted",
      s.access_token_expires_at AS "accessTokenExpiresAt",
      s.expires_at AS "expiresAt"
    FROM auth_sessions AS s
    JOIN identities AS i ON i.id = s.identity_id
    WHERE s.session_token_hash = $1
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND i.status = 'active'
    `,
    [hashSessionToken(sessionToken)],
  );

  return result.rows[0] ?? null;
}

export async function revokeSession(
  sessionToken: string,
): Promise<void> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(sessionToken)) {
    return;
  }

  await pool.query(
    `
    UPDATE auth_sessions
    SET revoked_at = now()
    WHERE session_token_hash = $1
      AND revoked_at IS NULL
    `,
    [hashSessionToken(sessionToken)],
  );
}

export async function deleteExpiredSessions(): Promise<number> {
  const result = await pool.query(
    `
    DELETE FROM auth_sessions
    WHERE expires_at <= now()
       OR revoked_at IS NOT NULL
    `,
  );

  return result.rowCount ?? 0;
}