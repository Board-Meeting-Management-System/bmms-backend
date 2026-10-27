import { createHash, randomBytes } from "node:crypto";

import { pool } from "../../db.js";
import { decryptSessionTokens } from "./session.cypto.js";
import { createSession, type SessionTokenBundle } from "./session.repository.js";

// Login handoff to an organization domain. Keycloak login always completes
// on the API (one registered callback). The callback then issues a one-time
// code bound to the organization hostname; that hostname's server exchanges
// it for a session cookie of its own, valid only there. No cookie is ever
// shared across subdomains.

const CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const hashCode = (code: string) => createHash("sha256").update(code, "utf8").digest("hex");

/** Issues a 60-second, single-use code for `targetHost`. */
export async function createHandoff(sourceSessionId: string, targetHost: string): Promise<string> {
  const code = randomBytes(32).toString("base64url");
  await pool.query(
    `INSERT INTO auth_handoffs (code_hash, source_session_id, target_host) VALUES ($1, $2, $3)`,
    [hashCode(code), sourceSessionId, targetHost],
  );
  return code;
}

/**
 * Consumes a code presented on `host` and creates a session bound to it.
 * Fails (null) for unknown, used, expired or wrong-host codes, and when the
 * platform session it came from has ended.
 */
export async function exchangeHandoff(
  code: string,
  host: string,
): Promise<{ sessionToken: string; expiresAt: Date } | null> {
  if (!CODE_PATTERN.test(code)) return null;

  // Single use: any presentation consumes the code — on the wrong host too,
  // so a code that leaked elsewhere can't be replayed on the right one.
  const consumed = await pool.query<{ sourceSessionId: string; targetHost: string }>(
    `
    UPDATE auth_handoffs
    SET consumed_at = now()
    WHERE code_hash = $1
      AND consumed_at IS NULL
      AND expires_at > now()
    RETURNING source_session_id AS "sourceSessionId", target_host AS "targetHost"
    `,
    [hashCode(code)],
  );
  const handoff = consumed.rows[0];
  if (!handoff || handoff.targetHost !== host) return null;
  const sourceSessionId = handoff.sourceSessionId;

  const sources = await pool.query<{
    identityId: string;
    tokensEncrypted: string;
    accessTokenExpiresAt: Date;
  }>(
    `
    SELECT
      session.identity_id AS "identityId",
      session.tokens_encrypted AS "tokensEncrypted",
      session.access_token_expires_at AS "accessTokenExpiresAt"
    FROM auth_sessions AS session
    JOIN identities AS identity ON identity.id = session.identity_id
    WHERE session.id = $1
      AND session.revoked_at IS NULL
      AND session.expires_at > now()
      AND session.bound_host IS NULL
      AND identity.status = 'active'
    `,
    [sourceSessionId],
  );
  const source = sources.rows[0];
  if (!source) return null;

  const tokens = JSON.parse(decryptSessionTokens(source.tokensEncrypted, sourceSessionId)) as SessionTokenBundle;

  try {
    const session = await createSession({
      identityId: source.identityId,
      tokens,
      accessTokenExpiresAt: source.accessTokenExpiresAt,
      boundHost: host,
    });
    return { sessionToken: session.sessionToken, expiresAt: session.expiresAt };
  } catch {
    // e.g. the access token expired meanwhile: sign in again.
    return null;
  }
}

export async function deleteExpiredHandoffs(): Promise<number> {
  const result = await pool.query(`DELETE FROM auth_handoffs WHERE expires_at <= now() - interval '1 hour'`);
  return result.rowCount ?? 0;
}
