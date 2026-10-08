import { createHash } from "node:crypto";
import { pool } from "../../db.js";

interface CreateLoginAttemptInput {
  browserBinding: string;
  state: string;
  pkceVerifier: string;
  nonce: string;
}

interface LoginAttempt {
  id: string;
  state: string;
  pkceVerifier: string;
  nonce: string;
}

function hashBrowserBinding(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export async function createLoginAttempt(
  input: CreateLoginAttemptInput,
): Promise<void> {
  await pool.query(
    `
    INSERT INTO auth_login_attempts (
      browser_binding_hash,
      state,
      pkce_verifier,
      nonce
    )
    VALUES ($1, $2, $3, $4)
    `,
    [
      hashBrowserBinding(input.browserBinding),
      input.state,
      input.pkceVerifier,
      input.nonce,
    ],
  );
}

export async function consumeLoginAttempt(
  state: string,
  browserBinding: string,
): Promise<LoginAttempt | null> {
  const result = await pool.query<LoginAttempt>(
    `
    DELETE FROM auth_login_attempts
    WHERE state = $1
      AND browser_binding_hash = $2
      AND expires_at > now()
    RETURNING
      id,
      state,
      pkce_verifier AS "pkceVerifier",
      nonce
    `,
    [state, hashBrowserBinding(browserBinding)],
  );

  return result.rows[0] ?? null;
}

export async function deleteExpiredLoginAttempts(): Promise<number> {
  const result = await pool.query(
    `
    DELETE FROM auth_login_attempts
    WHERE expires_at <= now()
    `,
  );

  return result.rowCount ?? 0;
}