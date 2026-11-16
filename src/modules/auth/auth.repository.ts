import {pool} from "../../db.js"
import type {
  AuthUser,
  VerifiedIdentity,
} from "./auth.types.js";

export async function upsertIdentity(
  identity: VerifiedIdentity,
): Promise<AuthUser> {
  const result = await pool.query<AuthUser>(
    `
    INSERT INTO identities (
      issuer,
      subject,
      email,
      email_verified
    )
    VALUES ($1, $2, $3, $4)

    ON CONFLICT (issuer, subject)
    DO UPDATE SET
      email = EXCLUDED.email,
      email_verified = EXCLUDED.email_verified,
      updated_at = now()

    RETURNING
      id,
      email,
      email_verified AS "emailVerified",
      status,
      is_platform_admin AS "isPlatformAdmin"
    `,
    [
      identity.issuer,
      identity.subject,
      identity.email,
      identity.emailVerified,
    ],
  );

  const user = result.rows[0];

  if (!user) {
    throw new Error("Identity persistence failed");
  }

  return user;
}

export interface PlatformAdministrator {
  id: string;
  email: string | null;
  emailVerified: boolean;
  status: "active" | "disabled";
  createdAt: string;
  /** Start of this administrator's most recent session; null if never signed in. */
  lastSignInAt: string | null;
}

/** Every platform administrator, oldest first. */
export async function listPlatformAdministrators(): Promise<PlatformAdministrator[]> {
  const result = await pool.query<{
    id: string;
    email: string | null;
    emailVerified: boolean;
    status: "active" | "disabled";
    createdAt: Date;
    lastSignInAt: Date | null;
  }>(
    `
    SELECT
      identity.id,
      identity.email,
      identity.email_verified AS "emailVerified",
      identity.status,
      identity.created_at AS "createdAt",
      (
        SELECT max(session.created_at)
        FROM auth_sessions AS session
        WHERE session.identity_id = identity.id
      ) AS "lastSignInAt"
    FROM identities AS identity
    WHERE identity.is_platform_admin
    ORDER BY identity.created_at
    `,
  );

  return result.rows.map((row) => ({
    ...row,
    createdAt: row.createdAt.toISOString(),
    lastSignInAt: row.lastSignInAt ? row.lastSignInAt.toISOString() : null,
  }));
}
