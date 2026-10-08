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