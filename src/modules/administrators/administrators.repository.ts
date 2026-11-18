import type { PoolClient } from "pg";

import { pool } from "../../db.js";
import { recordAudit, type AuditActor } from "../audit/audit.repository.js";
import type { AuthUser } from "../auth/auth.types.js";

// Platform administrators: admin-realm identities with is_platform_admin.
// Access can be granted by email ahead of a first sign-in; it's applied when
// that person signs in with a verified, matching email. Nobody can remove or
// disable themselves or the last active administrator. Every change revokes
// the affected sessions and is audited.

export class AdministratorError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AdministratorError";
  }
}

async function inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // One administrator change at a time, so the last-admin check holds.
    await client.query(`SELECT pg_advisory_xact_lock(hashtextextended('platform-administrators', 0))`);
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export interface PendingAdministrator {
  id: string;
  email: string;
  invitedAt: string;
}

export async function listPendingAdministrators(): Promise<PendingAdministrator[]> {
  const result = await pool.query<{ id: string; email: string; invitedAt: Date }>(
    `SELECT id, email, created_at AS "invitedAt" FROM platform_admin_invitations ORDER BY created_at`,
  );
  return result.rows.map((row) => ({ ...row, invitedAt: row.invitedAt.toISOString() }));
}

/** Grants access now if the person has signed in before; otherwise at their first sign-in. */
export async function addAdministrator(email: string, actor: { id: string; email: string | null }) {
  return inTransaction(async (client) => {
    const existing = await client.query<{ id: string; isAdmin: boolean; status: string; verified: boolean }>(
      `
      SELECT id, is_platform_admin AS "isAdmin", status, email_verified AS verified
      FROM identities
      WHERE lower(email) = $1
      ORDER BY created_at
      LIMIT 1
      FOR UPDATE
      `,
      [email],
    );
    const identity = existing.rows[0];

    if (identity?.isAdmin) {
      throw new AdministratorError(409, "ALREADY_ADMINISTRATOR", "This account is already an administrator.");
    }

    if (identity && identity.verified && identity.status === "active") {
      await client.query(`UPDATE identities SET is_platform_admin = TRUE, updated_at = now() WHERE id = $1`, [identity.id]);
      await recordAudit({ actor, action: "administrator.granted", metadata: { email } }, client);
      return { result: "granted" as const, identityId: identity.id };
    }

    const invited = await client.query(
      `INSERT INTO platform_admin_invitations (email, invited_by) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`,
      [email, actor.id],
    );
    if (invited.rowCount !== 1) {
      throw new AdministratorError(409, "ALREADY_INVITED", "Access for this email is already pending.");
    }
    await recordAudit({ actor, action: "administrator.invited", metadata: { email } }, client);
    return { result: "pending" as const, identityId: null };
  });
}

export async function cancelPendingAdministrator(invitationId: string, actor: AuditActor) {
  return inTransaction(async (client) => {
    const removed = await client.query<{ email: string }>(
      `DELETE FROM platform_admin_invitations WHERE id = $1 RETURNING email`,
      [invitationId],
    );
    if (removed.rowCount !== 1) {
      throw new AdministratorError(404, "INVITATION_NOT_FOUND", "Pending access not found.");
    }
    await recordAudit({ actor, action: "administrator.invitation_cancelled", metadata: { email: removed.rows[0]!.email } }, client);
  });
}

async function lockAdministrator(client: PoolClient, identityId: string, actorId: string) {
  if (identityId === actorId) {
    throw new AdministratorError(409, "CANNOT_CHANGE_SELF", "You can't change your own administrator access.");
  }
  const result = await client.query<{ email: string | null; status: string; isAdmin: boolean }>(
    `SELECT email, status, is_platform_admin AS "isAdmin" FROM identities WHERE id = $1 FOR UPDATE`,
    [identityId],
  );
  const admin = result.rows[0];
  if (!admin?.isAdmin) throw new AdministratorError(404, "ADMINISTRATOR_NOT_FOUND", "Administrator not found.");
  return admin;
}

async function assertAnotherActiveAdministrator(client: PoolClient, exceptId: string) {
  const others = await client.query(
    `SELECT 1 FROM identities WHERE is_platform_admin AND status = 'active' AND id <> $1 LIMIT 1`,
    [exceptId],
  );
  if (others.rowCount !== 1) {
    throw new AdministratorError(409, "LAST_ADMINISTRATOR", "At least one active administrator must remain.");
  }
}

async function revokeSessions(client: PoolClient, identityId: string) {
  await client.query(`UPDATE auth_sessions SET revoked_at = now() WHERE identity_id = $1 AND revoked_at IS NULL`, [identityId]);
}

/** Removes administrator access (the account itself stays). */
export async function revokeAdministrator(identityId: string, actor: { id: string; email: string | null }) {
  return inTransaction(async (client) => {
    const admin = await lockAdministrator(client, identityId, actor.id);
    await assertAnotherActiveAdministrator(client, identityId);
    await client.query(`UPDATE identities SET is_platform_admin = FALSE, updated_at = now() WHERE id = $1`, [identityId]);
    await revokeSessions(client, identityId);
    await recordAudit({ actor, action: "administrator.revoked", metadata: { email: admin.email } }, client);
  });
}

/** Blocks or unblocks an administrator's sign-in without removing access. */
export async function setAdministratorStatus(
  identityId: string,
  status: "active" | "disabled",
  actor: { id: string; email: string | null },
) {
  return inTransaction(async (client) => {
    const admin = await lockAdministrator(client, identityId, actor.id);
    if (admin.status === status) return;
    if (status === "disabled") {
      await assertAnotherActiveAdministrator(client, identityId);
      await revokeSessions(client, identityId);
    }
    await client.query(`UPDATE identities SET status = $2, updated_at = now() WHERE id = $1`, [identityId, status]);
    await recordAudit(
      {
        actor,
        action: status === "disabled" ? "administrator.disabled" : "administrator.enabled",
        metadata: { email: admin.email },
      },
      client,
    );
  });
}

/**
 * At sign-in: applies a pending grant for this identity's verified email.
 * Returns the user with its current admin flag.
 */
export async function applyPendingAdministratorGrant(user: AuthUser): Promise<AuthUser> {
  if (user.isPlatformAdmin || !user.emailVerified || !user.email || user.status !== "active") return user;
  const email = user.email.trim().toLowerCase();
  return inTransaction(async (client) => {
    const pending = await client.query(`DELETE FROM platform_admin_invitations WHERE email = $1 RETURNING id`, [email]);
    if (pending.rowCount !== 1) return user;
    await client.query(`UPDATE identities SET is_platform_admin = TRUE, updated_at = now() WHERE id = $1`, [user.id]);
    await recordAudit({ actor: { id: user.id, email: user.email }, action: "administrator.joined", metadata: { email } }, client);
    return { ...user, isPlatformAdmin: true };
  });
}
