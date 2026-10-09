import type { PoolClient } from "pg";

import { pool } from "../../db.js";

// Shared by the invitation repositories. Lock order everywhere:
// identity → invitation (FOR UPDATE) + tenant (FOR SHARE) → challenge.

export class InvitationError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "InvitationError";
  }
}

// One response for every unusable link, so a token can't be probed for
// whether it ever existed, was replaced, or was revoked.
export function invalidLinkError(): InvitationError {
  return new InvitationError(
    404,
    "INVITATION_LINK_INVALID",
    "This invitation link isn't valid. Use the link in the most recent invitation email.",
  );
}

export async function withTransaction<T>(
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL statement_timeout = '5s'");

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

/** Authorization is checked again at the database boundary. */
export async function assertPlatformAdmin(
  client: PoolClient,
  identityId: string,
): Promise<void> {
  const actor = await client.query(
    `
    SELECT id
    FROM identities
    WHERE id = $1
      AND status = 'active'
      AND is_platform_admin = TRUE
    FOR SHARE
    `,
    [identityId],
  );

  if (actor.rowCount !== 1) {
    throw new InvitationError(
      403,
      "FORBIDDEN",
      "Platform administrator access is required.",
    );
  }
}

export interface LockedInvitation {
  id: string;
  tenantId: string;
  tenantName: string;
  tenantStatus: string;
  email: string;
  status: "pending_setup" | "pending" | "accepted" | "expired" | "revoked";
  verifiedAt: Date | null;
  /** expires_at has passed (link-bearing invitations only). */
  linkExpired: boolean;
  acceptedBy: string | null;
  acceptedAt: Date | null;
}

export async function lockInvitation(
  client: PoolClient,
  by: { id: string } | { tokenHash: string },
): Promise<LockedInvitation | null> {
  const [column, value] =
    "id" in by ? ["invitation.id", by.id] : ["invitation.token_hash", by.tokenHash];

  const result = await client.query<LockedInvitation>(
    `
    SELECT
      invitation.id,
      invitation.tenant_id AS "tenantId",
      tenant.name AS "tenantName",
      tenant.status AS "tenantStatus",
      invitation.email,
      invitation.status,
      invitation.email_verified_at AS "verifiedAt",
      COALESCE(invitation.expires_at <= clock_timestamp(), FALSE) AS "linkExpired",
      invitation.accepted_by AS "acceptedBy",
      invitation.accepted_at AS "acceptedAt"
    FROM tenant_invitations AS invitation
    JOIN tenants AS tenant ON tenant.id = invitation.tenant_id
    WHERE ${column} = $1
      AND invitation.role = 'secretary'
    FOR UPDATE OF invitation
    FOR SHARE OF tenant
    `,
    [value],
  );

  return result.rows[0] ?? null;
}

/**
 * For requests made with an invitation link: the link must belong to an
 * open, unexpired invitation of an active organization.
 */
export function assertUsableLink(
  invitation: LockedInvitation | null,
): asserts invitation is LockedInvitation {
  if (
    !invitation ||
    invitation.status !== "pending" ||
    invitation.tenantStatus !== "active"
  ) {
    throw invalidLinkError();
  }

  if (invitation.linkExpired) {
    throw new InvitationError(
      410,
      "INVITATION_EXPIRED",
      "This invitation has expired. Ask your BMMS administrator to send a new one.",
    );
  }
}
