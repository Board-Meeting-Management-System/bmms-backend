import {
  assertPlatformAdmin,
  assertUsableLink,
  InvitationError,
  invalidLinkError,
  lockInvitation,
  withTransaction,
} from "./invitation.db.js";

export interface AcceptedInvitation {
  tenantId: string;
  organizationName: string;
  acceptedAt: Date;
}

/**
 * Turns a verified invitation into a membership for the signed-in identity.
 * Requires all of: a usable link, a verified invitation email, and a
 * Keycloak-verified identity email equal to it. The link is single use.
 */
export async function acceptInvitation(
  tokenHash: string,
  identityId: string,
): Promise<AcceptedInvitation> {
  return withTransaction(async (client) => {
    const identities = await client.query<{
      status: string;
      email: string | null;
      emailVerified: boolean;
    }>(
      `
      SELECT status, email, email_verified AS "emailVerified"
      FROM identities
      WHERE id = $1
      FOR SHARE
      `,
      [identityId],
    );

    const identity = identities.rows[0];

    if (!identity || identity.status !== "active") {
      throw new InvitationError(403, "FORBIDDEN", "This account can't accept invitations.");
    }

    const invitation = await lockInvitation(client, { tokenHash });

    // Repeating a completed acceptance is harmless for the same person.
    if (invitation?.status === "accepted" && invitation.tenantStatus === "active") {
      if (invitation.acceptedBy === identityId) {
        return {
          tenantId: invitation.tenantId,
          organizationName: invitation.tenantName,
          acceptedAt: invitation.acceptedAt!,
        };
      }

      throw invalidLinkError();
    }

    assertUsableLink(invitation);

    if (invitation.verifiedAt === null) {
      throw new InvitationError(
        409,
        "EMAIL_NOT_VERIFIED",
        "Verify your email address with the emailed code first.",
      );
    }

    if (!identity.emailVerified) {
      throw new InvitationError(
        403,
        "IDENTITY_EMAIL_NOT_VERIFIED",
        "Your sign-in account's email address isn't verified. Verify it in your account, then try again.",
      );
    }

    if (identity.email?.trim().toLowerCase() !== invitation.email) {
      throw new InvitationError(
        403,
        "IDENTITY_EMAIL_MISMATCH",
        "You're signed in with a different email address. Sign in with the account for the invited address.",
      );
    }

    const membership = await client.query(
      `
      INSERT INTO tenant_memberships (tenant_id, identity_id, role, invitation_id)
      VALUES ($1, $2, 'secretary', $3)
      ON CONFLICT (tenant_id, identity_id) DO NOTHING
      `,
      [invitation.tenantId, identityId, invitation.id],
    );

    if (membership.rowCount !== 1) {
      throw new InvitationError(
        409,
        "ALREADY_MEMBER",
        "You're already a member of this organization.",
      );
    }

    const accepted = await client.query<{ acceptedAt: Date }>(
      `
      UPDATE tenant_invitations
      SET
        status = 'accepted',
        accepted_by = $2,
        accepted_at = now(),
        updated_at = now()
      WHERE id = $1
        AND status = 'pending'
      RETURNING accepted_at AS "acceptedAt"
      `,
      [invitation.id, identityId],
    );

    return {
      tenantId: invitation.tenantId,
      organizationName: invitation.tenantName,
      acceptedAt: accepted.rows[0]!.acceptedAt,
    };
  });
}

/**
 * Admin action: corrects the secretary's address. The database trigger
 * clears the verification, the link and any outstanding code.
 */
export async function changeInvitationEmail(
  invitationId: string,
  email: string,
  actorId: string,
): Promise<{ email: string }> {
  return withTransaction(async (client) => {
    await assertPlatformAdmin(client, actorId);

    const invitation = await lockInvitation(client, { id: invitationId });

    if (!invitation) {
      throw new InvitationError(404, "INVITATION_NOT_FOUND", "Secretary invitation not found.");
    }

    if (!["pending_setup", "pending"].includes(invitation.status)) {
      throw new InvitationError(
        409,
        "INVITATION_NOT_AVAILABLE",
        "This invitation has already been accepted, revoked or expired.",
      );
    }

    if (invitation.email === email) {
      return { email };
    }

    try {
      await client.query(
        `
        UPDATE tenant_invitations
        SET email = $2, updated_at = now()
        WHERE id = $1
        `,
        [invitation.id, email],
      );
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new InvitationError(
          409,
          "EMAIL_ALREADY_INVITED",
          "This organization already has an open invitation for that address.",
        );
      }

      throw error;
    }

    return { email };
  });
}
