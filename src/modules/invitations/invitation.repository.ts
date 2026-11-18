import {
  assertPlatformAdmin,
  assertUsableLink,
  InvitationError,
  invalidLinkError,
  lockInvitation,
  withTransaction,
} from "./invitation.db.js";

export interface AcceptedInvitation {
  invitationId: string;
  tenantId: string;
  organizationName: string;
  email: string;
  role: "secretary";
  acceptedAt: Date;
}

/** An identity authenticated by the organization realm, as the organization platform reports it. */
export interface OrganizationIdentity {
  issuer: string;
  subject: string;
  email: string | null;
  emailVerified: boolean;
}

/**
 * Accepts an invitation for an organization-realm identity. Requires all of:
 * a usable link, a verified invitation email, and a verified identity email
 * equal to it. The organization platform creates the member in the
 * organization's own database; the control plane records who accepted.
 * Repeating it for the same identity is harmless; anyone else is refused.
 */
export async function acceptInvitation(
  tokenHash: string,
  identity: OrganizationIdentity,
): Promise<AcceptedInvitation> {
  return withTransaction(async (client) => {
    const invitation = await lockInvitation(client, { tokenHash });

    const accepted = (acceptedAt: Date): AcceptedInvitation => ({
      invitationId: invitation!.id,
      tenantId: invitation!.tenantId,
      organizationName: invitation!.tenantName,
      email: invitation!.email,
      role: "secretary",
      acceptedAt,
    });

    if (invitation?.status === "accepted" && invitation.tenantStatus === "active") {
      const previous = await client.query<{ issuer: string | null; subject: string | null }>(
        `SELECT accepted_issuer AS issuer, accepted_subject AS subject FROM tenant_invitations WHERE id = $1`,
        [invitation.id],
      );
      const row = previous.rows[0];
      if (row?.issuer === identity.issuer && row.subject === identity.subject) {
        return accepted(invitation.acceptedAt!);
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

    const result = await client.query<{ acceptedAt: Date }>(
      `
      UPDATE tenant_invitations
      SET
        status = 'accepted',
        accepted_issuer = $2,
        accepted_subject = $3,
        accepted_at = now(),
        updated_at = now()
      WHERE id = $1
        AND status = 'pending'
      RETURNING accepted_at AS "acceptedAt"
      `,
      [invitation.id, identity.issuer, identity.subject],
    );

    return accepted(result.rows[0]!.acceptedAt);
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
