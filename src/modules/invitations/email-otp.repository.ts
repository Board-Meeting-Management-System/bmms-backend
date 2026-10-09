import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

import { pool } from "../../db.js";
import {
  generateEmailOtp,
  hashEmailOtp,
  matchesEmailOtp,
} from "./email-otp.crypto.js";
import { generateInvitationToken, hashInvitationToken } from "./invitation-token.js";
import {
  assertPlatformAdmin,
  assertUsableLink,
  InvitationError,
  invalidLinkError,
  lockInvitation,
  withTransaction,
} from "./invitation.db.js";

// Must match the attempts CHECK in secretary_email_verifications.
export const MAX_OTP_ATTEMPTS = 5;
const MAX_SENDS_PER_HOUR = 5;
const INVITATION_LIFETIME = "7 days";

export interface IssuedChallenge {
  challengeId: string;
  otp: string;
}

/**
 * Replaces the invitation's challenge with a new code, after the resend
 * cooldown and hourly send limit. The caller holds the invitation lock.
 */
async function issueChallenge(
  client: PoolClient,
  invitationId: string,
  email: string,
): Promise<IssuedChallenge> {
  const previous = await client.query<{
    cooldown: boolean;
    windowActive: boolean;
    sendCount: number;
  }>(
    `
    SELECT
      last_requested_at > clock_timestamp() - interval '60 seconds'
        AS cooldown,
      send_window_started_at > clock_timestamp() - interval '1 hour'
        AS "windowActive",
      send_count AS "sendCount"
    FROM secretary_email_verifications
    WHERE invitation_id = $1
    FOR UPDATE
    `,
    [invitationId],
  );

  const prior = previous.rows[0];

  if (prior?.cooldown) {
    throw new InvitationError(
      429,
      "OTP_RESEND_COOLDOWN",
      "Please wait 60 seconds between verification requests.",
    );
  }

  if (prior?.windowActive && prior.sendCount >= MAX_SENDS_PER_HOUR) {
    throw new InvitationError(
      429,
      "OTP_SEND_LIMIT",
      "The hourly verification email limit has been reached. Try again later.",
    );
  }

  const challengeId = randomUUID();
  const otp = generateEmailOtp();
  const otpHash = hashEmailOtp({ invitationId, challengeId, email }, otp);

  await client.query(
    `
    INSERT INTO secretary_email_verifications (
      invitation_id,
      challenge_id,
      email,
      otp_hash,
      expires_at,
      last_requested_at,
      send_window_started_at
    )
    VALUES (
      $1, $2, $3, $4,
      clock_timestamp() + interval '10 minutes',
      clock_timestamp(),
      clock_timestamp()
    )
    ON CONFLICT (invitation_id) DO UPDATE
    SET
      challenge_id = EXCLUDED.challenge_id,
      email = EXCLUDED.email,
      otp_hash = EXCLUDED.otp_hash,
      attempts = 0,
      expires_at = EXCLUDED.expires_at,
      last_requested_at = EXCLUDED.last_requested_at,
      send_window_started_at = CASE
        WHEN $5::boolean
          THEN secretary_email_verifications.send_window_started_at
        ELSE EXCLUDED.send_window_started_at
      END,
      send_count = CASE
        WHEN $5::boolean
          THEN secretary_email_verifications.send_count + 1
        ELSE 1
      END,
      delivery_status = 'pending',
      consumed_at = NULL,
      updated_at = now()
    `,
    [invitationId, challengeId, email, otpHash, prior?.windowActive ?? false],
  );

  return { challengeId, otp };
}

// Internal results: they carry the plaintext link token and OTP for the
// email service. Never return them from an API or log them.

export interface PreparedInvitationEmail {
  invitationId: string;
  email: string;
  token: string;
  /** null when the address is already verified: the email has only the link. */
  challenge: IssuedChallenge | null;
}

/**
 * Admin action: issues a new invitation link (replacing any earlier one) and,
 * unless the address is verified, a new code. Moves pending_setup → pending.
 */
export async function prepareInvitationEmail(
  invitationId: string,
  requestedBy: string,
): Promise<PreparedInvitationEmail> {
  return withTransaction(async (client) => {
    await assertPlatformAdmin(client, requestedBy);

    const invitation = await lockInvitation(client, { id: invitationId });

    if (!invitation) {
      throw new InvitationError(
        404,
        "INVITATION_NOT_FOUND",
        "Secretary invitation not found.",
      );
    }

    if (invitation.tenantStatus !== "active") {
      throw new InvitationError(
        409,
        "TENANT_NOT_ACTIVE",
        "The organization must finish provisioning before its invitation can be sent.",
      );
    }

    if (!["pending_setup", "pending"].includes(invitation.status)) {
      throw new InvitationError(
        409,
        "INVITATION_NOT_AVAILABLE",
        "This invitation has already been accepted, revoked or expired.",
      );
    }

    const challenge =
      invitation.verifiedAt === null
        ? await issueChallenge(client, invitation.id, invitation.email)
        : null;

    const token = generateInvitationToken();

    await client.query(
      `
      UPDATE tenant_invitations
      SET
        token_hash = $2,
        expires_at = clock_timestamp() + interval '${INVITATION_LIFETIME}',
        status = 'pending',
        updated_at = now()
      WHERE id = $1
      `,
      [invitation.id, hashInvitationToken(token)],
    );

    return {
      invitationId: invitation.id,
      email: invitation.email,
      token,
      challenge,
    };
  });
}

export interface PreparedRecipientCode extends IssuedChallenge {
  invitationId: string;
  email: string;
}

/** Recipient action: a new code for the invitation behind this link. */
export async function prepareRecipientCode(
  tokenHash: string,
): Promise<PreparedRecipientCode> {
  return withTransaction(async (client) => {
    const invitation = await lockInvitation(client, { tokenHash });
    assertUsableLink(invitation);

    if (invitation.verifiedAt !== null) {
      throw new InvitationError(
        409,
        "EMAIL_ALREADY_VERIFIED",
        "Your email address is already verified.",
      );
    }

    const challenge = await issueChallenge(client, invitation.id, invitation.email);

    return { invitationId: invitation.id, email: invitation.email, ...challenge };
  });
}

/**
 * Records whether SMTP accepted the challenge's email. Only the pending,
 * current challenge is updated; false means it was replaced or consumed.
 */
export async function recordEmailOtpDelivery(
  invitationId: string,
  challengeId: string,
  status: "sent" | "failed",
): Promise<boolean> {
  const result = await pool.query(
    `
    UPDATE secretary_email_verifications
    SET
      delivery_status = $3,
      updated_at = now()
    WHERE invitation_id = $1
      AND challenge_id = $2
      AND delivery_status = 'pending'
      AND consumed_at IS NULL
    `,
    [invitationId, challengeId, status],
  );

  return result.rowCount === 1;
}

export interface EmailOtpVerificationResult {
  invitationId: string;
  verifiedAt: Date;
}

/**
 * Recipient action: checks the code against the latest challenge of the
 * invitation behind this link. A wrong code's attempt is committed before
 * the rejection is thrown, so it can't be rolled back by the error.
 */
export async function verifyEmailOtp(
  tokenHash: string,
  expectedChallengeId: string | null,
  otp: string,
): Promise<EmailOtpVerificationResult> {
  let rejection: InvitationError | undefined;

  const result = await withTransaction(async (client) => {
    const invitation = await lockInvitation(client, { tokenHash });
    assertUsableLink(invitation);

    if (invitation.verifiedAt !== null) {
      throw new InvitationError(
        409,
        "EMAIL_ALREADY_VERIFIED",
        "Your email address is already verified.",
      );
    }

    const challenges = await client.query<{
      challengeId: string;
      email: string;
      otpHash: string;
      attempts: number;
      expired: boolean;
      consumedAt: Date | null;
    }>(
      `
      SELECT
        challenge_id AS "challengeId",
        email,
        otp_hash AS "otpHash",
        attempts,
        expires_at <= clock_timestamp() AS expired,
        consumed_at AS "consumedAt"
      FROM secretary_email_verifications
      WHERE invitation_id = $1
      FOR UPDATE
      `,
      [invitation.id],
    );

    const challenge = challenges.rows[0];

    if (!challenge) {
      throw new InvitationError(
        404,
        "OTP_NOT_REQUESTED",
        "No verification code has been sent yet. Request a code.",
      );
    }

    // A resend or an email change replaces the challenge.
    if (
      (expectedChallengeId !== null &&
        challenge.challengeId !== expectedChallengeId.toLowerCase()) ||
      challenge.email !== invitation.email
    ) {
      throw new InvitationError(
        409,
        "OTP_CHALLENGE_CHANGED",
        "A newer code has been sent. Use the code from the most recent email.",
      );
    }

    if (challenge.consumedAt !== null) {
      throw new InvitationError(
        409,
        "OTP_ALREADY_USED",
        "This verification code has already been used.",
      );
    }

    if (challenge.expired) {
      throw new InvitationError(
        410,
        "OTP_EXPIRED",
        "This verification code has expired. Request a new code.",
      );
    }

    if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
      throw new InvitationError(
        429,
        "OTP_ATTEMPTS_EXCEEDED",
        "Too many incorrect codes. Request a new code.",
      );
    }

    const matches = matchesEmailOtp(
      {
        invitationId: invitation.id,
        challengeId: challenge.challengeId,
        email: challenge.email,
      },
      otp,
      challenge.otpHash,
    );

    if (!matches) {
      await client.query(
        `
        UPDATE secretary_email_verifications
        SET
          attempts = attempts + 1,
          updated_at = now()
        WHERE invitation_id = $1
        `,
        [invitation.id],
      );

      const remaining = MAX_OTP_ATTEMPTS - challenge.attempts - 1;

      rejection =
        remaining > 0
          ? new InvitationError(
              400,
              "OTP_INVALID",
              `That code is incorrect. ${remaining} attempt${remaining === 1 ? "" : "s"} left.`,
            )
          : new InvitationError(
              429,
              "OTP_ATTEMPTS_EXCEEDED",
              "Too many incorrect codes. Request a new code.",
            );

      return null;
    }

    await client.query(
      `
      UPDATE secretary_email_verifications
      SET
        consumed_at = now(),
        updated_at = now()
      WHERE invitation_id = $1
      `,
      [invitation.id],
    );

    const verified = await client.query<{ verifiedAt: Date }>(
      `
      UPDATE tenant_invitations
      SET
        email_verified_at = now(),
        verified_email = email,
        updated_at = now()
      WHERE id = $1
        AND email = $2
      RETURNING email_verified_at AS "verifiedAt"
      `,
      [invitation.id, challenge.email],
    );

    if (verified.rowCount !== 1) {
      throw new Error("Invitation email changed during verification.");
    }

    return {
      invitationId: invitation.id,
      verifiedAt: verified.rows[0]!.verifiedAt,
    };
  });

  if (rejection) {
    throw rejection;
  }

  return result!;
}

/** What the invitation page may show. Deliberately minimal. */
export type InvitationContext =
  | {
      state: "open";
      organizationName: string;
      maskedEmail: string;
      emailVerified: boolean;
      code: {
        challengeId: string;
        expiresAt: string;
        attemptsRemaining: number;
        resendAvailableAt: string;
      } | null;
    }
  | { state: "expired"; organizationName: string }
  | { state: "accepted"; organizationName: string };

/** "secretary@company.com" → "se•••••••@company.com" */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at);
  const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
  return `${visible}${"•".repeat(Math.max(local.length - visible.length, 1))}${email.slice(at)}`;
}

export async function getInvitationContext(
  tokenHash: string,
): Promise<InvitationContext> {
  const result = await pool.query<{
    tenantName: string;
    tenantStatus: string;
    email: string;
    status: string;
    verified: boolean;
    linkExpired: boolean;
    challengeId: string | null;
    codeExpiresAt: Date | null;
    codeUsable: boolean;
    attempts: number | null;
    resendAvailableAt: Date | null;
  }>(
    `
    SELECT
      tenant.name AS "tenantName",
      tenant.status AS "tenantStatus",
      invitation.email,
      invitation.status,
      invitation.email_verified_at IS NOT NULL AS verified,
      COALESCE(invitation.expires_at <= clock_timestamp(), FALSE) AS "linkExpired",
      challenge.challenge_id AS "challengeId",
      challenge.expires_at AS "codeExpiresAt",
      COALESCE(
        challenge.consumed_at IS NULL
          AND challenge.expires_at > clock_timestamp()
          AND challenge.email = invitation.email,
        FALSE
      ) AS "codeUsable",
      challenge.attempts,
      challenge.last_requested_at + interval '60 seconds' AS "resendAvailableAt"
    FROM tenant_invitations AS invitation
    JOIN tenants AS tenant ON tenant.id = invitation.tenant_id
    LEFT JOIN secretary_email_verifications AS challenge
      ON challenge.invitation_id = invitation.id
    WHERE invitation.token_hash = $1
      AND invitation.role = 'secretary'
    `,
    [tokenHash],
  );

  const row = result.rows[0];

  if (!row || row.tenantStatus !== "active") {
    throw invalidLinkError();
  }

  if (row.status === "accepted") {
    return { state: "accepted", organizationName: row.tenantName };
  }

  if (row.status !== "pending") {
    throw invalidLinkError();
  }

  if (row.linkExpired) {
    return { state: "expired", organizationName: row.tenantName };
  }

  return {
    state: "open",
    organizationName: row.tenantName,
    maskedEmail: maskEmail(row.email),
    emailVerified: row.verified,
    code:
      !row.verified && row.codeUsable && row.challengeId
        ? {
            challengeId: row.challengeId,
            expiresAt: row.codeExpiresAt!.toISOString(),
            attemptsRemaining: Math.max(MAX_OTP_ATTEMPTS - (row.attempts ?? 0), 0),
            resendAvailableAt: row.resendAvailableAt!.toISOString(),
          }
        : null,
  };
}
