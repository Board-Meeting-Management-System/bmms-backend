import { randomUUID } from "node:crypto";

import { pool } from "../../db.js";
import {
  generateEmailOtp,
  hashEmailOtp,
  matchesEmailOtp,
} from "./email-otp.crypto.js";

// Must match the attempts CHECK in secretary_email_verifications.
const MAX_OTP_ATTEMPTS = 5;

export class EmailOtpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "EmailOtpError";
  }
}

export interface PreparedEmailOtp {
  invitationId: string;
  challengeId: string;
  email: string;
  otp: string;
}

export async function prepareSecretaryEmailOtp(
  invitationId: string,
  requestedBy: string,
): Promise<PreparedEmailOtp> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL statement_timeout = '5s'");

    // Authorization is checked again at the database boundary.
    const actor = await client.query(
      `
      SELECT id
      FROM identities
      WHERE id = $1
        AND status = 'active'
        AND is_platform_admin = TRUE
      FOR SHARE
      `,
      [requestedBy],
    );

    if (actor.rowCount !== 1) {
      throw new EmailOtpError(
        403,
        "FORBIDDEN",
        "Platform administrator access is required.",
      );
    }

    // Lock the invitation to serialize requests, including first issuance.
    const invitation = await client.query<{
      email: string;
      status: string;
      verifiedAt: Date | null;
      tenantStatus: string;
    }>(
      `
      SELECT
        invitation.email,
        invitation.status,
        invitation.email_verified_at AS "verifiedAt",
        tenant.status AS "tenantStatus"
      FROM tenant_invitations AS invitation
      JOIN tenants AS tenant ON tenant.id = invitation.tenant_id
      WHERE invitation.id = $1
        AND invitation.role = 'secretary'
      FOR UPDATE OF invitation
      FOR SHARE OF tenant
      `,
      [invitationId],
    );

    const row = invitation.rows[0];

    if (!row) {
      throw new EmailOtpError(
        404,
        "INVITATION_NOT_FOUND",
        "Secretary invitation not found.",
      );
    }

    if (
      row.tenantStatus !== "active" ||
      !["pending_setup", "pending"].includes(row.status)
    ) {
      throw new EmailOtpError(
        409,
        "INVITATION_NOT_AVAILABLE",
        "This invitation is not available for email verification.",
      );
    }

    if (row.verifiedAt !== null) {
      throw new EmailOtpError(
        409,
        "EMAIL_ALREADY_VERIFIED",
        "The invitation email is already verified.",
      );
    }

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
      throw new EmailOtpError(
        429,
        "OTP_RESEND_COOLDOWN",
        "Please wait 60 seconds between verification requests.",
      );
    }

    if (prior?.windowActive && prior.sendCount >= 5) {
      throw new EmailOtpError(
        429,
        "OTP_SEND_LIMIT",
        "The hourly verification email limit has been reached.",
      );
    }

    const challengeId = randomUUID();
    const otp = generateEmailOtp();

    const otpHash = hashEmailOtp(
      {
        invitationId,
        challengeId,
        email: row.email,
      },
      otp,
    );

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
      [
        invitationId,
        challengeId,
        row.email,
        otpHash,
        prior?.windowActive ?? false,
      ],
    );

    await client.query("COMMIT");

    // Internal use only: pass the OTP to the email service.
    // Never return this object directly from an API or log it.
    return {
      invitationId,
      challengeId,
      email: row.email,
      otp,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

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
  email: string;
  verifiedAt: Date;
}

export async function verifySecretaryEmailOtp(
  invitationId: string,
  challengeId: string,
  otp: string,
  verifiedBy: string,
): Promise<EmailOtpVerificationResult> {
  const client = await pool.connect();

  // Set when a wrong code is committed; thrown only after COMMIT
  // so the attempt counter is never rolled back.
  let rejection: EmailOtpError | undefined;
  let result: EmailOtpVerificationResult | undefined;

  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL statement_timeout = '5s'");

    // Authorization is checked again at the database boundary.
    const actor = await client.query(
      `
      SELECT id
      FROM identities
      WHERE id = $1
        AND status = 'active'
        AND is_platform_admin = TRUE
      FOR SHARE
      `,
      [verifiedBy],
    );

    if (actor.rowCount !== 1) {
      throw new EmailOtpError(
        403,
        "FORBIDDEN",
        "Platform administrator access is required.",
      );
    }

    // Same lock order as prepareSecretaryEmailOtp: invitation, then challenge.
    const invitation = await client.query<{
      email: string;
      status: string;
      verifiedAt: Date | null;
      tenantStatus: string;
    }>(
      `
      SELECT
        invitation.email,
        invitation.status,
        invitation.email_verified_at AS "verifiedAt",
        tenant.status AS "tenantStatus"
      FROM tenant_invitations AS invitation
      JOIN tenants AS tenant ON tenant.id = invitation.tenant_id
      WHERE invitation.id = $1
        AND invitation.role = 'secretary'
      FOR UPDATE OF invitation
      FOR SHARE OF tenant
      `,
      [invitationId],
    );

    const row = invitation.rows[0];

    if (!row) {
      throw new EmailOtpError(
        404,
        "INVITATION_NOT_FOUND",
        "Secretary invitation not found.",
      );
    }

    if (
      row.tenantStatus !== "active" ||
      !["pending_setup", "pending"].includes(row.status)
    ) {
      throw new EmailOtpError(
        409,
        "INVITATION_NOT_AVAILABLE",
        "This invitation is not available for email verification.",
      );
    }

    if (row.verifiedAt !== null) {
      throw new EmailOtpError(
        409,
        "EMAIL_ALREADY_VERIFIED",
        "The invitation email is already verified.",
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
      [invitationId],
    );

    const challenge = challenges.rows[0];

    if (!challenge) {
      throw new EmailOtpError(
        404,
        "OTP_NOT_REQUESTED",
        "No verification code has been requested for this invitation.",
      );
    }

    // A resend or an email change invalidates the previous code.
    if (
      challenge.challengeId !== challengeId.toLowerCase() ||
      challenge.email !== row.email
    ) {
      throw new EmailOtpError(
        409,
        "OTP_CHALLENGE_CHANGED",
        "This verification code is no longer current. Use the latest code.",
      );
    }

    if (challenge.consumedAt !== null) {
      throw new EmailOtpError(
        409,
        "OTP_ALREADY_USED",
        "This verification code has already been used.",
      );
    }

    if (challenge.expired) {
      throw new EmailOtpError(
        410,
        "OTP_EXPIRED",
        "This verification code has expired. Request a new code.",
      );
    }

    if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
      throw new EmailOtpError(
        429,
        "OTP_ATTEMPTS_EXCEEDED",
        "Too many incorrect codes. Request a new code.",
      );
    }

    const matches = matchesEmailOtp(
      {
        invitationId,
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
        [invitationId],
      );

      const remaining = MAX_OTP_ATTEMPTS - challenge.attempts - 1;

      rejection =
        remaining > 0
          ? new EmailOtpError(
              400,
              "OTP_INVALID",
              `The verification code is incorrect. ${remaining} attempt(s) remaining.`,
            )
          : new EmailOtpError(
              429,
              "OTP_ATTEMPTS_EXCEEDED",
              "Too many incorrect codes. Request a new code.",
            );
    } else {
      await client.query(
        `
        UPDATE secretary_email_verifications
        SET
          consumed_at = now(),
          updated_at = now()
        WHERE invitation_id = $1
        `,
        [invitationId],
      );

      const verified = await client.query<{ verifiedAt: Date }>(
        `
        UPDATE tenant_invitations
        SET
          email_verified_at = now(),
          verified_email = $2,
          updated_at = now()
        WHERE id = $1
        RETURNING email_verified_at AS "verifiedAt"
        `,
        [invitationId, challenge.email],
      );

      result = {
        invitationId,
        email: challenge.email,
        verifiedAt: verified.rows[0]!.verifiedAt,
      };
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  if (rejection) {
    throw rejection;
  }

  return result!;
}
