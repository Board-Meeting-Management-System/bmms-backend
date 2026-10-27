import { pool } from "../../db.js";
import { sendInvitationEmail } from "./email-otp.service.js";
import { InvitationError } from "./invitation.db.js";

// The invitation delivery queue: one row per invitation, queued when its
// organization becomes ready. Processed by the worker, separately from
// provisioning — a delivery failure never re-runs infrastructure steps.

const MAX_ATTEMPTS = 5;

export interface ClaimedDelivery {
  invitationId: string;
  attempts: number;
}

/** Claims one due delivery (or one whose previous sender died). */
export async function claimDueDelivery(): Promise<ClaimedDelivery | null> {
  const result = await pool.query<ClaimedDelivery>(
    `
    UPDATE invitation_deliveries AS delivery
    SET
      status = 'sending',
      attempts = delivery.attempts + 1,
      lease_expires_at = now() + interval '2 minutes',
      updated_at = now()
    WHERE delivery.invitation_id = (
      SELECT invitation_id
      FROM invitation_deliveries
      WHERE attempts < $1
        AND (
          (status = 'queued' AND next_attempt_at <= now())
          OR (status = 'sending' AND lease_expires_at <= now())
        )
      ORDER BY next_attempt_at
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    RETURNING delivery.invitation_id AS "invitationId", delivery.attempts
    `,
    [MAX_ATTEMPTS],
  );
  return result.rows[0] ?? null;
}

async function finish(
  invitationId: string,
  status: "sent" | "skipped" | "failed" | "queued",
  errorCode: string | null,
  retryInSeconds = 0,
) {
  await pool.query(
    `
    UPDATE invitation_deliveries
    SET
      status = $2,
      last_error_code = $3,
      next_attempt_at = now() + ($4::integer * interval '1 second'),
      lease_expires_at = NULL,
      updated_at = now()
    WHERE invitation_id = $1 AND status = 'sending'
    `,
    [invitationId, status, errorCode, retryInSeconds],
  );
}

/** Sends one claimed invitation and records the outcome. */
export async function processDelivery(delivery: ClaimedDelivery): Promise<"sent" | "skipped" | "retry" | "failed"> {
  try {
    await sendInvitationEmail(delivery.invitationId, null);
    await finish(delivery.invitationId, "sent", null);
    return "sent";
  } catch (error) {
    const code = error instanceof InvitationError ? error.code : "INVITATION_DELIVERY_FAILED";

    // Already sent by an administrator, accepted, revoked or expired.
    if (code === "INVITATION_ALREADY_SENT" || code === "INVITATION_NOT_AVAILABLE" || code === "INVITATION_NOT_FOUND") {
      await finish(delivery.invitationId, "skipped", code);
      return "skipped";
    }

    if (delivery.attempts >= MAX_ATTEMPTS) {
      await finish(delivery.invitationId, "failed", code);
      return "failed";
    }

    // 1, 2, 4, 8 minutes. Cooldowns from a recent manual send also land here.
    await finish(delivery.invitationId, "queued", code, 60 * 2 ** (delivery.attempts - 1));
    return "retry";
  }
}

export async function deliveryStatus(invitationId: string) {
  const result = await pool.query<{
    status: string;
    attempts: number;
    lastErrorCode: string | null;
    updatedAt: Date;
  }>(
    `
    SELECT status, attempts, last_error_code AS "lastErrorCode", updated_at AS "updatedAt"
    FROM invitation_deliveries
    WHERE invitation_id = $1
    `,
    [invitationId],
  );
  return result.rows[0] ?? null;
}
