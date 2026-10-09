import { config } from "../../config.js";
import {
  sendSecretaryInvitation,
  sendSecretaryVerificationOtp,
} from "../email/email.service.js";
import {
  getInvitationContext,
  prepareInvitationEmail,
  prepareRecipientCode,
  recordEmailOtpDelivery,
  verifyEmailOtp,
  type InvitationContext,
} from "./email-otp.repository.js";
import { InvitationError, invalidLinkError } from "./invitation.db.js";
import { acceptInvitation } from "./invitation.repository.js";
import {
  hashInvitationToken,
  invitationUrl,
  isInvitationToken,
} from "./invitation-token.js";

// Nothing here returns or logs a link token, OTP, hash or SMTP detail.

function tokenHashOf(token: string): string {
  if (!isInvitationToken(token)) throw invalidLinkError();
  return hashInvitationToken(token);
}

/**
 * Records the delivery outcome of a challenge's email. SMTP failure and an
 * unrecordable outcome are reported as uncertain, never as "not sent": the
 * message may still arrive, and the cooldown has already started.
 */
async function deliverChallenge(
  invitationId: string,
  challengeId: string | null,
  send: () => Promise<void>,
): Promise<void> {
  try {
    await send();
  } catch {
    if (challengeId) {
      await recordEmailOtpDelivery(invitationId, challengeId, "failed").catch(() => {});
    }

    throw new InvitationError(
      503,
      "EMAIL_DELIVERY_UNCONFIRMED",
      "The email couldn't be confirmed as sent. Wait a minute before trying again.",
    );
  }

  if (!challengeId) return;

  let recorded: boolean;

  try {
    recorded = await recordEmailOtpDelivery(invitationId, challengeId, "sent");
  } catch {
    throw new InvitationError(
      503,
      "EMAIL_DELIVERY_STATUS_UNAVAILABLE",
      "The email was submitted, but its status couldn't be saved. Wait a minute before trying again.",
    );
  }

  if (!recorded) {
    throw new InvitationError(
      409,
      "OTP_CHALLENGE_CHANGED",
      "A newer code was requested in the meantime. Use the most recent email.",
    );
  }
}

export interface InvitationEmailResult {
  /** Whether the email included a code (false once the address is verified). */
  codeSent: boolean;
  message: string;
}

/** Admin: sends the secretary a fresh invitation link (and code). */
export async function sendInvitationEmail(
  invitationId: string,
  requestedBy: string,
): Promise<InvitationEmailResult> {
  const prepared = await prepareInvitationEmail(invitationId, requestedBy);

  await deliverChallenge(
    prepared.invitationId,
    prepared.challenge?.challengeId ?? null,
    () =>
      sendSecretaryInvitation(
        prepared.email,
        invitationUrl(config.frontendOrigin, prepared.token),
        prepared.challenge?.otp ?? null,
      ),
  );

  return {
    codeSent: prepared.challenge !== null,
    message: "Invitation email submitted. Earlier invitation links no longer work.",
  };
}

/** Recipient: what the invitation page shows. */
export function lookupInvitation(token: string): Promise<InvitationContext> {
  return getInvitationContext(tokenHashOf(token));
}

/** Recipient: a new code for the invitation behind this link. */
export async function resendRecipientCode(
  token: string,
): Promise<{ challengeId: string; message: string }> {
  const prepared = await prepareRecipientCode(tokenHashOf(token));

  await deliverChallenge(prepared.invitationId, prepared.challengeId, () =>
    sendSecretaryVerificationOtp(prepared.email, prepared.otp),
  );

  return {
    challengeId: prepared.challengeId,
    message: "A new code is on its way. Check your inbox and spam folder.",
  };
}

/** Recipient: verifies the invitation's email with the emailed code. */
export async function confirmRecipientCode(
  token: string,
  challengeId: string | null,
  code: string,
): Promise<{ verified: true; verifiedAt: string }> {
  const result = await verifyEmailOtp(tokenHashOf(token), challengeId, code);
  return { verified: true, verifiedAt: result.verifiedAt.toISOString() };
}

/** Signed-in recipient: accepts the invitation and becomes a member. */
export async function acceptInvitationByToken(
  token: string,
  identityId: string,
): Promise<{ accepted: true; organizationName: string; acceptedAt: string }> {
  const result = await acceptInvitation(tokenHashOf(token), identityId);
  return {
    accepted: true,
    organizationName: result.organizationName,
    acceptedAt: result.acceptedAt.toISOString(),
  };
}
