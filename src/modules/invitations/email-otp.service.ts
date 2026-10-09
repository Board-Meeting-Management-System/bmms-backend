import { sendSecretaryVerificationOtp } from "../email/email.service.js";
import {
  EmailOtpError,
  prepareSecretaryEmailOtp,
  recordEmailOtpDelivery,
  verifySecretaryEmailOtp,
} from "./email-otp.repository.js";

export interface EmailOtpRequestResult {
  challengeId: string;
  message: string;
}

export async function requestSecretaryEmailOtp(
  invitationId: string,
  requestedBy: string,
): Promise<EmailOtpRequestResult> {
  const prepared = await prepareSecretaryEmailOtp(
    invitationId,
    requestedBy,
  );

  try {
    await sendSecretaryVerificationOtp(
      prepared.email,
      prepared.otp,
    );
  } catch {
    try {
      await recordEmailOtpDelivery(
        prepared.invitationId,
        prepared.challengeId,
        "failed",
      );
    } catch {
      // Delivery outcome remains unknown.
      // Do not expose the original SMTP error or OTP.
    }

    throw new EmailOtpError(
      503,
      "OTP_DELIVERY_UNCONFIRMED",
      "Email delivery could not be confirmed. Please wait before requesting another code.",
    );
  }

  let recorded: boolean;

  try {
    recorded = await recordEmailOtpDelivery(
      prepared.invitationId,
      prepared.challengeId,
      "sent",
    );
  } catch {
    // SMTP accepted the message, but persistence failed.
    throw new EmailOtpError(
      503,
      "OTP_DELIVERY_STATUS_UNAVAILABLE",
      "The email was submitted, but its verification status could not be saved. Please wait before requesting another code.",
    );
  }

  if (!recorded) {
    throw new EmailOtpError(
      409,
      "OTP_CHALLENGE_CHANGED",
      "This verification request is no longer current. Use the latest request.",
    );
  }

  // Never return the OTP, its hash, or SMTP credentials.
  return {
    challengeId: prepared.challengeId,
    message: "Verification email submitted. Check the inbox and spam folder.",
  };
}
export interface EmailOtpConfirmResult {
  verified: true;
  email: string;
  verifiedAt: string;
}

export async function confirmSecretaryEmailOtp(
  invitationId: string,
  challengeId: string,
  otp: string,
  verifiedBy: string,
): Promise<EmailOtpConfirmResult> {
  const result = await verifySecretaryEmailOtp(
    invitationId,
    challengeId,
    otp,
    verifiedBy,
  );

  return {
    verified: true,
    email: result.email,
    verifiedAt: result.verifiedAt.toISOString(),
  };
}
