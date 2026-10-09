import {
  createHmac,
  randomInt,
  timingSafeEqual,
} from "node:crypto";

export interface EmailOtpContext {
  invitationId: string;
  challengeId: string;
  email: string;
}

function getOtpKey(): Buffer {
  const value = process.env.EMAIL_OTP_HMAC_KEY;

  if (!value) {
    throw new Error(
      "Missing environment variable: EMAIL_OTP_HMAC_KEY",
    );
  }

  const key = Buffer.from(value, "base64");

  if (
    key.length !== 32 ||
    key.toString("base64") !== value
  ) {
    throw new Error(
      "EMAIL_OTP_HMAC_KEY must be a base64-encoded 32-byte key.",
    );
  }

  return key;
}

export function generateEmailOtp(): string {
  return randomInt(0, 1_000_000)
    .toString()
    .padStart(6, "0");
}

export function hashEmailOtp(
  context: EmailOtpContext,
  otp: string,
): string {
  if (!/^\d{6}$/.test(otp)) {
    throw new Error("OTP must contain exactly six digits.");
  }

  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  if (
    !uuidPattern.test(context.invitationId) ||
    !uuidPattern.test(context.challengeId)
  ) {
    throw new Error("Invalid OTP context.");
  }

  const email = context.email.trim().toLowerCase();

  if (!email || email.length > 254) {
    throw new Error("Invalid OTP email.");
  }

  const key = getOtpKey();

  try {
    return createHmac("sha256", key)
      .update(
        JSON.stringify([
          "bmms-secretary-email-verification-v1",
          context.invitationId.toLowerCase(),
          context.challengeId.toLowerCase(),
          email,
          otp,
        ]),
        "utf8",
      )
      .digest("hex");
  } finally {
    key.fill(0);
  }
}

export function matchesEmailOtp(
  context: EmailOtpContext,
  otp: string,
  storedHash: string,
): boolean {
  if (
    !/^\d{6}$/.test(otp) ||
    !/^[0-9a-f]{64}$/.test(storedHash)
  ) {
    return false;
  }

  const candidate = Buffer.from(
    hashEmailOtp(context, otp),
    "hex",
  );

  const expected = Buffer.from(storedHash, "hex");

  return timingSafeEqual(candidate, expected);
}