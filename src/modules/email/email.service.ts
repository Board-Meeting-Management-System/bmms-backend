import nodemailer from "nodemailer";

function required(name: string): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return value;
}

function createEmailTransport() {
  const host = required("SMTP_HOST");
  const port = Number(required("SMTP_PORT"));
  const secureValue = required("SMTP_SECURE");

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("SMTP_PORT is invalid.");
  }

  if (!["true", "false"].includes(secureValue)) {
    throw new Error("SMTP_SECURE must be true or false.");
  }

  const secure = secureValue === "true";

  return nodemailer.createTransport({
    host,
    port,
    secure,

    // Require STARTTLS when not using implicit TLS.
    requireTLS: !secure,

    auth: {
      user: required("SMTP_USER"),
      pass: required("SMTP_PASSWORD"),
    },

    tls: {
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
    },

    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,

    disableFileAccess: true,
    disableUrlAccess: true,
    logger: false,
    debug: false,
  });
}

export async function verifyEmailConnection(): Promise<void> {
  const transport = createEmailTransport();

  try {
    await transport.verify();
  } finally {
    transport.close();
  }
}

// EMAIL_DELIVERY=capture keeps messages in memory instead of sending them.
// For automated tests only; refused in production.
export interface CapturedEmail {
  to: string;
  subject: string;
  text: string;
}

const capturedEmails: CapturedEmail[] = [];

function captureMode(): boolean {
  const mode = process.env.EMAIL_DELIVERY?.trim() || "smtp";

  if (mode !== "smtp" && mode !== "capture") {
    throw new Error("EMAIL_DELIVERY must be smtp or capture.");
  }

  if (mode === "capture" && process.env.NODE_ENV === "production") {
    throw new Error("EMAIL_DELIVERY=capture is not allowed in production.");
  }

  return mode === "capture";
}

/** Messages "sent" in capture mode, oldest first. Tests only. */
export function takeCapturedEmails(): CapturedEmail[] {
  return capturedEmails.splice(0, capturedEmails.length);
}

async function deliver(email: string, subject: string, text: string) {
  // Accept one plain email address, not a recipient list.
  if (
    email.length > 254 ||
    !/^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/.test(email)
  ) {
    throw new Error("Invalid recipient email.");
  }

  if (captureMode()) {
    capturedEmails.push({ to: email, subject, text });
    return;
  }

  const transport = createEmailTransport();

  try {
    const result = await transport.sendMail({
      from: required("MAIL_FROM"),
      to: {
        name: "",
        address: email,
      },
      subject,
      text,
    });

    if (result.accepted.length !== 1 || result.rejected.length !== 0) {
      throw new Error("SMTP server did not accept the email.");
    }
  } finally {
    transport.close();
  }
}

function assertOtp(otp: string) {
  if (!/^\d{6}$/.test(otp)) {
    throw new Error("Invalid verification code.");
  }
}

/**
 * The secretary's invitation: a link to the verification page and, unless
 * the address is already verified, the code to enter there.
 */
export async function sendSecretaryInvitation(
  email: string,
  invitationUrl: string,
  otp: string | null,
): Promise<void> {
  if (otp !== null) assertOtp(otp);

  const lines = [
    "You have been invited to set up your organization on BMMS as its company secretary.",
    "",
    "Open this link to continue:",
    invitationUrl,
    "",
  ];

  if (otp !== null) {
    lines.push(
      `Then enter this verification code on that page: ${otp}`,
      "",
      "The code expires in 10 minutes. You can request a new one from the page.",
      "",
    );
  }

  lines.push(
    "Never share this link or code with anyone, including BMMS staff.",
    "If you did not expect this invitation, ignore this email.",
  );

  await deliver(email, "BMMS — Your organization invitation", lines.join("\n"));
}

/** A new code requested from the verification page; no link. */
export async function sendSecretaryVerificationOtp(
  email: string,
  otp: string,
): Promise<void> {
  assertOtp(otp);

  await deliver(
    email,
    "BMMS — Your new verification code",
    [
      `Your new BMMS verification code is: ${otp}`,
      "",
      "Enter it on the invitation page you requested it from. It expires in 10 minutes,",
      "and any earlier code no longer works.",
      "",
      "Never share this code with anyone, including BMMS staff.",
      "If you did not request it, ignore this email.",
    ].join("\n"),
  );
}
