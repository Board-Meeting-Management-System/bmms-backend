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

export async function sendSecretaryVerificationOtp(
  email: string,
  otp: string,
): Promise<void> {
  // Accept one plain email address, not a recipient list.
  if (
    email.length > 254 ||
    !/^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/.test(email)
  ) {
    throw new Error("Invalid recipient email.");
  }

  if (!/^\d{6}$/.test(otp)) {
    throw new Error("Invalid verification code.");
  }

  const transport = createEmailTransport();

  try {
    const result = await transport.sendMail({
      from: required("MAIL_FROM"),
      to: {
        name: "",
        address: email,
      },
      subject: "BMMS — Verify your secretary email",
      text: [
        "You have been invited to join an organization on BMMS.",
        "",
        `Your email verification code is: ${otp}`,
        "",
        "This code expires in 10 minutes.",
        "Give it only to the BMMS administrator setting up your organization.",
        "Do not share this code with anyone else.",
        "",
        "If you did not expect this invitation, ignore this email.",
      ].join("\n"),
    });

    if (result.accepted.length !== 1 || result.rejected.length !== 0) {
      throw new Error("SMTP server did not accept the verification email.");
    }
  } finally {
    transport.close();
  }
}