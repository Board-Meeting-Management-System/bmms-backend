import { verifyEmailConnection } from "../modules/email/email.service.js";

try {
  await verifyEmailConnection();
  console.log("SMTP connection and authentication successful.");
} catch (error) {
  const code =
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string"
      ? error.code
      : "UNKNOWN";

  // Avoid logging credentials or the full SMTP response.
  console.error("SMTP verification failed. Code:", code);
  process.exitCode = 1;
}