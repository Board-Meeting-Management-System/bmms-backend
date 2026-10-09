import {
  createHash,
  createHmac,
  pbkdf2,
  randomBytes,
} from "node:crypto";
import { promisify } from "node:util";

const deriveKey = promisify(pbkdf2);

export async function createPostgresPasswordVerifier(
  password: string,
): Promise<string> {
  // Only accept the random base64url passwords our repository generates.
  // This deliberately excludes arbitrary Unicode/user-entered passwords.
  if (!/^[A-Za-z0-9_-]{43}$/.test(password)) {
    throw new Error("Invalid generated database password.");
  }

  const iterations = 4096;
  const salt = randomBytes(16);

  const saltedPassword = await deriveKey(
    password,
    salt,
    iterations,
    32,
    "sha256",
  );

  try {
    const clientKey = createHmac("sha256", saltedPassword)
      .update("Client Key", "utf8")
      .digest();

    const storedKey = createHash("sha256")
      .update(clientKey)
      .digest();

    const serverKey = createHmac("sha256", saltedPassword)
      .update("Server Key", "utf8")
      .digest();

    clientKey.fill(0);

    return (
      `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}` +
      `$${storedKey.toString("base64")}:${serverKey.toString("base64")}`
    );
  } finally {
    saltedPassword.fill(0);
  }
}