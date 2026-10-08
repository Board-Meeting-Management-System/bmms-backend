import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

const encodedKey = process.env.SESSION_ENCRYPTION_KEY?.trim();

if (!encodedKey) {
  throw new Error("Missing SESSION_ENCRYPTION_KEY");
}

const key = Buffer.from(encodedKey, "base64");

if (
  key.length !== 32 ||
  key.toString("base64") !== encodedKey
) {
  throw new Error(
    "SESSION_ENCRYPTION_KEY must be a valid base64-encoded 32-byte key",
  );
}

const VERSION = "v1";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

// Bind the encrypted data to its session.
// Copying the encrypted bundle to a different session will fail.
function additionalData(sessionId: string): Buffer {
  if (!sessionId) {
    throw new Error("Session ID is required");
  }

  return Buffer.from(
    JSON.stringify(["bmms-session-tokens", VERSION, sessionId]),
    "utf8",
  );
}

export function encryptSessionTokens(
  plaintext: string,
  sessionId: string,
): string {
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: TAG_LENGTH,
  });

  cipher.setAAD(additionalData(sessionId));

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return [
    VERSION,
    iv.toString("base64url"),
    tag.toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

export function decryptSessionTokens(
  encrypted: string,
  sessionId: string,
): string {
  try {
    const parts = encrypted.split(".");
    const [version, ivValue, tagValue, ciphertextValue] = parts;

    if (
      parts.length !== 4 ||
      version !== VERSION ||
      !ivValue ||
      !tagValue ||
      !ciphertextValue
    ) {
      throw new Error("Invalid encrypted token format");
    }

    const iv = Buffer.from(ivValue, "base64url");
    const tag = Buffer.from(tagValue, "base64url");
    const ciphertext = Buffer.from(ciphertextValue, "base64url");

    if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) {
      throw new Error("Invalid encryption metadata");
    }

    const decipher = createDecipheriv("aes-256-gcm", key, iv, {
      authTagLength: TAG_LENGTH,
    });

    decipher.setAAD(additionalData(sessionId));
    decipher.setAuthTag(tag);

    // Return plaintext only after authentication succeeds.
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return plaintext.toString("utf8");
  } catch {
    throw new Error("Unable to decrypt session tokens");
  }
}