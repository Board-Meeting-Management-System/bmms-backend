import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

export interface EncryptedTenantSecret {
  keyVersion: number;
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
}

export function getEncryptionKey(version: number): Buffer {
  if (version !== 1) {
    throw new Error("Unsupported tenant secret key version.");
  }

  const value = process.env.TENANT_SECRETS_KEY_V1;

  if (!value) {
    throw new Error(
      "Missing environment variable: TENANT_SECRETS_KEY_V1",
    );
  }

  const key = Buffer.from(value, "base64");

  if (
    key.length !== 32 ||
    key.toString("base64") !== value
  ) {
    throw new Error(
      "TENANT_SECRETS_KEY_V1 must be a base64-encoded 32-byte key.",
    );
  }

  return key;
}

function authenticatedContext(
  tenantId: string,
  keyVersion: number,
): Buffer {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      tenantId,
    )
  ) {
    throw new Error("Invalid tenant ID.");
  }

  return Buffer.from(
    JSON.stringify([
      "bmms-tenant-secret",
      tenantId.toLowerCase(),
      "database_credentials",
      keyVersion,
    ]),
    "utf8",
  );
}

export function encryptTenantSecret(
  tenantId: string,
  plaintext: string,
): EncryptedTenantSecret {
  if (!plaintext || Buffer.byteLength(plaintext, "utf8") > 16_384) {
    throw new Error("Invalid tenant secret size.");
  }

  const keyVersion = 1;
  const key = getEncryptionKey(keyVersion);
  const nonce = randomBytes(12);

  const cipher = createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });

  cipher.setAAD(authenticatedContext(tenantId, keyVersion));

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  return {
    keyVersion,
    ciphertext,
    nonce,
    authTag: cipher.getAuthTag(),
  };
}

export function decryptTenantSecret(
  tenantId: string,
  secret: EncryptedTenantSecret,
): string {
  if (
    secret.nonce.length !== 12 ||
    secret.authTag.length !== 16 ||
    secret.ciphertext.length === 0 ||
    secret.ciphertext.length > 16_384
  ) {
    throw new Error("Invalid encrypted tenant secret.");
  }

  const key = getEncryptionKey(secret.keyVersion);

  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    secret.nonce,
    { authTagLength: 16 },
  );

  decipher.setAAD(
    authenticatedContext(tenantId, secret.keyVersion),
  );
  decipher.setAuthTag(secret.authTag);

  // Return plaintext only after final() verifies authenticity.
  const plaintext = Buffer.concat([
    decipher.update(secret.ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}