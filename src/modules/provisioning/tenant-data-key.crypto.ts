import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

import { getEncryptionKey } from "./tenant-secret.crypto.js";

export interface WrappedTenantDataKey {
  keyVersion: number;
  wrappingKeyVersion: number;
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
}

function authenticatedContext(
  tenantId: string,
  keyVersion: number,
  wrappingKeyVersion: number,
): Buffer {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      tenantId,
    )
  ) {
    throw new Error("Invalid tenant ID.");
  }

  if (
    !Number.isSafeInteger(keyVersion) ||
    keyVersion < 1 ||
    !Number.isSafeInteger(wrappingKeyVersion) ||
    wrappingKeyVersion < 1
  ) {
    throw new Error("Invalid encryption key version.");
  }

  return Buffer.from(
    JSON.stringify([
      "bmms-tenant-data-key",
      tenantId.toLowerCase(),
      "AES-256-GCM",
      keyVersion,
      wrappingKeyVersion,
    ]),
    "utf8",
  );
}

export function generateWrappedTenantDataKey(
  tenantId: string,
  keyVersion = 1,
): WrappedTenantDataKey {
  const wrappingKeyVersion = 1;
  const context = authenticatedContext(
    tenantId,
    keyVersion,
    wrappingKeyVersion,
  );

  const wrappingKey = getEncryptionKey(wrappingKeyVersion);
  const dataKey = randomBytes(32);

  try {
    const nonce = randomBytes(12);

    const cipher = createCipheriv(
      "aes-256-gcm",
      wrappingKey,
      nonce,
      { authTagLength: 16 },
    );

    cipher.setAAD(context);

    const ciphertext = Buffer.concat([
      cipher.update(dataKey),
      cipher.final(),
    ]);

    return {
      keyVersion,
      wrappingKeyVersion,
      ciphertext,
      nonce,
      authTag: cipher.getAuthTag(),
    };
  } finally {
    dataKey.fill(0);
    wrappingKey.fill(0);
  }
}

export function unwrapTenantDataKey(
  tenantId: string,
  wrapped: WrappedTenantDataKey,
): Buffer {
  if (
    wrapped.ciphertext.length !== 32 ||
    wrapped.nonce.length !== 12 ||
    wrapped.authTag.length !== 16
  ) {
    throw new Error("Invalid wrapped tenant data key.");
  }

  const context = authenticatedContext(
    tenantId,
    wrapped.keyVersion,
    wrapped.wrappingKeyVersion,
  );

  const wrappingKey = getEncryptionKey(
    wrapped.wrappingKeyVersion,
  );

  let partialPlaintext: Buffer | undefined;

  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      wrappingKey,
      wrapped.nonce,
      { authTagLength: 16 },
    );

    decipher.setAAD(context);
    decipher.setAuthTag(wrapped.authTag);

    partialPlaintext = decipher.update(wrapped.ciphertext);

    // final() must succeed before plaintext is returned.
    const finalPlaintext = decipher.final();

    return Buffer.concat([
      partialPlaintext,
      finalPlaintext,
    ]);
  } finally {
    partialPlaintext?.fill(0);
    wrappingKey.fill(0);
  }
}