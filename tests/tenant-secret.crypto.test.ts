import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  encryptTenantSecret,
  decryptTenantSecret,
} from "../src/modules/provisioning/tenant-secret.crypto.js";

test("tenant secret encryption", async (t) => {
  const originalKey = process.env.TENANT_SECRETS_KEY_V1;

  process.env.TENANT_SECRETS_KEY_V1 =
    randomBytes(32).toString("base64");

  const tenantId = "9f7b8811-91a7-4299-bede-53d1c2b53bd0";
  const otherTenantId = "e9c102a8-d87d-49fc-a240-9ecc9e536874";

  const plaintext = JSON.stringify({
    username: "test_tenant_user",
    password: "test-only-password",
  });

  try {
    await t.test("decrypts the original credentials", () => {
      const encrypted = encryptTenantSecret(tenantId, plaintext);

      assert.equal(
        decryptTenantSecret(tenantId, encrypted),
        plaintext,
      );
    });

    await t.test("uses a fresh nonce for each encryption", () => {
      const first = encryptTenantSecret(tenantId, plaintext);
      const second = encryptTenantSecret(tenantId, plaintext);

      assert.notDeepEqual(first.nonce, second.nonce);
      assert.notDeepEqual(first.ciphertext, second.ciphertext);
    });

    await t.test("rejects a different tenant ID", () => {
      const encrypted = encryptTenantSecret(tenantId, plaintext);

      assert.throws(() => {
        decryptTenantSecret(otherTenantId, encrypted);
      });
    });

    await t.test("rejects modified ciphertext", () => {
      const encrypted = encryptTenantSecret(tenantId, plaintext);
      const modified = Buffer.from(encrypted.ciphertext);

      modified.writeUInt8(modified.readUInt8(0) ^ 1, 0);

      assert.throws(() => {
        decryptTenantSecret(tenantId, {
          ...encrypted,
          ciphertext: modified,
        });
      });
    });

    await t.test("rejects a modified authentication tag", () => {
      const encrypted = encryptTenantSecret(tenantId, plaintext);
      const modified = Buffer.from(encrypted.authTag);

      modified.writeUInt8(modified.readUInt8(0) ^ 1, 0);

      assert.throws(() => {
        decryptTenantSecret(tenantId, {
          ...encrypted,
          authTag: modified,
        });
      });
    });

    await t.test("rejects the wrong encryption key", () => {
      const encrypted = encryptTenantSecret(tenantId, plaintext);
      const correctKey = process.env.TENANT_SECRETS_KEY_V1!;

      try {
        process.env.TENANT_SECRETS_KEY_V1 =
          randomBytes(32).toString("base64");

        assert.throws(() => {
          decryptTenantSecret(tenantId, encrypted);
        });
      } finally {
        process.env.TENANT_SECRETS_KEY_V1 = correctKey;
      }
    });
  } finally {
    if (originalKey === undefined) {
      delete process.env.TENANT_SECRETS_KEY_V1;
    } else {
      process.env.TENANT_SECRETS_KEY_V1 = originalKey;
    }
  }
});