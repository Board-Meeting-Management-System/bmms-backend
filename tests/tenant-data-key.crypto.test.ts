import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  generateWrappedTenantDataKey,
  unwrapTenantDataKey,
} from "../src/modules/provisioning/tenant-data-key.crypto.js";

test("tenant data-key wrapping", async (t) => {
  const originalKey = process.env.TENANT_SECRETS_KEY_V1;

  process.env.TENANT_SECRETS_KEY_V1 =
    randomBytes(32).toString("base64");

  const tenantId = "9f7b8811-91a7-4299-bede-53d1c2b53bd0";
  const otherTenantId = "e9c102a8-d87d-49fc-a240-9ecc9e536874";

  try {
    await t.test("unwraps the same 32-byte key consistently", () => {
      const wrapped = generateWrappedTenantDataKey(tenantId);
      const first = unwrapTenantDataKey(tenantId, wrapped);

      try {
        const second = unwrapTenantDataKey(tenantId, wrapped);

        try {
          assert.equal(first.length, 32);
          assert.deepEqual(first, second);
        } finally {
          second.fill(0);
        }
      } finally {
        first.fill(0);
      }
    });

    await t.test("generates different data keys", () => {
      const first = unwrapTenantDataKey(
        tenantId,
        generateWrappedTenantDataKey(tenantId),
      );

      try {
        const second = unwrapTenantDataKey(
          tenantId,
          generateWrappedTenantDataKey(tenantId),
        );

        try {
          assert.notDeepEqual(first, second);
        } finally {
          second.fill(0);
        }
      } finally {
        first.fill(0);
      }
    });

    await t.test("rejects another tenant", () => {
      const wrapped = generateWrappedTenantDataKey(tenantId);

      assert.throws(() => {
        unwrapTenantDataKey(otherTenantId, wrapped);
      });
    });

    await t.test("rejects a changed data-key version", () => {
      const wrapped = generateWrappedTenantDataKey(tenantId);

      assert.throws(() => {
        unwrapTenantDataKey(tenantId, {
          ...wrapped,
          keyVersion: wrapped.keyVersion + 1,
        });
      });
    });

    await t.test("rejects modified ciphertext, nonce, and tag", () => {
      const wrapped = generateWrappedTenantDataKey(tenantId);

      for (const field of ["ciphertext", "nonce", "authTag"] as const) {
        const modified = Buffer.from(wrapped[field]);
        modified.writeUInt8(modified.readUInt8(0) ^ 1, 0);

        assert.throws(
          () => {
            unwrapTenantDataKey(tenantId, {
              ...wrapped,
              [field]: modified,
            });
          },
          `Tampering with ${field} must fail`,
        );
      }
    });

    await t.test("rejects the wrong wrapping key", () => {
      const wrapped = generateWrappedTenantDataKey(tenantId);
      const correctKey = process.env.TENANT_SECRETS_KEY_V1!;

      try {
        process.env.TENANT_SECRETS_KEY_V1 =
          randomBytes(32).toString("base64");

        assert.throws(() => {
          unwrapTenantDataKey(tenantId, wrapped);
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