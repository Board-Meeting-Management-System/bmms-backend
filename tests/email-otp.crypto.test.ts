import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  generateEmailOtp,
  hashEmailOtp,
  matchesEmailOtp,
} from "../src/modules/invitations/email-otp.crypto.js";

test("email OTP hashing", async (t) => {
  const originalKey = process.env.EMAIL_OTP_HMAC_KEY;

  process.env.EMAIL_OTP_HMAC_KEY = randomBytes(32).toString("base64");

  const context = {
    invitationId: "9f7b8811-91a7-4299-bede-53d1c2b53bd0",
    challengeId: "e9c102a8-d87d-49fc-a240-9ecc9e536874",
    email: "secretary@example.com",
  };

  try {
    await t.test("generates six-digit codes", () => {
      for (let i = 0; i < 1_000; i++) {
        assert.match(generateEmailOtp(), /^\d{6}$/);
      }
    });

    await t.test("produces a 64-character hex hash", () => {
      assert.match(hashEmailOtp(context, "012345"), /^[0-9a-f]{64}$/);
    });

    await t.test("matches the original code", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(matchesEmailOtp(context, "123456", hash), true);
    });

    await t.test("rejects a different code", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(matchesEmailOtp(context, "123457", hash), false);
    });

    await t.test("binds the hash to the challenge", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(
        matchesEmailOtp(
          { ...context, challengeId: "0d6c3a52-6f43-4d1f-9b38-4b0c3f0a7e11" },
          "123456",
          hash,
        ),
        false,
      );
    });

    await t.test("binds the hash to the invitation", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(
        matchesEmailOtp(
          { ...context, invitationId: "0d6c3a52-6f43-4d1f-9b38-4b0c3f0a7e11" },
          "123456",
          hash,
        ),
        false,
      );
    });

    await t.test("binds the hash to the email address", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(
        matchesEmailOtp({ ...context, email: "other@example.com" }, "123456", hash),
        false,
      );
    });

    await t.test("normalizes email case and whitespace", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(
        matchesEmailOtp(
          { ...context, email: "  Secretary@Example.COM " },
          "123456",
          hash,
        ),
        true,
      );
    });

    await t.test("rejects malformed codes and hashes without throwing", () => {
      const hash = hashEmailOtp(context, "123456");

      assert.equal(matchesEmailOtp(context, "12345", hash), false);
      assert.equal(matchesEmailOtp(context, "1234567", hash), false);
      assert.equal(matchesEmailOtp(context, "12345a", hash), false);
      assert.equal(matchesEmailOtp(context, "123456", "not-a-hash"), false);
    });

    await t.test("refuses to hash malformed input", () => {
      assert.throws(() => hashEmailOtp(context, "12345"));
      assert.throws(() =>
        hashEmailOtp({ ...context, invitationId: "nope" }, "123456"),
      );
      assert.throws(() => hashEmailOtp({ ...context, email: "  " }, "123456"));
    });

    await t.test("depends on the HMAC key", () => {
      const hash = hashEmailOtp(context, "123456");

      process.env.EMAIL_OTP_HMAC_KEY = randomBytes(32).toString("base64");

      assert.equal(matchesEmailOtp(context, "123456", hash), false);
    });

    await t.test("rejects a missing or invalid key", () => {
      delete process.env.EMAIL_OTP_HMAC_KEY;
      assert.throws(() => hashEmailOtp(context, "123456"), /EMAIL_OTP_HMAC_KEY/);

      process.env.EMAIL_OTP_HMAC_KEY = randomBytes(16).toString("base64");
      assert.throws(() => hashEmailOtp(context, "123456"), /32-byte/);
    });
  } finally {
    if (originalKey === undefined) {
      delete process.env.EMAIL_OTP_HMAC_KEY;
    } else {
      process.env.EMAIL_OTP_HMAC_KEY = originalKey;
    }
  }
});
