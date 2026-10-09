// Integration tests for
//   POST /admin/invitations/:invitationId/email-verification
//   POST /admin/invitations/:invitationId/email-verification/confirm
// against a running API, real database and real SMTP server.
//
// Requires:
//   - the API running (npm run dev)
//   - BMMS_SESSION: the bmms_session cookie of a platform admin
//     (sign in at /auth/login, copy it from browser DevTools)
//   - optional OTP_TEST_EMAIL: an inbox you control; three verification
//     emails are sent to it per run. Without it, the sending tests are
//     skipped. Confirmation tests seed codes directly and send no email.
//
// Run: BMMS_SESSION=... OTP_TEST_EMAIL=you@example.com npm run test:email-otp
//
// Each route allows 10 requests per minute, and this file makes exactly 10
// to each. Wait a minute between runs.
//
// Tenants and invitations created here use a per-run slug prefix and are
// deleted afterwards.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, describe, test } from "node:test";

import { pool } from "../src/db.js";
import { hashEmailOtp } from "../src/modules/invitations/email-otp.crypto.js";

const apiUrl = process.env.API_URL ?? "http://localhost:3001";
const origin = new URL(
  process.env.FRONTEND_ORIGIN ?? "http://localhost:5173",
).origin;
const adminSession = process.env.BMMS_SESSION?.trim();
const testEmail = process.env.OTP_TEST_EMAIL?.trim().toLowerCase();

// Unique per run, so reruns never collide with earlier data.
const prefix = `otp${Date.now().toString(36)}`;

let adminId: string;

async function requestOtp(
  invitationId: string,
  options: { session?: string | null } = {},
): Promise<{ status: number; headers: Headers; body: any }> {
  const headers: Record<string, string> = { Origin: origin };
  const session =
    options.session === undefined ? adminSession : options.session;

  if (session) headers["Cookie"] = `bmms_session=${session}`;

  const response = await fetch(
    `${apiUrl}/admin/invitations/${invitationId}/email-verification`,
    { method: "POST", headers },
  );

  return {
    status: response.status,
    headers: response.headers,
    body: await response.json().catch(() => null),
  };
}

async function confirmOtp(
  invitationId: string,
  body: unknown,
  options: { session?: string | null } = {},
): Promise<{ status: number; headers: Headers; body: any }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Origin: origin,
  };
  const session =
    options.session === undefined ? adminSession : options.session;

  if (session) headers["Cookie"] = `bmms_session=${session}`;

  const response = await fetch(
    `${apiUrl}/admin/invitations/${invitationId}/email-verification/confirm`,
    { method: "POST", headers, body: JSON.stringify(body) },
  );

  return {
    status: response.status,
    headers: response.headers,
    body: await response.json().catch(() => null),
  };
}

async function createInvitation(
  name: string,
  options: { tenantStatus?: string; email?: string } = {},
): Promise<string> {
  const tenant = await pool.query<{ id: string }>(
    `INSERT INTO tenants (name, slug, status, created_by)
     VALUES ($1, $2, $3, $4)
     RETURNING id`,
    [
      "OTP Test Organization",
      `${prefix}-${name}`,
      options.tenantStatus ?? "active",
      adminId,
    ],
  );

  const invitation = await pool.query<{ id: string }>(
    `INSERT INTO tenant_invitations (tenant_id, email, invited_by)
     VALUES ($1, $2, $3)
     RETURNING id`,
    [
      tenant.rows[0]!.id,
      options.email ?? testEmail ?? `${name}@example.com`,
      adminId,
    ],
  );

  return invitation.rows[0]!.id;
}

async function getChallenge(invitationId: string) {
  const result = await pool.query(
    `SELECT
       challenge_id AS "challengeId",
       email,
       otp_hash AS "otpHash",
       attempts,
       send_count AS "sendCount",
       delivery_status AS "deliveryStatus",
       consumed_at AS "consumedAt",
       expires_at - last_requested_at AS "lifetime"
     FROM secretary_email_verifications
     WHERE invitation_id = $1`,
    [invitationId],
  );

  return result.rows[0];
}

// Stores a challenge for a known code, as if it had been emailed.
// Uses the same EMAIL_OTP_HMAC_KEY as the API (both read .env).
async function seedChallenge(
  invitationId: string,
  code: string,
  options: { expired?: boolean; attempts?: number } = {},
): Promise<string> {
  const challengeId = randomUUID();
  const invitation = await pool.query<{ email: string }>(
    `SELECT email FROM tenant_invitations WHERE id = $1`,
    [invitationId],
  );
  const email = invitation.rows[0]!.email;
  const age = options.expired ? "11 minutes" : "0 seconds";

  await pool.query(
    `INSERT INTO secretary_email_verifications (
       invitation_id, challenge_id, email, otp_hash, attempts,
       expires_at, last_requested_at, send_window_started_at,
       delivery_status
     )
     VALUES (
       $1, $2, $3, $4, $5,
       now() - $6::interval + interval '10 minutes',
       now() - $6::interval,
       now() - $6::interval,
       'sent'
     )`,
    [
      invitationId,
      challengeId,
      email,
      hashEmailOtp({ invitationId, challengeId, email }, code),
      options.attempts ?? 0,
      age,
    ],
  );

  return challengeId;
}

// Simulates the passage of time instead of sleeping through cooldowns.
async function backdate(
  invitationId: string,
  fields: { lastRequested?: string; windowStarted?: string; sendCount?: number },
) {
  await pool.query(
    `UPDATE secretary_email_verifications
     SET
       last_requested_at = COALESCE(
         now() - $2::interval, last_requested_at),
       send_window_started_at = COALESCE(
         now() - $3::interval, send_window_started_at),
       send_count = COALESCE($4, send_count)
     WHERE invitation_id = $1`,
    [
      invitationId,
      fields.lastRequested ?? null,
      fields.windowStarted ?? null,
      fields.sendCount ?? null,
    ],
  );
}

before(async () => {
  assert.ok(
    adminSession,
    "Set BMMS_SESSION to a platform admin's bmms_session cookie",
  );

  const response = await fetch(`${apiUrl}/auth/me`, {
    headers: { Cookie: `bmms_session=${adminSession}` },
  }).catch(() => {
    throw new Error(`API is not reachable at ${apiUrl}. Start it with npm run dev.`);
  });

  assert.equal(
    response.status,
    200,
    "BMMS_SESSION is not a valid session. Sign in again and copy a fresh cookie.",
  );

  const { user } = (await response.json()) as {
    user: { id: string; isPlatformAdmin: boolean };
  };

  assert.ok(user.isPlatformAdmin, "BMMS_SESSION must belong to a platform admin");
  adminId = user.id;
});

after(async () => {
  // Delete in foreign-key order.
  const tenants = `SELECT id FROM tenants WHERE slug LIKE $1`;
  const pattern = [`${prefix}%`];

  await pool.query(
    `DELETE FROM secretary_email_verifications
     WHERE invitation_id IN (
       SELECT id FROM tenant_invitations WHERE tenant_id IN (${tenants}))`,
    pattern,
  );
  await pool.query(`DELETE FROM tenant_invitations WHERE tenant_id IN (${tenants})`, pattern);
  await pool.query(`DELETE FROM tenants WHERE slug LIKE $1`, pattern);

  await pool.end();
});

describe("rejected requests", () => {
  test("requires a session", async () => {
    const response = await requestOtp(randomUUID(), { session: null });

    assert.equal(response.status, 401);
  });

  test("rejects a malformed invitation id", async () => {
    const response = await requestOtp("not-a-uuid");

    assert.equal(response.status, 400);
  });

  test("returns 404 for an unknown invitation", async () => {
    const response = await requestOtp(randomUUID());

    assert.equal(response.status, 404);
    assert.equal(response.body.error, "INVITATION_NOT_FOUND");
  });

  test("refuses invitations of tenants that are not active", async () => {
    const invitationId = await createInvitation("provisioning", {
      tenantStatus: "provisioning",
      email: `${prefix}-provisioning@example.com`,
    });

    const response = await requestOtp(invitationId);

    assert.equal(response.status, 409);
    assert.equal(response.body.error, "INVITATION_NOT_AVAILABLE");
    assert.equal(await getChallenge(invitationId), undefined);
  });

  test("refuses invitations whose email is already verified", async () => {
    const email = `${prefix}-verified@example.com`;
    const invitationId = await createInvitation("verified", { email });

    await pool.query(
      `UPDATE tenant_invitations
       SET email_verified_at = now(), verified_email = $2
       WHERE id = $1`,
      [invitationId, email],
    );

    const response = await requestOtp(invitationId);

    assert.equal(response.status, 409);
    assert.equal(response.body.error, "EMAIL_ALREADY_VERIFIED");
  });
});

const sendingSkipped = !testEmail && "set OTP_TEST_EMAIL to run the email sending tests";

describe("sending and resending a code", { skip: sendingSkipped }, () => {
  let invitationId: string;
  let first: { challengeId: string; otpHash: string };

  before(async () => {
    invitationId = await createInvitation("send");
  });

  test("sends the code and returns only the challenge id", async () => {
    const response = await requestOtp(invitationId);

    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.deepEqual(Object.keys(response.body).sort(), ["challengeId", "message"]);
    assert.match(response.body.challengeId, /^[0-9a-f-]{36}$/);
    assert.equal(response.headers.get("cache-control"), "no-store");

    const challenge = await getChallenge(invitationId);

    assert.equal(challenge.challengeId, response.body.challengeId);
    assert.equal(challenge.email, testEmail);
    assert.match(challenge.otpHash, /^[0-9a-f]{64}$/);
    assert.equal(challenge.deliveryStatus, "sent");
    assert.equal(challenge.attempts, 0);
    assert.equal(challenge.sendCount, 1);
    assert.equal(challenge.consumedAt, null);
    assert.deepEqual({ ...challenge.lifetime }, { minutes: 10 });

    first = challenge;
  });

  test("enforces the 60 second resend cooldown", async () => {
    const response = await requestOtp(invitationId);

    assert.equal(response.status, 429);
    assert.equal(response.body.error, "OTP_RESEND_COOLDOWN");

    // The existing challenge is untouched.
    const challenge = await getChallenge(invitationId);
    assert.equal(challenge.challengeId, first.challengeId);
  });

  test("replaces the challenge after the cooldown", async () => {
    await backdate(invitationId, { lastRequested: "61 seconds" });

    const response = await requestOtp(invitationId);

    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.notEqual(response.body.challengeId, first.challengeId);

    const challenge = await getChallenge(invitationId);

    assert.equal(challenge.challengeId, response.body.challengeId);
    assert.notEqual(challenge.otpHash, first.otpHash);
    assert.equal(challenge.sendCount, 2);
    assert.equal(challenge.deliveryStatus, "sent");
  });

  test("stops at five sends per hour", async () => {
    await backdate(invitationId, {
      lastRequested: "61 seconds",
      windowStarted: "30 minutes",
      sendCount: 5,
    });

    const response = await requestOtp(invitationId);

    assert.equal(response.status, 429);
    assert.equal(response.body.error, "OTP_SEND_LIMIT");
    assert.equal((await getChallenge(invitationId)).sendCount, 5);
  });

  test("resets the send count once the hour has passed", async () => {
    await backdate(invitationId, {
      lastRequested: "61 seconds",
      windowStarted: "61 minutes",
      sendCount: 5,
    });

    const response = await requestOtp(invitationId);

    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.equal((await getChallenge(invitationId)).sendCount, 1);
  });
});

describe("confirming a code", () => {
  const code = "246810";

  test("requires a session", async () => {
    const response = await confirmOtp(
      randomUUID(),
      { challengeId: randomUUID(), code },
      { session: null },
    );

    assert.equal(response.status, 401);
  });

  test("rejects a malformed code", async () => {
    const response = await confirmOtp(randomUUID(), {
      challengeId: randomUUID(),
      code: "12345",
    });

    assert.equal(response.status, 400);
  });

  test("returns 404 when no code was requested", async () => {
    const invitationId = await createInvitation("unrequested", {
      email: `${prefix}-unrequested@example.com`,
    });

    const response = await confirmOtp(invitationId, {
      challengeId: randomUUID(),
      code,
    });

    assert.equal(response.status, 404);
    assert.equal(response.body.error, "OTP_NOT_REQUESTED");
  });

  test("rejects a code from a replaced challenge", async () => {
    const invitationId = await createInvitation("stale", {
      email: `${prefix}-stale@example.com`,
    });
    await seedChallenge(invitationId, code);

    // The right code, but for a challenge that is no longer current.
    const response = await confirmOtp(invitationId, {
      challengeId: randomUUID(),
      code,
    });

    assert.equal(response.status, 409);
    assert.equal(response.body.error, "OTP_CHALLENGE_CHANGED");
  });

  test("rejects an expired code", async () => {
    const invitationId = await createInvitation("expired", {
      email: `${prefix}-expired@example.com`,
    });
    const challengeId = await seedChallenge(invitationId, code, {
      expired: true,
    });

    const response = await confirmOtp(invitationId, { challengeId, code });

    assert.equal(response.status, 410);
    assert.equal(response.body.error, "OTP_EXPIRED");
  });

  describe("attempt limit", () => {
    let invitationId: string;
    let challengeId: string;

    before(async () => {
      invitationId = await createInvitation("attempts", {
        email: `${prefix}-attempts@example.com`,
      });
      challengeId = await seedChallenge(invitationId, code);
    });

    test("counts an incorrect code", async () => {
      const response = await confirmOtp(invitationId, {
        challengeId,
        code: "000000",
      });

      assert.equal(response.status, 400);
      assert.equal(response.body.error, "OTP_INVALID");
      assert.match(response.body.message, /4 attempt\(s\) remaining/);
      assert.equal((await getChallenge(invitationId)).attempts, 1);
    });

    test("locks the challenge on the fifth incorrect code", async () => {
      await pool.query(
        `UPDATE secretary_email_verifications SET attempts = 4
         WHERE invitation_id = $1`,
        [invitationId],
      );

      const response = await confirmOtp(invitationId, {
        challengeId,
        code: "000000",
      });

      assert.equal(response.status, 429);
      assert.equal(response.body.error, "OTP_ATTEMPTS_EXCEEDED");
      assert.equal((await getChallenge(invitationId)).attempts, 5);
    });

    test("refuses even the correct code once locked", async () => {
      const response = await confirmOtp(invitationId, { challengeId, code });

      assert.equal(response.status, 429);
      assert.equal(response.body.error, "OTP_ATTEMPTS_EXCEEDED");

      const invitation = await pool.query(
        `SELECT email_verified_at FROM tenant_invitations WHERE id = $1`,
        [invitationId],
      );
      assert.equal(invitation.rows[0].email_verified_at, null);
    });
  });

  describe("successful verification", () => {
    const email = `${prefix}-confirm@example.com`;
    let invitationId: string;
    let challengeId: string;

    before(async () => {
      invitationId = await createInvitation("confirm", { email });
      challengeId = await seedChallenge(invitationId, code);
    });

    test("verifies the invitation email", async () => {
      const response = await confirmOtp(invitationId, { challengeId, code });

      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(response.body.verified, true);
      assert.equal(response.body.email, email);
      assert.ok(!Number.isNaN(Date.parse(response.body.verifiedAt)));
      assert.equal(response.headers.get("cache-control"), "no-store");

      const invitation = await pool.query(
        `SELECT email_verified_at, verified_email
         FROM tenant_invitations WHERE id = $1`,
        [invitationId],
      );
      assert.notEqual(invitation.rows[0].email_verified_at, null);
      assert.equal(invitation.rows[0].verified_email, email);

      assert.notEqual((await getChallenge(invitationId)).consumedAt, null);
    });

    test("cannot be repeated", async () => {
      const response = await confirmOtp(invitationId, { challengeId, code });

      assert.equal(response.status, 409);
      assert.equal(response.body.error, "EMAIL_ALREADY_VERIFIED");
    });
  });
});
