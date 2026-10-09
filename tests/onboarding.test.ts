// Secretary onboarding: invitation email, recipient OTP verification,
// acceptance and the admin onboarding view.
//
// Runs against a disposable database (tests/support/test-database.ts) with
// EMAIL_DELIVERY=capture: no email is sent and the development database is
// never modified. Needs only a reachable PostgreSQL server.
//
// Run: npm run test:onboarding

import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, before, beforeEach, describe, test } from "node:test";

import { createTestDatabase, type TestDatabase } from "./support/test-database.js";

let database: TestDatabase;

// Imported after the environment points at the test database.
let pool: typeof import("../src/db.js")["pool"];
let app: Awaited<ReturnType<typeof import("../src/app.js")["buildApp"]>>;
let emails: typeof import("../src/modules/email/email.service.js");
let service: typeof import("../src/modules/invitations/email-otp.service.js");
let invitations: typeof import("../src/modules/invitations/invitation.repository.js");
let tokens: typeof import("../src/modules/invitations/invitation-token.js");
let onboarding: typeof import("../src/modules/organizations/onboarding.repository.js");
let safeReturnPath: typeof import("../src/modules/auth/browser-auth.routes.js")["safeReturnPath"];

before(async () => {
  database = await createTestDatabase();

  process.env.CONTROL_DATABASE_URL = database.url;
  process.env.EMAIL_DELIVERY = "capture";
  process.env.EMAIL_OTP_HMAC_KEY = randomBytes(32).toString("base64");
  process.env.FRONTEND_ORIGIN = "http://localhost:3000";
  process.env.PLATFORM_BASE_DOMAIN ??= "bmms.test";
  process.env.OIDC_ISSUER ??= "http://localhost:8080/realms/bmms";
  process.env.OIDC_JWKS_URL ??= "http://localhost:8080/realms/bmms/protocol/openid-connect/certs";
  process.env.OIDC_CLIENT_ID ??= "bmms-backend";
  process.env.OIDC_AUDIENCE ??= "bmms-api";
  process.env.OIDC_REDIRECT_URI ??= "http://localhost:3001/auth/callback";
  process.env.OIDC_CLIENT_SECRET ??= "test-only";

  ({ pool } = await import("../src/db.js"));
  emails = await import("../src/modules/email/email.service.js");
  service = await import("../src/modules/invitations/email-otp.service.js");
  invitations = await import("../src/modules/invitations/invitation.repository.js");
  tokens = await import("../src/modules/invitations/invitation-token.js");
  onboarding = await import("../src/modules/organizations/onboarding.repository.js");
  ({ safeReturnPath } = await import("../src/modules/auth/browser-auth.routes.js"));
  app = await (await import("../src/app.js")).buildApp();
});

after(async () => {
  await app?.close(); // also ends the pool
  await database?.drop();
});

// ---- Fixtures --------------------------------------------------------------

async function createIdentity(options: { admin?: boolean; email?: string; emailVerified?: boolean } = {}) {
  const result = await pool.query<{ id: string }>(
    `
    INSERT INTO identities (issuer, subject, email, email_verified, is_platform_admin)
    VALUES ('test', $1, $2, $3, $4)
    RETURNING id
    `,
    [randomUUID(), options.email ?? null, options.emailVerified ?? false, options.admin ?? false],
  );
  return result.rows[0]!.id;
}

interface Organization {
  adminId: string;
  tenantId: string;
  invitationId: string;
  email: string;
}

async function createOrganization(tenantStatus = "active"): Promise<Organization> {
  const adminId = await createIdentity({ admin: true, email: "admin@bmms.test", emailVerified: true });
  const slug = `org-${randomBytes(4).toString("hex")}`;
  const email = `${slug}@example.com`;

  const tenant = await pool.query<{ id: string }>(
    `INSERT INTO tenants (name, slug, status, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
    [`Org ${slug}`, slug, tenantStatus, adminId],
  );
  const tenantId = tenant.rows[0]!.id;

  await pool.query(
    `INSERT INTO tenant_domains (tenant_id, hostname, domain_type) VALUES ($1, $2, 'platform')`,
    [tenantId, `${slug}.bmms.test`],
  );
  await pool.query(
    `
    INSERT INTO provisioning_jobs (tenant_id, idempotency_key, request_hash, requested_by, status)
    VALUES ($1, $2, 'test', $3, $4)
    `,
    [tenantId, randomUUID(), adminId, tenantStatus === "active" ? "succeeded" : "running"],
  );
  await pool.query(`INSERT INTO tenant_resources (tenant_id) VALUES ($1)`, [tenantId]);
  const invitation = await pool.query<{ id: string }>(
    `INSERT INTO tenant_invitations (tenant_id, email, invited_by) VALUES ($1, $2, $3) RETURNING id`,
    [tenantId, email, adminId],
  );

  return { adminId, tenantId, invitationId: invitation.rows[0]!.id, email };
}

/** Admin sends the invitation; returns the link token and code from the captured email. */
async function sendInvitation(org: Organization) {
  emails.takeCapturedEmails();
  const result = await service.sendInvitationEmail(org.invitationId, org.adminId);
  const [email] = emails.takeCapturedEmails();
  assert.ok(email, "an invitation email was captured");

  const token = /#token=([A-Za-z0-9_-]{43})/.exec(email.text)?.[1];
  const code = /code on that page: (\d{6})/.exec(email.text)?.[1] ?? null;
  assert.ok(token, "the email contains the invitation link");

  return { result, email, token, code };
}

/** Moves the cooldown into the past so another code can be requested. */
async function skipCooldown(invitationId: string) {
  await pool.query(
    `
    UPDATE secretary_email_verifications
    SET last_requested_at = last_requested_at - interval '2 minutes'
    WHERE invitation_id = $1
    `,
    [invitationId],
  );
}

function wrongCode(code: string) {
  return code === "000000" ? "000001" : "000000";
}

async function rejectsWith(promise: Promise<unknown>, code: string) {
  await assert.rejects(promise, (error: { code?: string }) => {
    assert.equal(error.code, code);
    return true;
  });
}

async function challengeRow(invitationId: string) {
  const result = await pool.query(
    `SELECT attempts, consumed_at, otp_hash FROM secretary_email_verifications WHERE invitation_id = $1`,
    [invitationId],
  );
  return result.rows[0];
}

beforeEach(() => emails.takeCapturedEmails());

// ---- Tests -----------------------------------------------------------------

describe("invitation email (admin)", () => {
  test("sends a link and a code, and returns neither", async () => {
    const org = await createOrganization();
    const { result, email, token, code } = await sendInvitation(org);

    assert.equal(email.to, org.email);
    assert.match(code ?? "", /^\d{6}$/);
    assert.ok(email.text.includes(`http://localhost:3000/invitation#token=${token}`));

    const body = JSON.stringify(result);
    assert.ok(!body.includes(token) && !body.includes(code!), "result carries no token or code");

    const stored = await pool.query(
      `SELECT status, token_hash, expires_at FROM tenant_invitations WHERE id = $1`,
      [org.invitationId],
    );
    assert.equal(stored.rows[0].status, "pending");
    assert.equal(stored.rows[0].token_hash, tokens.hashInvitationToken(token));

    const challenge = await challengeRow(org.invitationId);
    assert.match(challenge.otp_hash, /^[0-9a-f]{64}$/);
    assert.notEqual(challenge.otp_hash, code);
  });

  test("refuses organizations that haven't finished provisioning", async () => {
    const org = await createOrganization("provisioning");
    await rejectsWith(service.sendInvitationEmail(org.invitationId, org.adminId), "TENANT_NOT_ACTIVE");
  });

  test("requires a platform administrator", async () => {
    const org = await createOrganization();
    const other = await createIdentity();
    await rejectsWith(service.sendInvitationEmail(org.invitationId, other), "FORBIDDEN");
  });

  test("a new invitation email replaces the earlier link", async () => {
    const org = await createOrganization();
    const first = await sendInvitation(org);
    await skipCooldown(org.invitationId);
    const second = await sendInvitation(org);

    await rejectsWith(service.lookupInvitation(first.token), "INVITATION_LINK_INVALID");
    assert.equal((await service.lookupInvitation(second.token)).state, "open");
  });

  test("records an SMTP failure as an unconfirmed delivery", async () => {
    const org = await createOrganization();
    const saved = { delivery: process.env.EMAIL_DELIVERY, host: process.env.SMTP_HOST };
    process.env.EMAIL_DELIVERY = "smtp";
    delete process.env.SMTP_HOST;

    try {
      await rejectsWith(
        service.sendInvitationEmail(org.invitationId, org.adminId),
        "EMAIL_DELIVERY_UNCONFIRMED",
      );
    } finally {
      process.env.EMAIL_DELIVERY = saved.delivery;
      if (saved.host !== undefined) process.env.SMTP_HOST = saved.host;
    }

    const status = await pool.query(
      `SELECT delivery_status FROM secretary_email_verifications WHERE invitation_id = $1`,
      [org.invitationId],
    );
    assert.equal(status.rows[0].delivery_status, "failed");
  });
});

describe("recipient verification", () => {
  test("the lookup shows only minimal information", async () => {
    const org = await createOrganization();
    const { token } = await sendInvitation(org);

    const context = await service.lookupInvitation(token);
    assert.equal(context.state, "open");
    assert.ok(context.state === "open" && !context.emailVerified && context.code);
    assert.ok(!JSON.stringify(context).includes(org.email), "the full address is masked");
  });

  test("unknown and malformed tokens get the same generic answer", async () => {
    const unknown = await app.inject({
      method: "POST",
      url: "/public/invitations/lookup",
      payload: { token: randomBytes(32).toString("base64url") },
    });
    assert.equal(unknown.statusCode, 404);
    assert.equal(unknown.json().error, "INVITATION_LINK_INVALID");

    const malformed = await app.inject({
      method: "POST",
      url: "/public/invitations/lookup",
      payload: { token: "short" },
    });
    assert.equal(malformed.statusCode, 400);
  });

  test("the correct code verifies the email exactly once", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);

    const response = await app.inject({
      method: "POST",
      url: "/public/invitations/email-verification/confirm",
      payload: { token, code },
    });
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().verified, true);

    const stored = await pool.query(
      `SELECT email, verified_email, email_verified_at FROM tenant_invitations WHERE id = $1`,
      [org.invitationId],
    );
    assert.equal(stored.rows[0].verified_email, stored.rows[0].email);
    assert.ok(stored.rows[0].email_verified_at);
    assert.ok((await challengeRow(org.invitationId)).consumed_at);

    await rejectsWith(service.confirmRecipientCode(token, null, code!), "EMAIL_ALREADY_VERIFIED");

    const memberships = await pool.query(
      `SELECT 1 FROM tenant_memberships WHERE tenant_id = $1`,
      [org.tenantId],
    );
    assert.equal(memberships.rowCount, 0, "verification alone creates no membership");
  });

  test("wrong codes are counted even though they fail", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);

    await rejectsWith(service.confirmRecipientCode(token, null, wrongCode(code!)), "OTP_INVALID");
    assert.equal((await challengeRow(org.invitationId)).attempts, 1);
  });

  test("five wrong codes exhaust the challenge, even for the right code", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);

    for (let i = 0; i < 4; i++) {
      await rejectsWith(service.confirmRecipientCode(token, null, wrongCode(code!)), "OTP_INVALID");
    }
    await rejectsWith(service.confirmRecipientCode(token, null, wrongCode(code!)), "OTP_ATTEMPTS_EXCEEDED");
    await rejectsWith(service.confirmRecipientCode(token, null, code!), "OTP_ATTEMPTS_EXCEEDED");
    assert.equal((await challengeRow(org.invitationId)).attempts, 5);
  });

  test("an expired code is refused", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);

    await pool.query(
      `
      UPDATE secretary_email_verifications
      SET last_requested_at = now() - interval '20 minutes',
          expires_at = now() - interval '10 minutes'
      WHERE invitation_id = $1
      `,
      [org.invitationId],
    );

    await rejectsWith(service.confirmRecipientCode(token, null, code!), "OTP_EXPIRED");
  });

  test("a resent code replaces the previous one", async () => {
    const org = await createOrganization();
    const first = await sendInvitation(org);
    const firstChallenge = (await service.lookupInvitation(first.token));
    assert.ok(firstChallenge.state === "open" && firstChallenge.code);

    await rejectsWith(service.resendRecipientCode(first.token), "OTP_RESEND_COOLDOWN");
    await skipCooldown(org.invitationId);

    const resend = await service.resendRecipientCode(first.token);
    const [email] = emails.takeCapturedEmails();
    const newCode = /verification code is: (\d{6})/.exec(email!.text)?.[1];
    assert.ok(newCode);
    assert.ok(!email!.text.includes(first.token), "the code-only email has no link");

    // The page still holding the old challenge is told a newer code exists.
    await rejectsWith(
      service.confirmRecipientCode(first.token, firstChallenge.code.challengeId, first.code!),
      "OTP_CHALLENGE_CHANGED",
    );
    if (first.code !== newCode) {
      await rejectsWith(service.confirmRecipientCode(first.token, null, first.code!), "OTP_INVALID");
    }

    const result = await service.confirmRecipientCode(first.token, resend.challengeId, newCode);
    assert.equal(result.verified, true);
  });

  test("stops at five codes per hour", async () => {
    const org = await createOrganization();
    const { token } = await sendInvitation(org);

    await pool.query(
      `UPDATE secretary_email_verifications SET send_count = 5 WHERE invitation_id = $1`,
      [org.invitationId],
    );
    await skipCooldown(org.invitationId);

    await rejectsWith(service.resendRecipientCode(token), "OTP_SEND_LIMIT");
  });

  test("concurrent correct codes verify exactly once", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);

    const results = await Promise.allSettled(
      Array.from({ length: 5 }, () => service.confirmRecipientCode(token, null, code!)),
    );

    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    for (const r of results.filter((r) => r.status === "rejected")) {
      assert.equal((r as PromiseRejectedResult).reason.code, "EMAIL_ALREADY_VERIFIED");
    }
  });

  test("concurrent wrong codes don't lose attempt increments", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);

    await Promise.allSettled(
      Array.from({ length: 3 }, () => service.confirmRecipientCode(token, null, wrongCode(code!))),
    );

    assert.equal((await challengeRow(org.invitationId)).attempts, 3);
  });
});

describe("email changes", () => {
  test("invalidate the link, the outstanding code and the verification", async () => {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);
    await service.confirmRecipientCode(token, null, code!);

    await invitations.changeInvitationEmail(org.invitationId, "new-secretary@example.com", org.adminId);

    const stored = await pool.query(
      `SELECT status, token_hash, email_verified_at, verified_email FROM tenant_invitations WHERE id = $1`,
      [org.invitationId],
    );
    assert.deepEqual(stored.rows[0], {
      status: "pending_setup",
      token_hash: null,
      email_verified_at: null,
      verified_email: null,
    });
    assert.equal(await challengeRow(org.invitationId), undefined);
    await rejectsWith(service.lookupInvitation(token), "INVITATION_LINK_INVALID");
  });

  test("a code issued for the old address can't verify the new one", async () => {
    const org = await createOrganization();
    const first = await sendInvitation(org);

    await invitations.changeInvitationEmail(org.invitationId, "changed@example.com", org.adminId);
    const second = await sendInvitation(org);
    assert.equal(second.email.to, "changed@example.com");

    await rejectsWith(service.confirmRecipientCode(first.token, null, first.code!), "INVITATION_LINK_INVALID");
    if (first.code !== second.code) {
      await rejectsWith(service.confirmRecipientCode(second.token, null, first.code!), "OTP_INVALID");
    }
  });
});

describe("acceptance", () => {
  async function verifiedInvitation() {
    const org = await createOrganization();
    const { token, code } = await sendInvitation(org);
    return { org, token, code: code! };
  }

  test("requires the invitation email to be verified first", async () => {
    const { org, token } = await verifiedInvitation();
    const secretary = await createIdentity({ email: org.email, emailVerified: true });
    await rejectsWith(service.acceptInvitationByToken(token, secretary), "EMAIL_NOT_VERIFIED");
  });

  test("requires a Keycloak-verified identity email", async () => {
    const { org, token, code } = await verifiedInvitation();
    await service.confirmRecipientCode(token, null, code);
    const secretary = await createIdentity({ email: org.email, emailVerified: false });
    await rejectsWith(service.acceptInvitationByToken(token, secretary), "IDENTITY_EMAIL_NOT_VERIFIED");
  });

  test("requires the identity email to match the invitation", async () => {
    const { token, code } = await verifiedInvitation();
    await service.confirmRecipientCode(token, null, code);
    const someoneElse = await createIdentity({ email: "someone@example.com", emailVerified: true });
    await rejectsWith(service.acceptInvitationByToken(token, someoneElse), "IDENTITY_EMAIL_MISMATCH");
  });

  test("creates one membership, and the link can't be reused by others", async () => {
    const { org, token, code } = await verifiedInvitation();
    await service.confirmRecipientCode(token, null, code);
    const secretary = await createIdentity({ email: org.email.toUpperCase(), emailVerified: true });

    const accepted = await service.acceptInvitationByToken(token, secretary);
    assert.equal(accepted.accepted, true);

    // Repeating it is harmless for the same person...
    await service.acceptInvitationByToken(token, secretary);
    const memberships = await pool.query(
      `SELECT role FROM tenant_memberships WHERE tenant_id = $1 AND identity_id = $2`,
      [org.tenantId, secretary],
    );
    assert.deepEqual(memberships.rows, [{ role: "secretary" }]);

    // ...but nobody else can use the link.
    const other = await createIdentity({ email: org.email, emailVerified: true });
    await rejectsWith(service.acceptInvitationByToken(token, other), "INVITATION_LINK_INVALID");
    assert.equal((await service.lookupInvitation(token)).state, "accepted");
  });

  test("needs a signed-in session", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/invitations/accept",
      payload: { token: randomBytes(32).toString("base64url") },
    });
    assert.equal(response.statusCode, 401);
  });
});

describe("admin onboarding status", () => {
  test("reports each stage separately, without secrets", async () => {
    const org = await createOrganization();
    await pool.query(
      `
      UPDATE tenant_resources SET database_secret_ref = 'secret://should-not-leak',
        kms_key_ref = 'kms://should-not-leak'
      WHERE tenant_id = $1
      `,
      [org.tenantId],
    );
    assert.equal(
      (await pool.query(`SELECT 1 FROM tenant_resources WHERE database_secret_ref IS NOT NULL AND tenant_id = $1`, [org.tenantId])).rowCount,
      1,
    );

    let status = (await onboarding.getTenantOnboarding(org.tenantId))!;
    assert.equal(status.infrastructure.status, "succeeded");
    assert.equal(status.domain?.status, "pending");
    assert.equal(status.secretary?.emailVerification.status, "not_requested");
    assert.equal(status.secretary?.membership.accepted, false);

    const { token, code } = await sendInvitation(org);
    status = (await onboarding.getTenantOnboarding(org.tenantId))!;
    assert.equal(status.secretary?.emailVerification.status, "code_sent", "sent is not verified");

    await service.confirmRecipientCode(token, null, code!);
    status = (await onboarding.getTenantOnboarding(org.tenantId))!;
    assert.equal(status.secretary?.emailVerification.status, "verified");
    assert.equal(status.secretary?.membership.accepted, false, "verified is not accepted");

    const body = JSON.stringify(status);
    for (const forbidden of ["should-not-leak", "hash", token, code!]) {
      assert.ok(!body.includes(forbidden), `response must not contain ${forbidden}`);
    }
  });

  test("lists organizations with their onboarding facts, without secrets", async () => {
    const org = await createOrganization();
    await pool.query(
      `UPDATE tenant_resources SET database_secret_ref = 'secret://list-leak', kms_key_ref = 'kms://list-leak' WHERE tenant_id = $1`,
      [org.tenantId],
    );
    const list = await onboarding.listTenantSummaries();
    const row = list.find((r) => r.id === org.tenantId);

    assert.ok(row);
    assert.equal(row.jobStatus, "succeeded");
    assert.equal(row.domainStatus, "pending");
    assert.equal(row.secretary?.email, org.email);
    assert.equal(row.secretary?.emailVerifiedAt, null);
    const body = JSON.stringify(list);
    assert.ok(!body.includes("list-leak") && !/hash|_ref|Ref"/i.test(body), "no secret material in the list");
  });

  test("admin endpoints require a session", async () => {
    const id = randomUUID();
    for (const [method, url] of [
      ["GET", "/admin/tenants"],
      ["GET", `/admin/tenants/${id}/onboarding`],
      ["POST", `/admin/invitations/${id}/email-verification`],
      ["PATCH", `/admin/invitations/${id}`],
    ] as const) {
      const response = await app.inject({ method, url, payload: method === "PATCH" ? { email: "a@b.co" } : undefined });
      assert.equal(response.statusCode, 401, `${method} ${url}`);
    }
  });
});

describe("login return path", () => {
  test("allows only known frontend paths", () => {
    assert.equal(safeReturnPath("/invitation"), "/invitation");
    assert.equal(safeReturnPath("/master/dashboard"), "/master/dashboard");
    for (const unsafe of ["//evil.example", "https://evil.example", "/invitation?x=1", "/other", "/master/../x", 42]) {
      assert.equal(safeReturnPath(unsafe), null, String(unsafe));
    }
  });
});
