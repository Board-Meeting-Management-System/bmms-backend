// Audit log, organization lifecycle (suspend / reactivate / scheduled
// deletion), administrator management, usage tracking and notifications.
//
// Same isolation as tenancy.test.ts: a disposable control database, tenant
// databases created under unique names and dropped afterwards, a temporary
// storage root, captured email, and a local JWKS instead of Keycloak.
//
// Run: npm run test:administration

import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";

import type { InjectOptions } from "fastify";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import pg from "pg";

import { createTestDatabase, type TestDatabase } from "./support/test-database.js";

const SERVICE_TOKEN = randomBytes(32).toString("base64url");
let database: TestDatabase;
let storageRoot: string;
let jwksServer: http.Server;
let routingServer: http.Server;
let signingKey: CryptoKey;
const createdTenants: string[] = [];

let pool: typeof import("../src/db.js")["pool"];
let app: Awaited<ReturnType<typeof import("../src/app.js")["buildApp"]>>;
let runner: typeof import("../src/modules/provisioning/provisioning-runner.js");
let organizations: typeof import("../src/modules/organizations/organization.service.js");
let sessions: typeof import("../src/modules/auth/session.repository.js");
let administrators: typeof import("../src/modules/administrators/administrators.repository.js");
let usage: typeof import("../src/modules/usage/usage.repository.js");
let provisioningPool: typeof import("../src/modules/provisioning/provisioning.db.js")["provisioningPool"];

const listen = (server: http.Server) =>
  new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));

before(async () => {
  database = await createTestDatabase();
  storageRoot = await mkdtemp(path.join(tmpdir(), "bmms-admin-storage-"));

  const keys = await generateKeyPair("RS256");
  signingKey = keys.privateKey;
  const jwk = { ...(await exportJWK(keys.publicKey)), kid: "test", alg: "RS256", use: "sig" };
  jwksServer = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  const jwksPort = await listen(jwksServer);

  Object.assign(process.env, {
    CONTROL_DATABASE_URL: database.url,
    NODE_ENV: "development",
    EMAIL_DELIVERY: "capture",
    EMAIL_OTP_HMAC_KEY: randomBytes(32).toString("base64"),
    SESSION_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    TENANT_SECRETS_KEY_V1: randomBytes(32).toString("base64"),
    FRONTEND_ORIGIN: "http://localhost:3000",
    DOMAIN_PROVIDER: "local",
    PLATFORM_BASE_DOMAIN: "localhost",
    STORAGE_PROVIDER: "local",
    TENANT_STORAGE_ROOT: storageRoot,
    ORG_PLATFORM_SERVICE_TOKEN: SERVICE_TOKEN,
    ORG_PLATFORM_ORIGIN: "http://localhost:3100",
    TENANT_DELETION_GRACE_HOURS: "0",
    OIDC_ISSUER: "http://localhost:8080/realms/bmms",
    OIDC_JWKS_URL: `http://127.0.0.1:${jwksPort}/jwks`,
    OIDC_AUDIENCE: "bmms-api",
    OIDC_CLIENT_ID: "bmms-backend",
    OIDC_CLIENT_SECRET: "test-only",
    OIDC_REDIRECT_URI: "http://localhost:3001/auth/callback",
  });

  ({ pool } = await import("../src/db.js"));
  ({ provisioningPool } = await import("../src/modules/provisioning/provisioning.db.js"));
  runner = await import("../src/modules/provisioning/provisioning-runner.js");
  organizations = await import("../src/modules/organizations/organization.service.js");
  sessions = await import("../src/modules/auth/session.repository.js");
  administrators = await import("../src/modules/administrators/administrators.repository.js");
  usage = await import("../src/modules/usage/usage.repository.js");
  app = await (await import("../src/app.js")).buildApp();

  // The organization platform's /bmms-routing, via the internal API.
  routingServer = http.createServer(async (req, res) => {
    const host = (req.headers.host ?? "").split(":")[0] ?? "";
    const response = await internal(`/internal/v1/tenants/resolve?hostname=${encodeURIComponent(host)}`);
    const body = response.statusCode === 200
      ? { hostname: response.json().hostname, organizationId: response.json().organizationId }
      : response.json();
    res.writeHead(response.statusCode, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  process.env.LOCAL_ROUTING_CHECK_ORIGIN = `http://127.0.0.1:${await listen(routingServer)}`;
});

after(async () => {
  await app?.close();
  routingServer?.close();
  jwksServer?.close();
  // Drop whatever the tests left (deleted organizations are already gone).
  if (createdTenants.length) {
    for (const id of createdTenants) {
      const suffix = id.replaceAll("-", "");
      assert.match(suffix, /^[0-9a-f]{32}$/);
      await provisioningPool.query(`DROP DATABASE IF EXISTS bmms_t_${suffix} WITH (FORCE)`);
      await provisioningPool.query(`DROP ROLE IF EXISTS bmms_app_${suffix}`);
      await provisioningPool.query(`DROP ROLE IF EXISTS bmms_owner_${suffix}`);
    }
  }
  await provisioningPool?.end();
  await database?.drop();
  if (storageRoot) await rm(storageRoot, { recursive: true, force: true });
});

// ---- Helpers ------------------------------------------------------------------

const internal = (url: string) =>
  app.inject({ method: "GET", url, headers: { authorization: `Bearer ${SERVICE_TOKEN}` } });

async function createIdentity(options: { admin?: boolean; email?: string; verified?: boolean } = {}) {
  const subject = randomUUID();
  const email = options.email ?? `${subject}@example.com`;
  const result = await pool.query<{ id: string }>(
    `INSERT INTO identities (issuer, subject, email, email_verified, is_platform_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [process.env.OIDC_ISSUER, subject, email, options.verified ?? true, options.admin ?? false],
  );
  return { id: result.rows[0]!.id, subject, email };
}

let firstAdmin: Awaited<ReturnType<typeof createIdentity>>;
async function adminIdentity() {
  firstAdmin ??= await createIdentity({ admin: true, email: "first-admin@bmms.test" });
  return firstAdmin;
}

async function sessionFor(identity: { id: string; subject: string }) {
  const accessToken = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid: "test" })
    .setIssuer(process.env.OIDC_ISSUER!)
    .setAudience(process.env.OIDC_AUDIENCE!)
    .setSubject(identity.subject)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(signingKey);
  return (await sessions.createSession({ identityId: identity.id, tokens: { accessToken }, accessTokenExpiresAt: new Date(Date.now() + 3_600_000) })).sessionToken;
}

/** An admin request with a session cookie and the trusted Origin. */
async function asAdmin(method: "GET" | "POST" | "DELETE", url: string, payload?: Record<string, unknown>, who?: { id: string; subject: string }) {
  const cookie = await sessionFor(who ?? (await adminIdentity()));
  const options: InjectOptions = {
    method,
    url,
    headers: { cookie: `bmms_session=${cookie}`, origin: "http://localhost:3000" },
  };
  if (payload !== undefined) options.payload = payload;
  return app.inject(options);
}

async function register(label: string) {
  const admin = await adminIdentity();
  const slug = `${label}-${randomBytes(3).toString("hex")}`;
  const result = await organizations.createOrganization(
    { name: `Org ${slug}`, slug, secretaryEmail: `secretary@${slug}.example.com` },
    randomUUID(),
    { id: admin.id, email: admin.email, emailVerified: true, status: "active", isPlatformAdmin: true },
  );
  createdTenants.push(result.tenantId);
  return { ...result, slug };
}

async function drainWorker(max = 30) {
  for (let i = 0; i < max; i++) {
    if ((await runner.runWorkerIteration("admin-test-worker")) === "idle") return;
  }
  throw new Error("Worker did not become idle.");
}

async function events(action: string, tenantId?: string) {
  return (
    await pool.query(
      `SELECT actor_identity_id, actor_label, tenant_name, metadata FROM audit_events WHERE action = $1 AND ($2::uuid IS NULL OR tenant_id = $2::uuid) ORDER BY id`,
      [action, tenantId ?? null],
    )
  ).rows;
}

// ---- Audit log --------------------------------------------------------------------

describe("audit log", () => {
  test("registration and provisioning are recorded, with who did it", async () => {
    const org = await register("audited");
    await drainWorker();
    const [registered] = await events("organization.registered", org.tenantId);
    assert.equal(registered.actor_identity_id, firstAdmin.id);
    assert.equal(registered.actor_label, firstAdmin.email);
    assert.equal(registered.metadata.slug, org.slug);
    assert.equal((await events("provisioning.succeeded", org.tenantId)).length, 1);
    assert.equal((await events("invitation.sent", org.tenantId))[0].actor_label, null, "the system sent it");
  });

  test("is append-only", async () => {
    await assert.rejects(pool.query(`UPDATE audit_events SET action = 'x.y'`), /append-only/);
    await assert.rejects(pool.query(`DELETE FROM audit_events`), /append-only/);
  });

  test("the API lists events newest first, per organization, with paging", async () => {
    const org = await register("listed");
    await drainWorker();
    const all = (await asAdmin("GET", `/admin/audit?tenantId=${org.tenantId}`)).json();
    assert.ok(all.events.length >= 2);
    assert.ok(all.events.every((e: { tenantId: string }) => e.tenantId === org.tenantId));
    assert.ok(Number(all.events[0].id) > Number(all.events[1].id));
    const page = (await asAdmin("GET", `/admin/audit?tenantId=${org.tenantId}&limit=1&before=${all.events[0].id}`)).json();
    assert.equal(page.events[0].id, all.events[1].id);
  });
});

// ---- Lifecycle --------------------------------------------------------------------

describe("organization lifecycle", () => {
  test("suspending stops the organization being served; reactivating restores it", async () => {
    const org = await register("pausable");
    await drainWorker();
    const hostname = `${org.slug}.localhost`;
    assert.equal((await internal(`/internal/v1/tenants/resolve?hostname=${hostname}`)).statusCode, 200);

    const suspended = await asAdmin("POST", `/admin/tenants/${org.tenantId}/suspend`, { reason: "Unpaid invoice" });
    assert.equal(suspended.statusCode, 200);
    assert.equal((await internal(`/internal/v1/tenants/resolve?hostname=${hostname}`)).statusCode, 404);
    assert.equal((await internal(`/internal/v1/tenants/${org.tenantId}/database`)).statusCode, 404, "no credentials while suspended");
    assert.equal((await events("organization.suspended", org.tenantId))[0].metadata.reason, "Unpaid invoice");

    assert.equal((await asAdmin("POST", `/admin/tenants/${org.tenantId}/suspend`)).json().error, "NOT_ACTIVE");
    assert.equal((await asAdmin("POST", `/admin/tenants/${org.tenantId}/reactivate`)).statusCode, 200);
    assert.equal((await internal(`/internal/v1/tenants/resolve?hostname=${hostname}`)).json().ready, true);
  });

  test("deletion needs suspension and the slug, can be cancelled, then removes everything", async () => {
    const org = await register("doomed");
    await drainWorker();
    const suffix = org.tenantId.replaceAll("-", "");
    const url = `/admin/tenants/${org.tenantId}/deletion`;

    assert.equal((await asAdmin("POST", url, { confirmSlug: org.slug })).json().error, "NOT_SUSPENDED");
    await asAdmin("POST", `/admin/tenants/${org.tenantId}/suspend`);
    assert.equal((await asAdmin("POST", url, { confirmSlug: "wrong" })).json().error, "CONFIRMATION_MISMATCH");

    // Scheduled, then cancelled: nothing is deleted.
    assert.equal((await asAdmin("POST", url, { confirmSlug: org.slug.toUpperCase() })).statusCode, 200);
    assert.equal((await asAdmin("POST", `/admin/tenants/${org.tenantId}/reactivate`)).json().error, "DELETION_SCHEDULED");
    assert.equal((await asAdmin("DELETE", url)).statusCode, 200);
    await drainWorker();
    assert.equal((await pool.query(`SELECT 1 FROM tenants WHERE id = $1`, [org.tenantId])).rowCount, 1);

    // Scheduled again (grace 0 in tests): the worker removes it.
    await writeFile(path.join(storageRoot, org.tenantId, "minutes.pdf"), "x");
    assert.equal((await asAdmin("POST", url, { confirmSlug: org.slug })).statusCode, 200);
    await drainWorker();

    assert.equal((await pool.query(`SELECT 1 FROM tenants WHERE id = $1`, [org.tenantId])).rowCount, 0);
    for (const table of ["tenant_domains", "tenant_resources", "tenant_secrets", "tenant_data_keys", "tenant_invitations", "provisioning_jobs"]) {
      assert.equal((await pool.query(`SELECT 1 FROM ${table} WHERE tenant_id = $1`, [org.tenantId])).rowCount, 0, table);
    }
    assert.equal((await provisioningPool.query(`SELECT 1 FROM pg_database WHERE datname = $1`, [`bmms_t_${suffix}`])).rowCount, 0);
    assert.equal((await provisioningPool.query(`SELECT 1 FROM pg_roles WHERE rolname LIKE $1`, [`bmms_%_${suffix}`])).rowCount, 0);
    await assert.rejects(stat(path.join(storageRoot, org.tenantId)), { code: "ENOENT" });

    const deleted = await events("organization.deleted", org.tenantId);
    assert.equal(deleted.length, 1);
    assert.equal(deleted[0].tenant_name, `Org ${org.slug}`, "the audit log keeps the name");
  });
});

// ---- Administrators -------------------------------------------------------------

describe("administrators", () => {
  test("access is granted now for known accounts, or at the first sign-in", async () => {
    const known = await createIdentity({ email: "known@bmms.test" });
    assert.equal((await asAdmin("POST", "/admin/administrators", { email: "KNOWN@bmms.test" })).json().result, "granted");
    assert.equal((await pool.query(`SELECT is_platform_admin FROM identities WHERE id = $1`, [known.id])).rows[0].is_platform_admin, true);
    assert.equal((await asAdmin("POST", "/admin/administrators", { email: "known@bmms.test" })).json().error, "ALREADY_ADMINISTRATOR");

    assert.equal((await asAdmin("POST", "/admin/administrators", { email: "newcomer@bmms.test" })).json().result, "pending");
    assert.equal((await asAdmin("POST", "/admin/administrators", { email: "newcomer@bmms.test" })).json().error, "ALREADY_INVITED");

    // Unverified email: not granted.
    const unverified = await createIdentity({ email: "newcomer@bmms.test", verified: false });
    const asUnverified = await administrators.applyPendingAdministratorGrant({
      id: unverified.id, email: unverified.email, emailVerified: false, status: "active", isPlatformAdmin: false,
    });
    assert.equal(asUnverified.isPlatformAdmin, false);

    const newcomer = await createIdentity({ email: "Newcomer@bmms.test" });
    const user = await administrators.applyPendingAdministratorGrant({
      id: newcomer.id, email: newcomer.email, emailVerified: true, status: "active", isPlatformAdmin: false,
    });
    assert.equal(user.isPlatformAdmin, true);
    assert.equal((await pool.query(`SELECT 1 FROM platform_admin_invitations WHERE email = 'newcomer@bmms.test'`)).rowCount, 0);
    assert.equal((await events("administrator.joined")).length, 1);
  });

  test("nobody can change themselves or remove the last active administrator", async () => {
    const me = await adminIdentity();
    assert.equal((await asAdmin("DELETE", `/admin/administrators/${me.id}`)).json().error, "CANNOT_CHANGE_SELF");
    assert.equal((await asAdmin("POST", `/admin/administrators/${me.id}/disable`)).json().error, "CANNOT_CHANGE_SELF");

    // Through the API an acting admin is always another active admin, so the
    // last-admin guard is defence in depth: exercise it directly, with every
    // other admin temporarily removed.
    const others = await pool.query<{ id: string }>(
      `UPDATE identities SET is_platform_admin = FALSE WHERE is_platform_admin AND id <> $1 RETURNING id`,
      [me.id],
    );
    try {
      await assert.rejects(
        administrators.revokeAdministrator(me.id, { id: randomUUID(), email: "someone@bmms.test" }),
        (e: { code?: string }) => e.code === "LAST_ADMINISTRATOR",
      );
      await assert.rejects(
        administrators.setAdministratorStatus(me.id, "disabled", { id: randomUUID(), email: null }),
        (e: { code?: string }) => e.code === "LAST_ADMINISTRATOR",
      );
    } finally {
      await pool.query(`UPDATE identities SET is_platform_admin = TRUE WHERE id = ANY($1)`, [others.rows.map((r) => r.id)]);
    }

    // With another admin present, revoking works and is audited.
    const removable = await createIdentity({ admin: true, email: "removable@bmms.test" });
    assert.equal((await asAdmin("DELETE", `/admin/administrators/${removable.id}`)).statusCode, 200);
    assert.equal((await events("administrator.revoked")).at(-1)?.metadata.email, "removable@bmms.test");
  });

  test("disabling revokes sessions and blocks sign-in until enabled", async () => {
    const target = await createIdentity({ admin: true, email: "target@bmms.test" });
    const targetSession = await sessionFor(target);
    const disabled = await asAdmin("POST", `/admin/administrators/${target.id}/disable`);
    assert.equal(disabled.statusCode, 200);
    const me = await app.inject({ method: "GET", url: "/auth/me", headers: { cookie: `bmms_session=${targetSession}` } });
    assert.equal(me.statusCode, 401);
    assert.equal((await asAdmin("POST", `/admin/administrators/${target.id}/enable`)).statusCode, 200);
    assert.equal((await pool.query(`SELECT status FROM identities WHERE id = $1`, [target.id])).rows[0].status, "active");
  });

  test("my sessions: list them and sign out the others", async () => {
    const me = await adminIdentity();
    const other = await sessionFor(me);
    const current = await sessionFor(me);
    const list = await app.inject({ method: "GET", url: "/auth/sessions", headers: { cookie: `bmms_session=${current}` } });
    assert.ok(list.json().sessions.some((s: { current: boolean }) => s.current));
    const revoked = await app.inject({
      method: "POST",
      url: "/auth/sessions/revoke-others",
      headers: { cookie: `bmms_session=${current}`, origin: "http://localhost:3000" },
    });
    assert.ok(revoked.json().revoked >= 1);
    const stillOther = await app.inject({ method: "GET", url: "/auth/me", headers: { cookie: `bmms_session=${other}` } });
    assert.equal(stillOther.statusCode, 401);
  });
});

// ---- Usage and notifications ------------------------------------------------------

describe("usage and notifications", () => {
  test("measures database and storage, and flags organizations near limits", async () => {
    const org = await register("measured");
    await drainWorker();
    await writeFile(path.join(storageRoot, org.tenantId, "agenda.pdf"), Buffer.alloc(2048));

    const measured = await usage.collectTenantUsage(org.tenantId);
    assert.ok((measured.databaseBytes ?? 0) > 1024 * 1024, "a real database size");
    assert.equal(measured.storageBytes, 2048);
    assert.equal(measured.storageFiles, 1, "the ownership marker isn't counted");
    assert.equal(measured.lastErrorCode, null);

    process.env.TENANT_DATABASE_WARN_MB = "1";
    try {
      assert.deepEqual(usage.usageWarnings(measured), ["DATABASE_NEAR_LIMIT"]);
      const notes = (await asAdmin("GET", "/admin/notifications")).json().notifications;
      assert.ok(notes.some((n: { id: string }) => n.id === `usage_limit:${org.tenantId}`));
    } finally {
      delete process.env.TENANT_DATABASE_WARN_MB;
    }

    const onboarding = (await asAdmin("GET", `/admin/tenants/${org.tenantId}/onboarding`)).json().onboarding;
    assert.equal(onboarding.usage.storageBytes, 2048);
  });

  test("notifications follow current state", async () => {
    const org = await register("noisy");
    await drainWorker();
    await pool.query(`UPDATE provisioning_jobs SET status = 'failed', last_error_code = 'DOMAIN_NOT_READY' WHERE tenant_id = $1`, [org.tenantId]);
    let notes = (await asAdmin("GET", "/admin/notifications")).json().notifications;
    assert.equal(notes.find((n: { id: string }) => n.id === `provisioning_failed:${org.tenantId}`)?.severity, "critical");

    await pool.query(`UPDATE provisioning_jobs SET status = 'succeeded', last_error_code = NULL WHERE tenant_id = $1`, [org.tenantId]);
    notes = (await asAdmin("GET", "/admin/notifications")).json().notifications;
    assert.ok(!notes.some((n: { id: string }) => n.id === `provisioning_failed:${org.tenantId}`), "gone once fixed");
  });

  test("settings expose configuration, never secrets", async () => {
    const response = await asAdmin("GET", "/admin/platform/settings");
    const body = JSON.stringify(response.json());
    assert.equal(response.json().settings.organizationPlatform.internalApiEnabled, true);
    assert.equal(response.json().settings.lifecycle.deletionGraceHours, 0);
    for (const secret of [SERVICE_TOKEN, process.env.TENANT_SECRETS_KEY_V1!, process.env.SESSION_ENCRYPTION_KEY!]) {
      assert.ok(!body.includes(secret));
    }
  });

  test("every new admin endpoint needs a session", async () => {
    const id = randomUUID();
    for (const [method, url] of [
      ["GET", "/admin/audit"],
      ["GET", "/admin/notifications"],
      ["GET", "/admin/platform/settings"],
      ["POST", `/admin/tenants/${id}/suspend`],
      ["POST", `/admin/tenants/${id}/reactivate`],
      ["POST", `/admin/tenants/${id}/deletion`],
      ["DELETE", `/admin/tenants/${id}/deletion`],
      ["POST", `/admin/tenants/${id}/usage/refresh`],
      ["POST", "/admin/administrators"],
      ["DELETE", `/admin/administrators/${id}`],
      ["GET", "/auth/sessions"],
    ] as const) {
      assert.equal((await app.inject({ method, url })).statusCode, 401, `${method} ${url}`);
    }
  });
});
