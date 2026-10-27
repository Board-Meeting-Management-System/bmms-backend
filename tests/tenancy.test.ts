// Multi-tenant provisioning, routing and isolation.
//
// Provisions real organizations: their control rows go to a disposable
// control database, their tenant databases and roles are created on the
// PostgreSQL server in PROVISIONING_DATABASE_URL under unique names and are
// dropped afterwards. Storage goes to a temporary directory. Keycloak is
// replaced by a local JWKS server and locally signed tokens; email is
// captured in memory. Nothing in bmms_control is touched.
//
// Run: npm run test:tenancy

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, describe, test } from "node:test";

import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import pg from "pg";

import { createTestDatabase, type TestDatabase } from "./support/test-database.js";

// ---- Environment -------------------------------------------------------------

let database: TestDatabase;
let storageRoot: string;
let jwksServer: http.Server;
let routingServer: http.Server;
let signingKey: CryptoKey;
const createdTenants: string[] = [];

/** When set, the fake frontend answers /bmms-routing with this organization id. */
let routingOverride: string | null = null;

let pool: typeof import("../src/db.js")["pool"];
let app: Awaited<ReturnType<typeof import("../src/app.js")["buildApp"]>>;
let runner: typeof import("../src/modules/provisioning/provisioning-runner.js");
let worker: typeof import("../src/modules/provisioning/provisioning-worker.repository.js");
let steps: typeof import("../src/modules/provisioning/provisioning-step.repository.js");
let createStep: typeof import("../src/modules/provisioning/create-database.step.js");
let jobs: typeof import("../src/modules/provisioning/provisioning.repository.js");
let organizations: typeof import("../src/modules/organizations/organization.service.js");
let registration: typeof import("../src/modules/organizations/organization.repository.js");
let domains: typeof import("../src/modules/domains/domain.repository.js");
let providers: typeof import("../src/modules/domains/domain-provider.js");
let tenantDb: typeof import("../src/modules/tenant/tenant-database.js");
let sessions: typeof import("../src/modules/auth/session.repository.js");
let handoffs: typeof import("../src/modules/auth/handoff.repository.js");
let browserAuth: typeof import("../src/modules/auth/browser-auth.routes.js");
let storage: typeof import("../src/modules/storage/storage-provider.js");
let emails: typeof import("../src/modules/email/email.service.js");
let provisioningPool: typeof import("../src/modules/provisioning/provisioning.db.js")["provisioningPool"];

const listen = (server: http.Server | https.Server) =>
  new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));

before(async () => {
  database = await createTestDatabase();
  storageRoot = await mkdtemp(path.join(tmpdir(), "bmms-storage-"));

  // Local identity provider: a JWKS endpoint and a key to sign tokens with.
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
    // The frontend server is the trusted proxy that forwards tenant hosts.
    TRUST_PROXY: "127.0.0.1",
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
  worker = await import("../src/modules/provisioning/provisioning-worker.repository.js");
  steps = await import("../src/modules/provisioning/provisioning-step.repository.js");
  createStep = await import("../src/modules/provisioning/create-database.step.js");
  jobs = await import("../src/modules/provisioning/provisioning.repository.js");
  organizations = await import("../src/modules/organizations/organization.service.js");
  registration = await import("../src/modules/organizations/organization.repository.js");
  domains = await import("../src/modules/domains/domain.repository.js");
  providers = await import("../src/modules/domains/domain-provider.js");
  tenantDb = await import("../src/modules/tenant/tenant-database.js");
  sessions = await import("../src/modules/auth/session.repository.js");
  handoffs = await import("../src/modules/auth/handoff.repository.js");
  browserAuth = await import("../src/modules/auth/browser-auth.routes.js");
  storage = await import("../src/modules/storage/storage-provider.js");
  emails = await import("../src/modules/email/email.service.js");
  app = await (await import("../src/app.js")).buildApp();

  // Stand-in for the frontend's /bmms-routing: forwards the Host to the API.
  routingServer = http.createServer(async (req, res) => {
    const response = await app.inject({
      method: "GET",
      url: "/tenant/routing-probe",
      headers: { "x-forwarded-host": req.headers.host ?? "" },
    });
    let body = response.body;
    if (routingOverride && response.statusCode === 200) {
      body = JSON.stringify({ ...response.json(), organizationId: routingOverride });
    }
    res.writeHead(response.statusCode, { "content-type": "application/json" });
    res.end(body);
  });
  process.env.LOCAL_ROUTING_CHECK_ORIGIN = `http://127.0.0.1:${await listen(routingServer)}`;
});

after(async () => {
  await app?.close();
  await provisioningPool?.end();
  routingServer?.close();
  jwksServer?.close();

  // Drop exactly the tenant databases and roles these tests created.
  if (createdTenants.length) {
    const server = new pg.Client({ connectionString: process.env.PROVISIONING_DATABASE_URL });
    await server.connect();
    for (const id of createdTenants) {
      const suffix = id.replaceAll("-", "");
      assert.match(suffix, /^[0-9a-f]{32}$/);
      await server.query(`DROP DATABASE IF EXISTS bmms_t_${suffix} WITH (FORCE)`);
      await server.query(`DROP ROLE IF EXISTS bmms_app_${suffix}`);
      await server.query(`DROP ROLE IF EXISTS bmms_owner_${suffix}`);
    }
    await server.end();
  }

  await database?.drop();
  if (storageRoot) await rm(storageRoot, { recursive: true, force: true });
});

// ---- Helpers -------------------------------------------------------------------

async function createIdentity(options: { admin?: boolean; email?: string } = {}) {
  const subject = randomUUID();
  const result = await pool.query<{ id: string }>(
    `
    INSERT INTO identities (issuer, subject, email, email_verified, is_platform_admin)
    VALUES ($1, $2, $3, TRUE, $4)
    RETURNING id
    `,
    [process.env.OIDC_ISSUER, subject, options.email ?? `${subject}@example.com`, options.admin ?? false],
  );
  return { id: result.rows[0]!.id, subject };
}

let adminActor: Awaited<ReturnType<typeof createIdentity>>;

async function admin() {
  adminActor ??= await createIdentity({ admin: true, email: "admin@bmms.test" });
  return { id: adminActor.id, email: "admin@bmms.test", emailVerified: true, status: "active" as const, isPlatformAdmin: true };
}

async function register(slug: string, key: string = randomUUID()) {
  const result = await organizations.createOrganization(
    { name: `Org ${slug}`, slug, secretaryEmail: `secretary@${slug}.example.com` },
    key,
    await admin(),
  );
  if (!createdTenants.includes(result.tenantId)) createdTenants.push(result.tenantId);
  return result;
}

const uniqueSlug = (label: string) => `${label}-${randomBytes(3).toString("hex")}`;

async function jobRow(jobId: string) {
  return (await pool.query(`SELECT status, attempts, last_error_code, next_run_at FROM provisioning_jobs WHERE id = $1`, [jobId])).rows[0];
}

type StepRow = { step_name: string; status: string; attempts: number };

async function stepRows(jobId: string): Promise<Record<string, StepRow>> {
  const rows = (await pool.query<StepRow>(`SELECT step_name, status, attempts FROM provisioning_steps WHERE job_id = $1`, [jobId])).rows;
  return Object.fromEntries(rows.map((r) => [r.step_name, r]));
}

/** Runs worker iterations until nothing is due (bounded). */
async function drainWorker(workerId = "test-worker", max = 20) {
  for (let i = 0; i < max; i++) {
    if ((await runner.runWorkerIteration(workerId)) === "idle") return;
  }
  throw new Error("Worker did not become idle.");
}

/** A platform session for an identity, using a locally signed access token. */
async function platformSession(identity: { id: string; subject: string }) {
  const accessToken = await new SignJWT({ email: "x@example.com" })
    .setProtectedHeader({ alg: "RS256", kid: "test" })
    .setIssuer(process.env.OIDC_ISSUER!)
    .setAudience(process.env.OIDC_AUDIENCE!)
    .setSubject(identity.subject)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(signingKey);
  return sessions.createSession({
    identityId: identity.id,
    tokens: { accessToken },
    accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
  });
}

/** Signs in on an organization host the way the browser does: via a handoff. */
async function hostSession(identity: { id: string; subject: string }, host: string) {
  const platform = await platformSession(identity);
  const code = await handoffs.createHandoff(platform.sessionId, host);
  const exchanged = await handoffs.exchangeHandoff(code, host);
  assert.ok(exchanged);
  return exchanged.sessionToken;
}

const tenantRequest = (host: string, url: string, cookie?: string) =>
  app.inject({
    method: "GET",
    url,
    headers: { "x-forwarded-host": `${host}:3000`, ...(cookie ? { cookie: `bmms_session=${cookie}` } : {}) },
  });

// ---- Two organizations -----------------------------------------------------------

describe("two organizations", () => {
  let a: { tenantId: string; jobId: string };
  let b: { tenantId: string; jobId: string };
  let aHost: string;
  let bHost: string;

  before(async () => {
    a = await register(uniqueSlug("orga"));
    b = await register(uniqueSlug("orgb"));
    emails.takeCapturedEmails();
    await drainWorker();
    aHost = (await domains.primaryPlatformDomain(a.tenantId))!.hostname;
    bHost = (await domains.primaryPlatformDomain(b.tenantId))!.hostname;
  });

  test("both are fully provisioned, each step once", async () => {
    for (const org of [a, b]) {
      assert.equal((await jobRow(org.jobId)).status, "succeeded");
      const all = await stepRows(org.jobId);
      assert.equal(Object.keys(all).length, 8);
      for (const step of Object.values(all)) assert.deepEqual([step.status, step.attempts], ["succeeded", 1]);
    }
  });

  test("get separate databases, storage and hostnames", async () => {
    const resources = (
      await pool.query(`SELECT tenant_id, database_name, storage_ref FROM tenant_resources WHERE tenant_id = ANY($1)`, [[a.tenantId, b.tenantId]])
    ).rows;
    assert.equal(new Set(resources.map((r) => r.database_name)).size, 2);
    assert.deepEqual(new Set(resources.map((r) => r.storage_ref)), new Set([`local-fs:${a.tenantId}`, `local-fs:${b.tenantId}`]));

    for (const org of [a, b]) {
      const db = await tenantDb.tenantDatabase(org.tenantId);
      const stored = await db.query(`SELECT tenant_id FROM bmms.tenant_metadata`);
      assert.equal(stored.rows[0].tenant_id, org.tenantId, "each organization reads only its own database");
      assert.equal((await readFile(path.join(storageRoot, org.tenantId, ".bmms-tenant"), "utf8")).trim(), org.tenantId);
    }

    assert.notEqual(aHost, bHost);
    assert.match(aHost, /^orga-[0-9a-f]{6}\.localhost$/);
    assert.equal((await domains.resolveTenantByHostname(aHost))?.tenantId, a.tenantId);
    assert.equal((await domains.resolveTenantByHostname(bHost))?.tenantId, b.tenantId);
  });

  test("domains are active, with routing verified but no TLS claimed locally", async () => {
    const row = (await pool.query(`SELECT status, routing_verified_at, tls_ready_at, last_error_code FROM tenant_domains WHERE hostname = $1`, [aHost])).rows[0];
    assert.equal(row.status, "active");
    assert.ok(row.routing_verified_at);
    assert.equal(row.tls_ready_at, null);
    assert.equal(row.last_error_code, null);
  });

  test("each secretary invitation was queued at activation and delivered once", async () => {
    const deliveries = (
      await pool.query(
        `SELECT d.status FROM invitation_deliveries d JOIN tenant_invitations i ON i.id = d.invitation_id WHERE i.tenant_id = ANY($1)`,
        [[a.tenantId, b.tenantId]],
      )
    ).rows;
    assert.deepEqual(deliveries.map((d) => d.status), ["sent", "sent"]);
  });

  test("each hostname resolves to its own organization", async () => {
    const response = await tenantRequest(aHost, "/tenant/context");
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().hostname, aHost);
    assert.notEqual(response.json().organization.slug, (await tenantRequest(bHost, "/tenant/context")).json().organization.slug);
  });

  test("a member reaches their organization's own database", async () => {
    const secretary = await createIdentity();
    await pool.query(
      `INSERT INTO tenant_memberships (tenant_id, identity_id, role, invitation_id)
       SELECT $1, $2, 'secretary', id FROM tenant_invitations WHERE tenant_id = $1`,
      [a.tenantId, secretary.id],
    );
    const cookie = await hostSession(secretary, aHost);

    const me = await tenantRequest(aHost, "/tenant/me", cookie);
    assert.equal(me.statusCode, 200);
    assert.equal(me.json().membership.role, "secretary");

    const overview = await tenantRequest(aHost, "/tenant/overview", cookie);
    assert.equal(overview.statusCode, 200);
    assert.equal(overview.json().database.organizationId, a.tenantId);
  });

  test("cross-tenant access is denied", async () => {
    const member = await createIdentity();
    await pool.query(
      `INSERT INTO tenant_memberships (tenant_id, identity_id, role, invitation_id)
       SELECT $1, $2, 'secretary', id FROM tenant_invitations WHERE tenant_id = $1
       ON CONFLICT DO NOTHING`,
      [b.tenantId, member.id],
    );
    // A's session is bound to A's hostname: it's refused on B's.
    const aCookie = await hostSession(member, aHost);
    assert.equal((await tenantRequest(bHost, "/tenant/me", aCookie)).statusCode, 401);

    // A session for A's host, by someone who isn't A's member: forbidden.
    assert.equal((await tenantRequest(aHost, "/tenant/me", aCookie)).json().error, "NOT_A_MEMBER");

    // Platform sessions don't work on tenant routes, and vice versa.
    const platform = await platformSession(member);
    assert.equal((await tenantRequest(bHost, "/tenant/me", platform.sessionToken)).statusCode, 401);
    const bCookie = await hostSession(member, bHost);
    assert.equal((await tenantRequest(bHost, "/tenant/me", bCookie)).statusCode, 200);
    const adminCall = await app.inject({ method: "GET", url: "/auth/me", headers: { cookie: `bmms_session=${bCookie}` } });
    assert.equal(adminCall.statusCode, 401, "a host-bound session can't be used on platform routes");
  });

  test("platform administrators get no implicit access to tenant content", async () => {
    const cookie = await hostSession(adminActor, aHost);
    assert.equal((await tenantRequest(aHost, "/tenant/me", cookie)).json().error, "NOT_A_MEMBER");
  });

  test("storage keys can't escape the organization's directory", () => {
    const local = storage.storageProvider();
    assert.ok(local.objectPath(a.tenantId, "minutes/2026/agenda.pdf").startsWith(path.join(storageRoot, a.tenantId) + path.sep));
    for (const key of ["../x", "a/../../b", "/etc/passwd", "", ".bmms-tenant", `../${b.tenantId}/x`]) {
      assert.throws(() => local.objectPath(a.tenantId, key), key);
    }
  });

  test("login and logout return only to registered, active organization hosts", async () => {
    assert.equal(await browserAuth.safeReturnHost(`${aHost.toUpperCase()}:3000`), aHost);
    for (const bad of ["evil.example.com", "unknown.localhost", "localhost", "127.0.0.1", "", 42]) {
      assert.equal(await browserAuth.safeReturnHost(bad), null, String(bad));
    }

    const back = await app.inject({ method: "GET", url: `/auth/logged-out?state=${aHost}` });
    assert.equal(back.headers.location, `http://${aHost}:3000/`);
    const evil = await app.inject({ method: "GET", url: "/auth/logged-out?state=evil.example.com" });
    assert.equal(evil.headers.location, "http://localhost:3000/master");
  });

  test("handoff codes are single use, short-lived and bound to their host", async () => {
    const someone = await createIdentity();
    const platform = await platformSession(someone);

    const wrongHost = await handoffs.createHandoff(platform.sessionId, aHost);
    assert.equal(await handoffs.exchangeHandoff(wrongHost, bHost), null);
    assert.equal(await handoffs.exchangeHandoff(wrongHost, aHost), null, "consumed by the failed attempt");

    const once = await handoffs.createHandoff(platform.sessionId, aHost);
    assert.ok(await handoffs.exchangeHandoff(once, aHost));
    assert.equal(await handoffs.exchangeHandoff(once, aHost), null);

    const expired = await handoffs.createHandoff(platform.sessionId, aHost);
    await pool.query(`UPDATE auth_handoffs SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute' WHERE consumed_at IS NULL`);
    assert.equal(await handoffs.exchangeHandoff(expired, aHost), null);

    const revoked = await handoffs.createHandoff(platform.sessionId, aHost);
    await sessions.revokeSessionById(platform.sessionId);
    assert.equal(await handoffs.exchangeHandoff(revoked, aHost), null, "the platform session ended");
  });
});

// ---- Hostnames and registration ----------------------------------------------------

describe("hostnames and registration", () => {
  test("unknown hosts are rejected, never defaulted", async () => {
    assert.equal(await domains.resolveTenantByHostname("nobody.localhost"), null);
    const response = await tenantRequest("nobody.localhost", "/tenant/context");
    assert.equal(response.statusCode, 404);
    assert.equal(response.json().error, "TENANT_NOT_FOUND");
  });

  test("forwarded hosts from untrusted addresses are ignored", async () => {
    const org = await register(uniqueSlug("trust"));
    await drainWorker();
    const host = (await domains.primaryPlatformDomain(org.tenantId))!.hostname;
    const response = await app.inject({
      method: "GET",
      url: "/tenant/context",
      remoteAddress: "10.1.2.3",
      headers: { "x-forwarded-host": host },
    });
    assert.equal(response.statusCode, 404);
  });

  test("duplicate slugs and reserved names are refused", async () => {
    const slug = uniqueSlug("dup");
    await register(slug);
    await assert.rejects(register(slug), (e: { code?: string }) => e.code === "SLUG_ALREADY_EXISTS");
    for (const reserved of ["admin", "api", "auth", "www", "bmms-check-x"]) {
      await assert.rejects(register(reserved), (e: { code?: string }) => e.code === "RESERVED_SLUG", reserved);
    }
  });

  test("hostnames are unique across organizations", async () => {
    const org = await register(uniqueSlug("host"));
    const hostname = (await domains.primaryPlatformDomain(org.tenantId))!.hostname;
    await assert.rejects(
      pool.query(`INSERT INTO tenant_domains (tenant_id, hostname, domain_type) SELECT id, $1, 'platform' FROM tenants WHERE id <> $2 LIMIT 1`, [hostname, org.tenantId]),
      (e: { code?: string }) => e.code === "23505",
    );
  });

  test("duplicate submissions create one organization", async () => {
    const slug = uniqueSlug("idem");
    const key = randomUUID();
    const results = await Promise.all([register(slug, key), register(slug, key), register(slug, key)]);
    assert.equal(new Set(results.map((r) => r.tenantId)).size, 1);
    assert.equal(new Set(results.map((r) => r.jobId)).size, 1);
    const count = (await pool.query(`SELECT count(*)::int AS n FROM tenants WHERE slug = $1`, [slug])).rows[0].n;
    assert.equal(count, 1);
    await assert.rejects(
      organizations.createOrganization({ name: "Other", slug, secretaryEmail: "x@example.com" }, key, await admin()),
      (e: { code?: string }) => e.code === "IDEMPOTENCY_CONFLICT",
    );
    assert.ok(registration);
  });
});

// ---- Failures, retries and recovery --------------------------------------------------

describe("failures, retries and recovery", () => {
  // Each test claims its own job: start with nothing else due.
  beforeEach(() => drainWorker());

  test("a failing domain check retries with backoff and keeps finished steps", async () => {
    const org = await register(uniqueSlug("retry"));
    routingOverride = randomUUID(); // the "frontend" now routes to a different organization
    try {
      const job = await worker.claimNextProvisioningJob("retry-worker");
      assert.equal(job?.id, org.jobId);
      assert.equal(await runner.processJob(job!), "retry");
    } finally {
      routingOverride = null;
    }

    const failed = await jobRow(org.jobId);
    assert.equal(failed.status, "pending");
    assert.equal(failed.last_error_code, "DOMAIN_NOT_READY");
    assert.ok(new Date(failed.next_run_at).getTime() > Date.now(), "backoff before the next attempt");
    const domain = (await pool.query(`SELECT status, last_error_code FROM tenant_domains WHERE tenant_id = $1`, [org.tenantId])).rows[0];
    assert.deepEqual(domain, { status: "failed", last_error_code: "ROUTING_WRONG_ORGANIZATION" });
    assert.equal((await stepRows(org.jobId)).configure_domain!.status, "failed");

    await pool.query(`UPDATE provisioning_jobs SET next_run_at = now() WHERE id = $1`, [org.jobId]);
    await drainWorker();

    assert.equal((await jobRow(org.jobId)).status, "succeeded");
    const after = await stepRows(org.jobId);
    assert.equal(after.create_database!.attempts, 1, "the database wasn't provisioned twice");
    assert.equal(after.configure_domain!.attempts, 2);
  });

  test("a worker that crashes mid-job is recovered by another, with fencing", async () => {
    const org = await register(uniqueSlug("crash"));
    const first = await worker.claimNextProvisioningJob("worker-1");
    assert.equal(first?.id, org.jobId);
    await createStep.runCreateDatabaseStep(first!, new AbortController().signal);

    // worker-1 dies: its lease runs out.
    await pool.query(`UPDATE provisioning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, [org.jobId]);

    const second = await worker.claimNextProvisioningJob("worker-2");
    assert.equal(second?.id, org.jobId);
    assert.equal(await runner.processJob(second!), "succeeded");

    // The old worker can no longer change anything.
    await assert.rejects(steps.startProvisioningStep(first!, "configure_credentials"), steps.ProvisioningLeaseLostError);

    const all = await stepRows(org.jobId);
    assert.equal(all.create_database!.attempts, 1);
    assert.ok(Object.values(all).every((s) => s.status === "succeeded"));
  });

  test("two workers never run the same job", async () => {
    const org = await register(uniqueSlug("race"));
    const claims = await Promise.all([worker.claimNextProvisioningJob("w-a"), worker.claimNextProvisioningJob("w-b")]);
    assert.equal(claims.filter((c) => c?.id === org.jobId).length, 1);
    await runner.processJob(claims.find((c) => c?.id === org.jobId)!);
    await drainWorker();
  });

  test("a failed job is retried only on request, resuming where it stopped", async () => {
    const org = await register(uniqueSlug("manual"));
    routingOverride = randomUUID();
    try {
      for (let i = 0; i < 5; i++) {
        await pool.query(`UPDATE provisioning_jobs SET next_run_at = now() WHERE id = $1`, [org.jobId]);
        const job = await worker.claimNextProvisioningJob("exhaust");
        if (!job) break;
        await runner.processJob(job);
      }
    } finally {
      routingOverride = null;
    }
    assert.equal((await jobRow(org.jobId)).status, "failed");
    assert.equal((await pool.query(`SELECT status FROM tenants WHERE id = $1`, [org.tenantId])).rows[0].status, "failed");
    assert.equal(await jobs.retryFailedJob(randomUUID()), "not_found");

    // Unauthenticated retry is refused.
    const anonymous = await app.inject({ method: "POST", url: `/admin/provisioning-jobs/${org.jobId}/retry` });
    assert.equal(anonymous.statusCode, 401);

    assert.equal(await jobs.retryFailedJob(org.jobId), "retried");
    assert.equal(await jobs.retryFailedJob(org.jobId), "not_failed");
    await drainWorker();
    const done = await stepRows(org.jobId);
    assert.equal((await jobRow(org.jobId)).status, "succeeded");
    assert.equal(done.create_database!.attempts, 1);
  });

  test("an invitation delivery failure doesn't touch provisioning", async () => {
    const org = await register(uniqueSlug("mail"));
    const saved = process.env.EMAIL_DELIVERY;
    process.env.EMAIL_DELIVERY = "smtp";
    const host = process.env.SMTP_HOST;
    delete process.env.SMTP_HOST;
    try {
      await drainWorker();
    } finally {
      process.env.EMAIL_DELIVERY = saved;
      if (host !== undefined) process.env.SMTP_HOST = host;
    }
    assert.equal((await jobRow(org.jobId)).status, "succeeded");
    const delivery = (
      await pool.query(
        `SELECT d.status, d.attempts, d.last_error_code FROM invitation_deliveries d JOIN tenant_invitations i ON i.id = d.invitation_id WHERE i.tenant_id = $1`,
        [org.tenantId],
      )
    ).rows[0];
    assert.equal(delivery.status, "queued", "rescheduled, not failed provisioning");
    assert.equal(delivery.last_error_code, "EMAIL_DELIVERY_UNCONFIRMED");
    assert.ok(Object.values(await stepRows(org.jobId)).every((s) => s.attempts === 1));
  });
});

// ---- Production provider ---------------------------------------------------------------

describe("production domain provider", () => {
  const notFound = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  const resolver = (addresses: string[] | null, txt: string[][] = []) => ({
    resolve4: async () => (addresses ? addresses : Promise.reject(notFound)),
    resolve6: async () => Promise.reject(notFound),
    resolveTxt: async () => (txt.length ? txt : Promise.reject(notFound)),
  });

  let tls: { cert: string; key: string; port: number; server: https.Server; tenantId: string };

  before(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "bmms-tls-"));
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-subj", "/CN=org.bmms.example",
      "-addext", "subjectAltName=DNS:org.bmms.example,DNS:*.bmms.example",
      "-keyout", path.join(dir, "key.pem"), "-out", path.join(dir, "cert.pem"),
    ], { stdio: "ignore" });
    const cert = await readFile(path.join(dir, "cert.pem"), "utf8");
    const key = await readFile(path.join(dir, "key.pem"), "utf8");
    await rm(dir, { recursive: true, force: true });
    const tenantId = randomUUID();
    const server = https.createServer({ cert, key }, (req, res) => {
      const host = (req.headers.host ?? "").split(":")[0];
      res.writeHead(host === "org.bmms.example" ? 200 : 404, { "content-type": "application/json" });
      res.end(JSON.stringify(host === "org.bmms.example" ? { hostname: host, organizationId: tenantId } : { error: "TENANT_NOT_FOUND" }));
    });
    tls = { cert, key, server, tenantId, port: await listen(server) };
  });

  after(() => tls?.server.close());

  const provider = (addresses: string[] | null, options: { ca?: boolean } = {}) =>
    new providers.ProductionDomainProvider({
      baseDomain: "bmms.example",
      ingressAddresses: ["127.0.0.1"],
      httpsPort: tls.port,
      resolver: resolver(addresses),
      ...(options.ca ? { ca: tls.cert } : {}),
    });

  test("missing DNS is pending, with an actionable code", async () => {
    const check = await provider(null).verifyHostname("org.bmms.example", tls.tenantId);
    assert.deepEqual([check.status, check.errorCode], ["pending", "DNS_NOT_FOUND"]);
    const platform = await provider(null).checkPlatform();
    assert.deepEqual([platform.status, platform.errorCode], ["pending", "WILDCARD_DNS_MISSING"]);
  });

  test("DNS pointing elsewhere fails, and nothing is contacted", async () => {
    const check = await provider(["10.0.0.9"]).verifyHostname("org.bmms.example", tls.tenantId);
    assert.deepEqual([check.status, check.errorCode], ["failed", "DNS_NOT_INGRESS"]);
  });

  test("an untrusted certificate fails TLS", async () => {
    const check = await provider(["127.0.0.1"]).verifyHostname("org.bmms.example", tls.tenantId);
    assert.deepEqual([check.status, check.errorCode, check.tlsVerified], ["failed", "TLS_INVALID", false]);
  });

  test("valid DNS, TLS and routing activate; the wrong organization doesn't", async () => {
    const ok = await provider(["127.0.0.1"], { ca: true }).verifyHostname("org.bmms.example", tls.tenantId);
    assert.deepEqual([ok.status, ok.routingVerified, ok.tlsVerified], ["active", true, true]);
    const wrong = await provider(["127.0.0.1"], { ca: true }).verifyHostname("org.bmms.example", randomUUID());
    assert.deepEqual([wrong.status, wrong.errorCode], ["failed", "ROUTING_WRONG_ORGANIZATION"]);
    const platform = await provider(["127.0.0.1"], { ca: true }).checkPlatform();
    assert.equal(platform.status, "active", "an unknown wildcard name reaches the app and is refused by it");
  });

  test("hostnames outside the platform domain aren't checked as subdomains", async () => {
    const check = await provider(["127.0.0.1"]).verifyHostname("evil.example.com", tls.tenantId);
    assert.deepEqual([check.status, check.errorCode], ["failed", "HOSTNAME_OUTSIDE_BASE_DOMAIN"]);
  });

  test("custom domains need the ownership record first", async () => {
    const check = await provider(["127.0.0.1"]).verifyCustomDomain("board.customer.example", tls.tenantId, "token-value-0123456789abcdefghijkl");
    assert.deepEqual([check.status, check.errorCode], ["pending", "OWNERSHIP_RECORD_MISSING"]);
  });

  test("local provider configuration is refused in production", () => {
    assert.throws(() => providers.createDomainProviderFromEnv({ NODE_ENV: "production", DOMAIN_PROVIDER: "local" }), /not allowed in production/);
    assert.throws(() => providers.createDomainProviderFromEnv({ NODE_ENV: "production" }), /DOMAIN_PROVIDER/);
    assert.throws(
      () => providers.createDomainProviderFromEnv({ NODE_ENV: "production", DOMAIN_PROVIDER: "production", PLATFORM_BASE_DOMAIN: "bmms.example" }),
      /PLATFORM_INGRESS_ADDRESSES/,
    );
    assert.throws(() => storage.createStorageProviderFromEnv({ NODE_ENV: "production", STORAGE_PROVIDER: "local" }), /not allowed in production/);
  });
});

describe("custom domains (local provider)", () => {
  test("are registered as pending and never activated locally", async () => {
    const org = await register(uniqueSlug("custom"));
    const added = await domains.addCustomDomain(org.tenantId, "board.customer.example");
    assert.equal(added.status, "pending");
    const check = await providers.domainProvider().verifyCustomDomain(added.hostname, org.tenantId, added.ownershipToken);
    assert.deepEqual([check.status, check.errorCode], ["failed", "CUSTOM_DOMAINS_REQUIRE_PRODUCTION_PROVIDER"]);
    await domains.recordDomainCheck(added.id, check);
    assert.equal((await domains.getCustomDomain(org.tenantId, added.id))?.status, "failed");
    assert.equal(await domains.resolveTenantByHostname("board.customer.example", "registered"), null, "not routed before activation");
    await assert.rejects(
      pool.query(`UPDATE tenant_domains SET status = 'active' WHERE id = $1`, [added.id]),
      (e: { code?: string }) => e.code === "23514",
      "the database refuses activation without proof",
    );
  });
});
