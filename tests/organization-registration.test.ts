// Integration tests for POST /admin/tenants against a running API.
//
// Requires:
//   - the API running (npm run dev)
//   - BMMS_SESSION: the bmms_session cookie of a platform admin
//     (sign in at /auth/login, copy it from browser DevTools)
//   - optional BMMS_USER_SESSION: the cookie of a non-admin user
//
// Run: BMMS_SESSION=... npm run test:registration
//
// Every tenant created here uses a per-run slug prefix and is deleted afterwards.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, describe, test } from "node:test";

import { pool } from "../src/db.js";

const apiUrl = process.env.API_URL ?? "http://localhost:3001";
const origin = new URL(
  process.env.FRONTEND_ORIGIN ?? "http://localhost:5173",
).origin;
const baseDomain = process.env.PLATFORM_BASE_DOMAIN?.trim().toLowerCase();
const adminSession = process.env.BMMS_SESSION?.trim();
const userSession = process.env.BMMS_USER_SESSION?.trim();

// Unique per run, so reruns never collide with earlier data.
const prefix = `t${Date.now().toString(36)}`;

interface RequestOptions {
  key?: string | null;
  origin?: string | null;
  session?: string | null;
}

async function register(
  body: unknown,
  options: RequestOptions = {},
): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  const key = options.key === undefined ? randomUUID() : options.key;
  const requestOrigin =
    options.origin === undefined ? origin : options.origin;
  const session =
    options.session === undefined ? adminSession : options.session;

  if (key !== null) headers["Idempotency-Key"] = key;
  if (requestOrigin !== null) headers["Origin"] = requestOrigin;
  if (session) headers["Cookie"] = `bmms_session=${session}`;

  const response = await fetch(`${apiUrl}/admin/tenants`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  return {
    status: response.status,
    body: await response.json().catch(() => null),
  };
}

function org(slug: string, overrides: Record<string, unknown> = {}) {
  return {
    name: "Test Organization",
    slug,
    secretaryEmail: "secretary@example.com",
    ...overrides,
  };
}

before(async () => {
  assert.ok(baseDomain, "PLATFORM_BASE_DOMAIN must be set (run with --env-file=.env)");
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
    user: { isPlatformAdmin: boolean };
  };

  assert.ok(user.isPlatformAdmin, "BMMS_SESSION must belong to a platform admin");
});

after(async () => {
  // Delete in foreign-key order.
  const tenants = `SELECT id FROM tenants WHERE slug LIKE $1`;
  const pattern = [`${prefix}%`];

  await pool.query(
    `DELETE FROM provisioning_steps
     WHERE job_id IN (SELECT id FROM provisioning_jobs WHERE tenant_id IN (${tenants}))`,
    pattern,
  );
  await pool.query(`DELETE FROM provisioning_jobs WHERE tenant_id IN (${tenants})`, pattern);
  await pool.query(`DELETE FROM tenant_invitations WHERE tenant_id IN (${tenants})`, pattern);
  await pool.query(`DELETE FROM tenant_domains WHERE tenant_id IN (${tenants})`, pattern);
  await pool.query(`DELETE FROM tenant_resources WHERE tenant_id IN (${tenants})`, pattern);
  await pool.query(`DELETE FROM tenants WHERE slug LIKE $1`, pattern);

  await pool.end();
});

describe("successful registration", () => {
  const slug = `${prefix}-acme`;
  let result: { tenantId: string; jobId: string };

  test("returns 202 with tenant and job ids", async () => {
    const response = await register(
      org(slug, {
        name: "  Acme Corporation  ",
        secretaryEmail: "Secretary@Example.COM",
      }),
    );

    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.equal(response.body.status, "provisioning");
    assert.match(response.body.tenantId, /^[0-9a-f-]{36}$/);
    assert.match(response.body.jobId, /^[0-9a-f-]{36}$/);

    result = response.body;
  });

  test("stores the tenant with a trimmed name", async () => {
    const { rows } = await pool.query(
      `SELECT name, slug, status, created_by FROM tenants WHERE id = $1`,
      [result.tenantId],
    );

    assert.equal(rows.length, 1);
    assert.equal(rows[0].name, "Acme Corporation");
    assert.equal(rows[0].slug, slug);
    assert.equal(rows[0].status, "provisioning");
    assert.ok(rows[0].created_by);
  });

  test("stores the platform hostname as slug + base domain", async () => {
    const { rows } = await pool.query(
      `SELECT hostname, domain_type, status, is_primary
       FROM tenant_domains WHERE tenant_id = $1`,
      [result.tenantId],
    );

    assert.deepEqual(rows, [
      {
        hostname: `${slug}.${baseDomain}`,
        domain_type: "platform",
        status: "pending",
        is_primary: true,
      },
    ]);
  });

  test("stores a lowercase secretary invitation waiting for setup", async () => {
    const { rows } = await pool.query(
      `SELECT email, role, status, token_hash
       FROM tenant_invitations WHERE tenant_id = $1`,
      [result.tenantId],
    );

    assert.deepEqual(rows, [
      {
        email: "secretary@example.com",
        role: "secretary",
        status: "pending_setup",
        token_hash: null,
      },
    ]);
  });

  test("creates a pending job with all six provisioning steps", async () => {
    const jobs = await pool.query(
      `SELECT status FROM provisioning_jobs WHERE id = $1 AND tenant_id = $2`,
      [result.jobId, result.tenantId],
    );
    const steps = await pool.query(
      `SELECT step_name FROM provisioning_steps
       WHERE job_id = $1 AND status = 'pending' ORDER BY step_name`,
      [result.jobId],
    );

    assert.equal(jobs.rows[0]?.status, "pending");
    assert.deepEqual(
      steps.rows.map((row) => row.step_name),
      [
        "activate_tenant",
        "configure_credentials",
        "configure_encryption",
        "create_database",
        "migrate_tenant",
        "verify_resources",
      ],
    );
  });

  test("rejects the same slug with 409 SLUG_ALREADY_EXISTS", async () => {
    const response = await register(org(slug));

    assert.equal(response.status, 409);
    assert.equal(response.body.error, "SLUG_ALREADY_EXISTS");
  });

  test("rejects a hostname already assigned elsewhere with 409 DOMAIN_ALREADY_EXISTS", async () => {
    // Only reachable once custom domains exist, so claim the hostname directly.
    const taken = `${prefix}-taken`;

    await pool.query(
      `INSERT INTO tenant_domains (tenant_id, hostname, domain_type, is_primary)
       VALUES ($1, $2, 'custom', FALSE)`,
      [result.tenantId, `${taken}.${baseDomain}`],
    );

    const response = await register(org(taken));

    assert.equal(response.status, 409);
    assert.equal(response.body.error, "DOMAIN_ALREADY_EXISTS");

    const { rowCount } = await pool.query(
      `SELECT 1 FROM tenants WHERE slug = $1`,
      [taken],
    );
    assert.equal(rowCount, 0, "the failed registration must roll back");
  });
});

describe("slug validation", () => {
  const reserved = [
    "admin", "api", "app", "auth", "dashboard", "keycloak",
    "login", "mail", "static", "status", "support", "www",
  ];

  for (const slug of reserved) {
    test(`rejects reserved slug "${slug}" with RESERVED_SLUG`, async () => {
      const response = await register(org(slug));

      assert.equal(response.status, 400);
      assert.equal(response.body.error, "RESERVED_SLUG");
    });
  }

  const invalid: Array<[string, string]> = [
    ["too short", "ab"],
    ["longer than 63 characters", "a".repeat(64)],
    ["uppercase letters", `${prefix}-ABC`],
    ["leading hyphen", `-${prefix}`],
    ["trailing hyphen", `${prefix}-`],
    ["double hyphen", `${prefix}--x`],
    ["underscore", `${prefix}_x`],
    ["dot", `${prefix}.x`],
    ["space", `${prefix} x`],
    ["non-ASCII letter", `${prefix}-café`],
  ];

  for (const [reason, slug] of invalid) {
    test(`rejects slug with ${reason}`, async () => {
      const response = await register(org(slug));

      assert.equal(response.status, 400, JSON.stringify(response.body));
    });
  }

  test("accepts a 63-character slug", async () => {
    const slug = `${prefix}-${"a".repeat(62 - prefix.length)}`;
    assert.equal(slug.length, 63);

    const response = await register(org(slug));

    assert.equal(response.status, 202, JSON.stringify(response.body));
  });
});

describe("name and email validation", () => {
  const cases: Array<[string, Record<string, unknown>, string?]> = [
    ["blank name", { name: "   " }],
    ["name that is 1 character after trimming", { name: "  A  " }, "INVALID_NAME"],
    ["name over 150 characters", { name: "A".repeat(151) }],
    ["invalid email", { secretaryEmail: "not-an-email" }],
    ["email over 254 characters", { secretaryEmail: `${"a".repeat(250)}@x.io` }],
    ["missing email", { secretaryEmail: undefined }],
    ["unknown field", { plan: "enterprise" }],
  ];

  for (const [reason, overrides, code] of cases) {
    test(`rejects ${reason}`, async () => {
      const response = await register(org(`${prefix}-field`, overrides));

      assert.equal(response.status, 400, JSON.stringify(response.body));
      if (code) assert.equal(response.body.error, code);
    });
  }
});

describe("idempotency", () => {
  test("replays the original result for the same key and body", async () => {
    const key = randomUUID();
    const body = org(`${prefix}-idem`);

    const first = await register(body, { key });
    const second = await register(body, { key });

    assert.equal(first.status, 202, JSON.stringify(first.body));
    assert.equal(second.status, 202, JSON.stringify(second.body));
    assert.deepEqual(second.body, first.body);
  });

  test("treats an uppercase key as the same key", async () => {
    const key = randomUUID();
    const body = org(`${prefix}-idem-case`);

    const first = await register(body, { key });
    const second = await register(body, { key: key.toUpperCase() });

    assert.equal(first.status, 202);
    assert.deepEqual(second.body, first.body);
  });

  test("rejects the same key with a different body", async () => {
    const key = randomUUID();

    const first = await register(org(`${prefix}-idem-a`), { key });
    const second = await register(org(`${prefix}-idem-b`), { key });

    assert.equal(first.status, 202);
    assert.equal(second.status, 409);
    assert.equal(second.body.error, "IDEMPOTENCY_CONFLICT");
  });

  test("requires the Idempotency-Key header", async () => {
    const response = await register(org(`${prefix}-nokey`), { key: null });

    assert.equal(response.status, 400);
  });

  test("rejects a key that is not a UUID", async () => {
    const response = await register(org(`${prefix}-badkey`), { key: "retry-1" });

    assert.equal(response.status, 400);
  });
});

describe("access control", () => {
  test("rejects a request without a session", async () => {
    const response = await register(org(`${prefix}-anon`), { session: null });

    assert.equal(response.status, 401);
    assert.equal(response.body.error, "UNAUTHORIZED");
  });

  test("rejects a request without an Origin header", async () => {
    const response = await register(org(`${prefix}-noorigin`), { origin: null });

    assert.equal(response.status, 403);
    assert.equal(response.body.error, "ORIGIN_NOT_ALLOWED");
  });

  test("rejects a request from another origin", async () => {
    const response = await register(org(`${prefix}-evil`), {
      origin: "http://evil.example",
    });

    assert.equal(response.status, 403);
    assert.equal(response.body.error, "ORIGIN_NOT_ALLOWED");
  });

  test(
    "rejects a signed-in user who is not a platform admin",
    { skip: !userSession && "set BMMS_USER_SESSION to run" },
    async () => {
      const response = await register(org(`${prefix}-user`), {
        session: userSession,
      });

      assert.equal(response.status, 403);
      assert.equal(response.body.error, "FORBIDDEN");
    },
  );
});
