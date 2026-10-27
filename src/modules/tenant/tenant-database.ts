import pg from "pg";

import { pool } from "../../db.js";
import { getTenantResourceNames } from "../provisioning/tenant-resource-names.js";
import { readCredentials } from "../provisioning/tenant-secret.repository.js";
import type { EncryptedTenantSecret } from "../provisioning/tenant-secret.crypto.js";

// Connections to an organization's own database, as its restricted runtime
// role. The database is chosen only from server-side records for a tenant id
// that was itself resolved from the request hostname — never from a value in
// the request. Pools are cached per tenant id.

const pools = new Map<string, Promise<pg.Pool>>();

async function openPool(tenantId: string): Promise<pg.Pool> {
  const names = getTenantResourceNames(tenantId);

  const resources = await pool.query<{
    host: string | null;
    port: number | null;
    database: string | null;
    runtimeRole: string | null;
    secretRef: string | null;
  }>(
    `
    SELECT
      resource.database_host AS host,
      resource.database_port AS port,
      resource.database_name AS database,
      resource.runtime_role_ref AS "runtimeRole",
      resource.database_secret_ref AS "secretRef"
    FROM tenant_resources AS resource
    JOIN tenants AS tenant ON tenant.id = resource.tenant_id
    WHERE resource.tenant_id = $1 AND tenant.status = 'active'
    `,
    [tenantId],
  );
  const resource = resources.rows[0];

  if (
    !resource?.host ||
    resource.port === null ||
    resource.database !== names.database ||
    resource.runtimeRole !== names.runtimeRole ||
    !resource.secretRef
  ) {
    throw new Error("Tenant database is not available.");
  }

  // Same guard as provisioning verification: remote connections need
  // verified TLS, which isn't configured yet.
  if (process.env.NODE_ENV !== "development" || !["127.0.0.1", "localhost", "::1"].includes(resource.host)) {
    throw new Error("Configure verified TLS before using remote tenant connections.");
  }

  const secrets = await pool.query<EncryptedTenantSecret & { id: string }>(
    `
    SELECT id, key_version AS "keyVersion", ciphertext, nonce, auth_tag AS "authTag"
    FROM tenant_secrets
    WHERE tenant_id = $1
      AND purpose = 'database_credentials'
      AND ('local-db:' || id::text) = $2
    `,
    [tenantId, resource.secretRef],
  );
  const secret = secrets.rows[0];
  if (!secret) throw new Error("Tenant database credentials are missing.");

  const credentials = readCredentials(tenantId, secret);

  const tenantPool = new pg.Pool({
    host: resource.host,
    port: resource.port,
    database: resource.database,
    user: credentials.username,
    password: credentials.password,
    application_name: "bmms-api-tenant",
    max: 3,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 10_000,
  });
  tenantPool.on("error", () => console.error("Tenant database connection error."));
  return tenantPool;
}

/** The organization's database pool. Callers pass a tenant id from tenant context. */
export function tenantDatabase(tenantId: string): Promise<pg.Pool> {
  let existing = pools.get(tenantId);
  if (!existing) {
    existing = openPool(tenantId);
    pools.set(tenantId, existing);
    // Don't cache failures.
    existing.catch(() => pools.delete(tenantId));
  }
  return existing;
}

export async function closeTenantDatabases(): Promise<void> {
  const all = [...pools.values()];
  pools.clear();
  await Promise.allSettled(all.map(async (p) => (await p).end()));
}
