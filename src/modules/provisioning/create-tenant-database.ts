import { provisioningPool } from "./provisioning.db.js";
import {
  getTenantResourceNames,
  quoteResourceIdentifier,
  type TenantResourceNames,
} from "./tenant-resource-names.js";

export async function createTenantDatabase(
  tenantId: string,
  signal: AbortSignal,
): Promise<TenantResourceNames> {
  const names = getTenantResourceNames(tenantId);
  const database = quoteResourceIdentifier(names.database);
  const owner = quoteResourceIdentifier(names.ownerRole);

  signal.throwIfAborted();

  const client = await provisioningPool.connect();

  try {
    // A session lock protects infrastructure setup across worker retries.
    // All provisioning workers must use the same maintenance database.
    const lock = await client.query<{ acquired: boolean }>(
      `
      SELECT pg_try_advisory_lock(
        hashtextextended($1::text, 0)
      ) AS acquired
      `,
      [`tenant-setup:${names.database}`],
    );

    if (!lock.rows[0]?.acquired) {
      throw new Error("Tenant resource setup is already in progress.");
    }

    signal.throwIfAborted();

    const existingOwner = await client.query<{
      safe: boolean;
    }>(
      `
      SELECT (
        NOT rolcanlogin
        AND NOT rolsuper
        AND NOT rolcreatedb
        AND NOT rolcreaterole
        AND NOT rolreplication
        AND NOT rolbypassrls
      ) AS safe
      FROM pg_roles
      WHERE rolname = $1
      `,
      [names.ownerRole],
    );

    if (existingOwner.rows.length === 0) {
      signal.throwIfAborted();

      await client.query(`
        CREATE ROLE ${owner}
        NOLOGIN
        NOSUPERUSER
        NOCREATEDB
        NOCREATEROLE
        NOREPLICATION
        NOBYPASSRLS
      `);
    } else if (!existingOwner.rows[0]?.safe) {
      throw new Error("Existing tenant owner role has unsafe attributes.");
    }

    signal.throwIfAborted();

    const existingDatabase = await client.query<{
      ownerRole: string;
      isTemplate: boolean;
    }>(
      `
      SELECT
        pg_get_userbyid(datdba) AS "ownerRole",
        datistemplate AS "isTemplate"
      FROM pg_database
      WHERE datname = $1
      `,
      [names.database],
    );

    const current = existingDatabase.rows[0];

    if (current) {
      // Never take ownership of an unexpected database.
      if (
        current.ownerRole !== names.ownerRole ||
        current.isTemplate
      ) {
        throw new Error("Existing tenant database ownership is unexpected.");
      }
    } else {
      signal.throwIfAborted();

      await client.query(`
        CREATE DATABASE ${database}
        WITH
          OWNER = ${owner}
          TEMPLATE = template0
          ALLOW_CONNECTIONS = false
      `);
    }

    signal.throwIfAborted();

    // Remove PostgreSQL's default public database privileges.
    // Repeating this is safe after an interrupted setup.
    await client.query(`
      REVOKE ALL PRIVILEGES
      ON DATABASE ${database}
      FROM PUBLIC
    `);

    signal.throwIfAborted();

    await client.query(`
      ALTER DATABASE ${database}
      ALLOW_CONNECTIONS = true
    `);

    signal.throwIfAborted();

    return names;
  } finally {
    // Destroy this connection so its session advisory lock is released.
    // Never return a connection holding a session lock to the pool.
    client.release(true);
  }
}