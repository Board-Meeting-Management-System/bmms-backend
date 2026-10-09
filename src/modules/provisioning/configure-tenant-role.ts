import pg from "pg";

import { provisioningPool } from "./provisioning.db.js";
import { createPostgresPasswordVerifier } from "./postgres-password.js";
import {
  getTenantResourceNames,
  quoteResourceIdentifier,
} from "./tenant-resource-names.js";
import type { TenantDatabaseCredentials } from "./tenant-secret.repository.js";

export async function configureTenantRole(
  tenantId: string,
  credentials: TenantDatabaseCredentials,
  signal: AbortSignal,
): Promise<void> {
  const names = getTenantResourceNames(tenantId);

  if (credentials.username !== names.runtimeRole) {
    throw new Error("Tenant runtime username does not match.");
  }

  signal.throwIfAborted();

  const verifier = await createPostgresPasswordVerifier(
    credentials.password,
  );

  const role = quoteResourceIdentifier(names.runtimeRole);
  const database = quoteResourceIdentifier(names.database);
  const passwordLiteral = pg.escapeLiteral(verifier);

  signal.throwIfAborted();

  const client = await provisioningPool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL statement_timeout = '5s'");

    // Uses the same resource lock as database creation.
    const lock = await client.query<{ acquired: boolean }>(
      `
      SELECT pg_try_advisory_xact_lock(
        hashtextextended($1::text, 0)
      ) AS acquired
      `,
      [`tenant-setup:${names.database}`],
    );

    if (!lock.rows[0]?.acquired) {
      throw new Error("Tenant resource setup is already in progress.");
    }

    signal.throwIfAborted();

    const databaseCheck = await client.query(
      `
      SELECT datname
      FROM pg_database
      WHERE datname = $1
        AND pg_get_userbyid(datdba) = $2
        AND NOT datistemplate
        AND datallowconn
      `,
      [names.database, names.ownerRole],
    );

    if (databaseCheck.rowCount !== 1) {
      throw new Error("Tenant database is missing or unexpected.");
    }

    const existing = await client.query<{ safe: boolean }>(
      `
      SELECT (
        NOT role.rolsuper
        AND NOT role.rolcreatedb
        AND NOT role.rolcreaterole
        AND NOT role.rolreplication
        AND NOT role.rolbypassrls
        AND NOT EXISTS (
          SELECT 1
          FROM pg_auth_members AS membership
          WHERE membership.member = role.oid
             OR membership.roleid = role.oid
        )
        AND NOT EXISTS (
          SELECT 1
          FROM pg_database AS database
          WHERE database.datdba = role.oid
        )
      ) AS safe
      FROM pg_roles AS role
      WHERE role.rolname = $1
      `,
      [names.runtimeRole],
    );

    const current = existing.rows[0];

    if (current && !current.safe) {
      throw new Error(
        "Existing runtime role has unexpected privileges or memberships.",
      );
    }

    signal.throwIfAborted();

    if (!current) {
      await client.query(`
        CREATE ROLE ${role}
        NOLOGIN
        NOSUPERUSER
        NOCREATEDB
        NOCREATEROLE
        NOINHERIT
        NOREPLICATION
        NOBYPASSRLS
      `);
    }

    // Reuses the persisted password on retries.
    // Never log this SQL or the verifier.
    await client.query(`
      ALTER ROLE ${role}
      WITH
        LOGIN
        NOSUPERUSER
        NOCREATEDB
        NOCREATEROLE
        NOINHERIT
        NOREPLICATION
        NOBYPASSRLS
        CONNECTION LIMIT 10
        PASSWORD ${passwordLiteral}
        VALID UNTIL 'infinity'
    `);

    signal.throwIfAborted();

    await client.query(`
      REVOKE ALL PRIVILEGES
      ON DATABASE ${database}
      FROM PUBLIC
    `);

    await client.query(`
      REVOKE ALL PRIVILEGES
      ON DATABASE ${database}
      FROM ${role}
    `);

    await client.query(`
      GRANT CONNECT
      ON DATABASE ${database}
      TO ${role}
    `);

    signal.throwIfAborted();

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    // Close the maintenance connection after this operation.
    client.release(true);
  }
}