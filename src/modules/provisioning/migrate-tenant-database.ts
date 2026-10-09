import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import pg from "pg";

import { provisioningPool } from "./provisioning.db.js";
import {
  getTenantResourceNames,
  quoteResourceIdentifier,
} from "./tenant-resource-names.js";

interface Migration {
  name: string;
  sql: string;
  checksum: string;
}

async function loadTenantMigrations(): Promise<Migration[]> {
  const directory = path.resolve("migrations/tenant");
  const files = await readdir(directory);

  const names = files
    .filter((name) => /^\d{3}_[a-z0-9_]+\.sql$/.test(name))
    .sort();

  if (names.length === 0) {
    throw new Error("No tenant migrations found.");
  }

  const migrations: Migration[] = [];

  for (const name of names) {
    const sql = await readFile(path.join(directory, name), "utf8");

    migrations.push({
      name,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex"),
    });
  }

  return migrations;
}

export async function migrateTenantDatabase(
  tenantId: string,
  signal: AbortSignal,
): Promise<string> {
  const names = getTenantResourceNames(tenantId);
  const owner = quoteResourceIdentifier(names.ownerRole);
  const runtimeRole = quoteResourceIdentifier(names.runtimeRole);
  const migrations = await loadTenantMigrations();

  signal.throwIfAborted();

  const maintenance = await provisioningPool.connect();
  let tenantClient: pg.Client | undefined;

  try {
    const lock = await maintenance.query<{ acquired: boolean }>(
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

    const databaseCheck = await maintenance.query(
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

    signal.throwIfAborted();

    // Reuse the provisioning connection settings, targeting this database.
    const connectionUrl = new URL(
      process.env.PROVISIONING_DATABASE_URL!,
    );
    connectionUrl.pathname = `/${names.database}`;

    tenantClient = new pg.Client({
      connectionString: connectionUrl.toString(),
      application_name: "bmms-tenant-migrations",
      connectionTimeoutMillis: 5_000,
    });

    // Avoid logging connection details from idle connection errors.
    tenantClient.on("error", () => {
      console.error("Tenant migration connection failed.");
    });

    await tenantClient.connect();
    await tenantClient.query("BEGIN");

    try {
      await tenantClient.query("SET LOCAL lock_timeout = '5s'");
      await tenantClient.query("SET LOCAL statement_timeout = '60s'");

      // All migration objects must belong to the tenant owner.
      await tenantClient.query(`SET LOCAL ROLE ${owner}`);
      await tenantClient.query("SET LOCAL search_path = pg_catalog");

      await tenantClient.query(`
        CREATE SCHEMA IF NOT EXISTS bmms_internal
      `);

      await tenantClient.query(`
        REVOKE ALL ON SCHEMA bmms_internal FROM PUBLIC
      `);

      await tenantClient.query(`
        CREATE TABLE IF NOT EXISTS bmms_internal.schema_migrations (
          name TEXT PRIMARY KEY,
          checksum TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      const applied = await tenantClient.query<{
        name: string;
        checksum: string;
      }>(`
        SELECT name, checksum
        FROM bmms_internal.schema_migrations
        ORDER BY name
      `);

      // Require applied migrations to be an unchanged prefix.
      // This also rejects deleted or inserted historical migrations.
      for (const [index, row] of applied.rows.entries()) {
        const migration = migrations[index];

        if (
          !migration ||
          migration.name !== row.name ||
          migration.checksum !== row.checksum
        ) {
          throw new Error(
            "Applied tenant migration history does not match local files.",
          );
        }
      }

      for (const migration of migrations.slice(applied.rows.length)) {
        signal.throwIfAborted();

        await tenantClient.query(migration.sql);

        await tenantClient.query(
          `
          INSERT INTO bmms_internal.schema_migrations (name, checksum)
          VALUES ($1, $2)
          `,
          [migration.name, migration.checksum],
        );
      }

      signal.throwIfAborted();

      await tenantClient.query(
        `
        INSERT INTO bmms.tenant_metadata (singleton, tenant_id)
        VALUES (TRUE, $1)
        ON CONFLICT (singleton) DO NOTHING
        `,
        [tenantId],
      );

      const identity = await tenantClient.query<{ tenantId: string }>(
        `
        SELECT tenant_id AS "tenantId"
        FROM bmms.tenant_metadata
        WHERE singleton = TRUE
        `,
      );

      if (
        identity.rows[0]?.tenantId !== tenantId.toLowerCase()
      ) {
        throw new Error("Tenant database identity does not match.");
      }

      // Runtime access is deliberately limited to reading metadata.
      await tenantClient.query(`
        GRANT USAGE ON SCHEMA bmms TO ${runtimeRole}
      `);

      await tenantClient.query(`
        GRANT SELECT ON bmms.tenant_metadata TO ${runtimeRole}
      `);

      signal.throwIfAborted();

      await tenantClient.query("COMMIT");
    } catch (error) {
      await tenantClient.query("ROLLBACK");
      throw error;
    }

    return names.database;
  } finally {
    try {
      if (tenantClient) {
        await tenantClient.end();
      }
    } finally {
      // Closing releases the session advisory lock.
      maintenance.release(true);
    }
  }
}