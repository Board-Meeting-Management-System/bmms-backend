import pg from "pg";

import { pool } from "../../db.js";
import { loadVerificationResources } from "./verification-resources.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function verifyTenantDatabase(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<string> {
  signal.throwIfAborted();

  const resources = await loadVerificationResources(job);

  // Local-development connections only.
  if (
    process.env.NODE_ENV !== "development" ||
    !["127.0.0.1", "localhost", "::1"].includes(resources.host)
  ) {
    throw new Error(
      "Configure verified TLS before using remote tenant connections.",
    );
  }

  const controlDatabase = await pool.query<{ name: string }>(
    "SELECT current_database() AS name",
  );

  const controlDatabaseName = controlDatabase.rows[0]?.name;

  if (!controlDatabaseName) {
    throw new Error("Cannot determine the control database.");
  }

  signal.throwIfAborted();

  const client = new pg.Client({
    host: resources.host,
    port: resources.port,
    database: resources.database,
    user: resources.username,
    password: resources.password,
    application_name: "bmms-resource-verification",
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
  });

  client.on("error", () => {
    console.error("Tenant verification connection failed.");
  });

  try {
    await client.connect();

    signal.throwIfAborted();

    const identity = await client.query<{
      database: string;
      username: string;
      tenantId: string;
    }>(`
      SELECT
        current_database() AS database,
        current_user AS username,
        tenant_id AS "tenantId"
      FROM bmms.tenant_metadata
      WHERE singleton = TRUE
    `);

    const actual = identity.rows[0];

    if (
      identity.rowCount !== 1 ||
      !actual ||
      actual.database !== resources.database ||
      actual.username !== resources.username ||
      actual.tenantId !== job.tenantId.toLowerCase()
    ) {
      throw new Error("Tenant connection identity does not match.");
    }

    signal.throwIfAborted();

    const permissions = await client.query<{ safe: boolean }>(`
      SELECT (
        role.rolcanlogin
        AND NOT role.rolsuper
        AND NOT role.rolcreatedb
        AND NOT role.rolcreaterole
        AND NOT role.rolreplication
        AND NOT role.rolbypassrls

        AND NOT EXISTS (
          SELECT 1
          FROM pg_auth_members
          WHERE member = role.oid OR roleid = role.oid
        )

        AND NOT EXISTS (
          SELECT 1
          FROM pg_database
          WHERE datdba = role.oid
        )

        AND NOT has_database_privilege(
          current_database(), 'CREATE'
        )
        AND NOT has_database_privilege(
          current_database(), 'TEMPORARY'
        )

        AND has_schema_privilege('bmms', 'USAGE')
        AND NOT has_schema_privilege('bmms', 'CREATE')
        AND NOT has_schema_privilege('public', 'CREATE')
        AND NOT has_schema_privilege('bmms_internal', 'USAGE')
        AND NOT has_schema_privilege('bmms_internal', 'CREATE')

        AND has_table_privilege(
          'bmms.tenant_metadata', 'SELECT'
        )
        AND NOT has_table_privilege(
          'bmms.tenant_metadata',
          'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
        )
        AND NOT has_any_column_privilege(
          'bmms.tenant_metadata',
          'INSERT, UPDATE, REFERENCES'
        )
      ) AS safe
      FROM pg_roles AS role
      WHERE rolname = current_user
    `);

    if (permissions.rows[0]?.safe !== true) {
      throw new Error("Tenant runtime permissions are unsafe.");
    }

    signal.throwIfAborted();

    // Reject access to the control database or other tenant databases.
    const forbiddenDatabases = await client.query(
      `
      SELECT datname
      FROM pg_database
      WHERE (
          datname = $1
          OR (
            datname ~ '^bmms_t_[0-9a-f]{32}$'
            AND datname <> current_database()
          )
        )
        AND has_database_privilege(current_user, oid, 'CONNECT')
      LIMIT 1
      `,
      [controlDatabaseName],
    );

    if (forbiddenDatabases.rowCount !== 0) {
      throw new Error(
        "Tenant runtime role can connect to a forbidden database.",
      );
    }

    signal.throwIfAborted();

    return resources.database;
  } finally {
    await client.end();
  }
}