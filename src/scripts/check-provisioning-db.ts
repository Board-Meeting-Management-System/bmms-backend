import { provisioningPool } from "../modules/provisioning/provisioning.db.js";

interface PermissionCheck {
  database: string;
  username: string;
  canCreateDatabase: boolean;
  canCreateRole: boolean;
  isSuperuser: boolean;
}

try {
  const result = await provisioningPool.query<PermissionCheck>(`
    SELECT
      current_database() AS database,
      current_user AS username,
      (rolcreatedb OR rolsuper) AS "canCreateDatabase",
      (rolcreaterole OR rolsuper) AS "canCreateRole",
      rolsuper AS "isSuperuser"
    FROM pg_roles
    WHERE rolname = current_user
  `);

  const permissions = result.rows[0];

  if (!permissions) {
    throw new Error("Could not read provisioning account permissions.");
  }

  console.table(permissions);

  if (
    !permissions.canCreateDatabase ||
    !permissions.canCreateRole
  ) {
    throw new Error(
      "Provisioning account needs CREATEDB and CREATEROLE permissions.",
    );
  }

  console.log("Provisioning database permission check passed.");
} catch (error) {
  // Avoid printing connection details or credentials.
  const code =
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string"
      ? error.code
      : undefined;

  console.error(
    "Provisioning database check failed.",
    code ? `Error code: ${code}` : "Check connectivity and permissions.",
  );

  process.exitCode = 1;
} finally {
  await provisioningPool.end();
}