import { withOwnedJob } from "./provisioning-step.repository.js";
import { getTenantResourceNames } from "./tenant-resource-names.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

function getTenantDatabaseAddress(): {
  host: string;
  port: number;
} {
  const host = process.env.TENANT_DATABASE_HOST?.trim();
  const portValue = process.env.TENANT_DATABASE_PORT?.trim();

  if (
    !host ||
    /[\s/@?#]/.test(host) ||
    host.includes("://")
  ) {
    throw new Error("TENANT_DATABASE_HOST is missing or invalid.");
  }

  if (!portValue || !/^\d+$/.test(portValue)) {
    throw new Error("TENANT_DATABASE_PORT is missing or invalid.");
  }

  const port = Number(portValue);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("TENANT_DATABASE_PORT is invalid.");
  }

  return { host, port };
}

export async function saveTenantDatabaseResources(
  job: ClaimedProvisioningJob,
  secretRef: string,
): Promise<void> {
  const match = /^local-db:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(
    secretRef,
  );

  const secretId = match?.[1];

  if (!secretId) {
    throw new Error("Invalid tenant database secret reference.");
  }

  const names = getTenantResourceNames(job.tenantId);
  const address = getTenantDatabaseAddress();

  await withOwnedJob(job, async (client) => {
    // Confirm that the referenced secret belongs to this tenant.
    const secret = await client.query(
      `
      SELECT id
      FROM tenant_secrets
      WHERE id = $1
        AND tenant_id = $2
        AND purpose = 'database_credentials'
      `,
      [secretId, job.tenantId],
    );

    if (secret.rowCount !== 1) {
      throw new Error("Tenant database secret was not found.");
    }

    // Allow initial setup and identical retries.
    // Reject overwriting different resource assignments.
    const updated = await client.query(
      `
      UPDATE tenant_resources
      SET
        database_host = $2,
        database_port = $3,
        database_name = $4,
        database_secret_ref = $5,
        runtime_role_ref = $6,
        updated_at = now()
      WHERE tenant_id = $1
        AND (database_host IS NULL OR database_host = $2)
        AND (database_port IS NULL OR database_port = $3)
        AND (database_name IS NULL OR database_name = $4)
        AND (
          database_secret_ref IS NULL
          OR database_secret_ref = $5
        )
        AND (runtime_role_ref IS NULL OR runtime_role_ref = $6)
      `,
      [
        job.tenantId,
        address.host,
        address.port,
        names.database,
        `local-db:${secretId.toLowerCase()}`,
        names.runtimeRole,
      ],
    );

    if (updated.rowCount !== 1) {
      throw new Error(
        "Tenant resource record is missing or has conflicting assignments.",
      );
    }
  });
}