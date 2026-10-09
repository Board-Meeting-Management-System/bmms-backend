import { pool } from "../../db.js";
import { ProvisioningLeaseLostError } from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

const REQUIRED_STEPS = [
  "create_database",
  "configure_credentials",
  "migrate_tenant",
  "configure_encryption",
  "verify_resources",
];

export async function activateTenant(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL statement_timeout = '5s'");

    const owned = await client.query(
      `
      SELECT id
      FROM provisioning_jobs
      WHERE id = $1
        AND tenant_id = $2
        AND status = 'running'
        AND lease_owner = $3
        AND lease_version = $4::bigint
        AND lease_expires_at > clock_timestamp()
      FOR UPDATE
      `,
      [job.id, job.tenantId, job.leaseOwner, job.leaseVersion],
    );

    if (owned.rowCount !== 1) {
      throw new ProvisioningLeaseLostError();
    }

    const completed = await client.query(
      `
      SELECT step_name
      FROM provisioning_steps
      WHERE job_id = $1
        AND step_name = ANY($2::text[])
        AND status = 'succeeded'
      FOR UPDATE
      `,
      [job.id, REQUIRED_STEPS],
    );

    if (completed.rowCount !== REQUIRED_STEPS.length) {
      throw new Error("Required provisioning steps are incomplete.");
    }

    const resources = await client.query(
      `
      SELECT tenant_id
      FROM tenant_resources
      WHERE tenant_id = $1
        AND database_host IS NOT NULL
        AND database_port IS NOT NULL
        AND database_name IS NOT NULL
        AND database_secret_ref IS NOT NULL
        AND runtime_role_ref IS NOT NULL
        AND kms_key_ref IS NOT NULL
      FOR UPDATE
      `,
      [job.tenantId],
    );

    if (resources.rowCount !== 1) {
      throw new Error("Tenant resources are incomplete.");
    }

    signal.throwIfAborted();

    const tenant = await client.query(
      `
      UPDATE tenants
      SET
        status = 'active',
        updated_at = now()
      WHERE id = $1
        AND status = 'provisioning'
      `,
      [job.tenantId],
    );

    if (tenant.rowCount !== 1) {
      throw new Error("Tenant is not awaiting activation.");
    }

    const step = await client.query(
      `
      UPDATE provisioning_steps
      SET
        status = 'succeeded',
        resource_ref = $2,
        last_error_code = NULL,
        completed_at = now()
      WHERE job_id = $1
        AND step_name = 'activate_tenant'
        AND status = 'running'
      `,
      [job.id, job.tenantId],
    );

    if (step.rowCount !== 1) {
      throw new Error("Activation step is not running.");
    }

    // Recheck ownership and expiry before releasing the lease.
    const finished = await client.query(
      `
      UPDATE provisioning_jobs
      SET
        status = 'succeeded',
        last_error_code = NULL,
        lease_owner = NULL,
        lease_expires_at = NULL,
        updated_at = now()
      WHERE id = $1
        AND status = 'running'
        AND lease_owner = $2
        AND lease_version = $3::bigint
        AND lease_expires_at > clock_timestamp()
      `,
      [job.id, job.leaseOwner, job.leaseVersion],
    );

    if (finished.rowCount !== 1) {
      throw new ProvisioningLeaseLostError();
    }

    signal.throwIfAborted();

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}