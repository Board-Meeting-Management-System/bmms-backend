import type { PoolClient } from "pg";

import { pool } from "../../db.js";
import type {
  ClaimedProvisioningJob,
  ProvisioningFailureCode,
} from "./provisioning-worker.repository.js";

export type ProvisioningStepName =
  | "create_database"
  | "configure_credentials"
  | "migrate_tenant"
  | "configure_encryption"
  | "verify_resources"
  | "activate_tenant";

export class ProvisioningLeaseLostError extends Error {
  constructor() {
    super("Provisioning job lease is no longer owned.");
    this.name = "ProvisioningLeaseLostError";
  }
}

export async function withOwnedJob<T>(
  job: ClaimedProvisioningJob,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    await client.query("SET LOCAL statement_timeout = '5s'");

    // Lock the job before inspecting or changing its steps.
    // Another worker cannot reclaim it during this transaction.
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

    const result = await operation(client);

    // Recheck expiry before committing step changes.
    const valid = await client.query(
      `
      SELECT id
      FROM provisioning_jobs
      WHERE id = $1
        AND lease_expires_at > clock_timestamp()
      `,
      [job.id],
    );

    if (valid.rowCount !== 1) {
      throw new ProvisioningLeaseLostError();
    }

    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function startProvisioningStep(
  job: ClaimedProvisioningJob,
  stepName: ProvisioningStepName,
): Promise<"run" | "already_succeeded"> {
  return withOwnedJob(job, async (client) => {
    const existing = await client.query<{ status: string }>(
      `
      SELECT status
      FROM provisioning_steps
      WHERE job_id = $1 AND step_name = $2
      FOR UPDATE
      `,
      [job.id, stepName],
    );

    const step = existing.rows[0];

    if (!step) {
      throw new Error(`Missing provisioning step: ${stepName}`);
    }

    if (step.status === "succeeded") {
      return "already_succeeded";
    }

    // A running step may belong to a previous crashed worker.
    // Its infrastructure operation must be safe to retry.
    await client.query(
      `
      UPDATE provisioning_steps
      SET
        status = 'running',
        attempts = attempts + 1,
        last_error_code = NULL,
        completed_at = NULL
      WHERE job_id = $1 AND step_name = $2
      `,
      [job.id, stepName],
    );

    return "run";
  });
}

export async function completeProvisioningStep(
  job: ClaimedProvisioningJob,
  stepName: ProvisioningStepName,
  resourceRef: string | null = null,
): Promise<void> {
  await withOwnedJob(job, async (client) => {
    const updated = await client.query(
      `
      UPDATE provisioning_steps
      SET
        status = 'succeeded',
        resource_ref = $3,
        last_error_code = NULL,
        completed_at = now()
      WHERE job_id = $1
        AND step_name = $2
        AND status = 'running'
      `,
      [job.id, stepName, resourceRef],
    );

    if (updated.rowCount !== 1) {
      throw new Error("Provisioning step is missing or not running.");
    }
  });
}

export async function failProvisioningStep(
  job: ClaimedProvisioningJob,
  stepName: ProvisioningStepName,
  errorCode: ProvisioningFailureCode,
): Promise<void> {
  await withOwnedJob(job, async (client) => {
    const updated = await client.query(
      `
      UPDATE provisioning_steps
      SET
        status = 'failed',
        last_error_code = $3,
        completed_at = NULL
      WHERE job_id = $1
        AND step_name = $2
        AND status = 'running'
      `,
      [job.id, stepName, errorCode],
    );

    if (updated.rowCount !== 1) {
      throw new Error(
        "Cannot fail a provisioning step that is missing or not running.",
      );
    }
  });
}