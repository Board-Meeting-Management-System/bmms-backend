import { pool } from "../../db.js";

const MAX_ATTEMPTS = 5;

export interface ClaimedProvisioningJob {
  id: string;
  tenantId: string;
  attempts: number;
  leaseOwner: string;
  // PostgreSQL bigint is returned as a string.
  leaseVersion: string;
  leaseExpiresAt: Date;
}

export type ProvisioningFailureCode =
  | "DATABASE_SETUP_FAILED"
  | "CREDENTIAL_SETUP_FAILED"
  | "TENANT_MIGRATION_FAILED"
  | "ENCRYPTION_SETUP_FAILED"
  | "RESOURCE_VERIFICATION_FAILED"
  | "TENANT_ACTIVATION_FAILED"
  | "PROVISIONING_FAILED";

export async function claimNextProvisioningJob(
  workerId: string,
): Promise<ClaimedProvisioningJob | null> {
  if (!workerId.trim()) {
    throw new Error("Worker ID is required.");
  }

  const result = await pool.query<ClaimedProvisioningJob>(
    `
    WITH candidate AS (
      SELECT id
      FROM provisioning_jobs
      WHERE attempts < $2::integer
        AND (
          (
            status = 'pending'
            AND next_run_at <= now()
          )
          OR
          (
            status = 'running'
            AND lease_expires_at <= now()
          )
        )
      ORDER BY next_run_at, created_at, id
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    UPDATE provisioning_jobs AS job
    SET
      status = 'running',
      attempts = job.attempts + 1,
      lease_owner = $1,
      lease_expires_at = now() + interval '60 seconds',
      lease_version = job.lease_version + 1,
      updated_at = now()
    FROM candidate
    WHERE job.id = candidate.id
    RETURNING
      job.id,
      job.tenant_id AS "tenantId",
      job.attempts,
      job.lease_owner AS "leaseOwner",
      job.lease_version AS "leaseVersion",
      job.lease_expires_at AS "leaseExpiresAt"
    `,
    [workerId, MAX_ATTEMPTS],
  );

  return result.rows[0] ?? null;
}

export async function renewProvisioningLease(
  job: ClaimedProvisioningJob,
): Promise<boolean> {
  const result = await pool.query(
    `
    UPDATE provisioning_jobs
    SET
      lease_expires_at = now() + interval '60 seconds',
      updated_at = now()
    WHERE id = $1
      AND status = 'running'
      AND lease_owner = $2
      AND lease_version = $3::bigint
      AND lease_expires_at > clock_timestamp()
    `,
    [job.id, job.leaseOwner, job.leaseVersion],
  );

  return result.rowCount === 1;
}

export async function recordProvisioningFailure(
  job: ClaimedProvisioningJob,
  errorCode: ProvisioningFailureCode,
): Promise<"pending" | "failed" | null> {
  // Retry delays: 30, 60, 120, 240 seconds.
  const retryDelaySeconds = Math.min(
    30 * 2 ** Math.min(Math.max(job.attempts - 1, 0), 4),
    300,
  );

  const result = await pool.query<{
    status: "pending" | "failed";
  }>(
    `
    WITH updated_job AS (
      UPDATE provisioning_jobs
      SET
        status = CASE
          WHEN attempts >= $5::integer THEN 'failed'
          ELSE 'pending'
        END,
        next_run_at =
          now() + ($6::integer * interval '1 second'),
        last_error_code = $4,
        lease_owner = NULL,
        lease_expires_at = NULL,
        updated_at = now()
      WHERE id = $1
        AND status = 'running'
        AND lease_owner = $2
        AND lease_version = $3::bigint
        AND lease_expires_at > clock_timestamp()
      RETURNING tenant_id, status
    ),
    updated_tenant AS (
      UPDATE tenants AS tenant
      SET
        status = 'failed',
        updated_at = now()
      FROM updated_job AS job
      WHERE tenant.id = job.tenant_id
        AND job.status = 'failed'
        AND tenant.status = 'provisioning'
      RETURNING tenant.id
    )
    SELECT status
    FROM updated_job
    `,
    [
      job.id,
      job.leaseOwner,
      job.leaseVersion,
      errorCode,
      MAX_ATTEMPTS,
      retryDelaySeconds,
    ],
  );

  // No update means this worker no longer owns a valid lease.
  return result.rows[0]?.status ?? null;
}

export async function failExhaustedProvisioningJobs(): Promise<number> {
  const result = await pool.query<{ id: string }>(
    `
    WITH exhausted AS (
      SELECT id
      FROM provisioning_jobs
      WHERE attempts >= $1::integer
        AND (
          status = 'pending'
          OR (
            status = 'running'
            AND lease_expires_at <= now()
          )
        )
      ORDER BY created_at, id
      LIMIT 100
      FOR UPDATE SKIP LOCKED
    ),
    failed_jobs AS (
      UPDATE provisioning_jobs AS job
      SET
        status = 'failed',
        last_error_code = 'ATTEMPTS_EXHAUSTED',
        lease_owner = NULL,
        lease_expires_at = NULL,
        updated_at = now()
      FROM exhausted
      WHERE job.id = exhausted.id
      RETURNING job.id, job.tenant_id
    ),
    failed_tenants AS (
      UPDATE tenants AS tenant
      SET
        status = 'failed',
        updated_at = now()
      FROM failed_jobs AS job
      WHERE tenant.id = job.tenant_id
        AND tenant.status = 'provisioning'
      RETURNING tenant.id
    )
    SELECT id
    FROM failed_jobs
    `,
    [MAX_ATTEMPTS],
  );

  return result.rowCount ?? 0;
}