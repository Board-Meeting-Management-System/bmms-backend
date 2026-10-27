import { pool } from "../../db.js";

interface ProvisioningJobStatus {
  id: string;
  tenantId: string;
  status: "pending" | "running" | "failed" | "succeeded";
  attempts: number;
  lastErrorCode: string | null;
  createdAt: Date;
  updatedAt: Date;
  steps: Array<{
    name: string;
    status: "pending" | "running" | "failed" | "succeeded";
    attempts: number;
    lastErrorCode: string | null;
    completedAt: string | null;
  }>;
  // Needed by the frontend to request and confirm email verification.
  secretaryInvitation: {
    id: string;
    email: string;
    status: string;
    emailVerifiedAt: string | null;
  } | null;
}

export async function getProvisioningJob(
  jobId: string,
): Promise<ProvisioningJobStatus | null> {
  const result = await pool.query<ProvisioningJobStatus>(
    `
    SELECT
      j.id,
      j.tenant_id AS "tenantId",
      j.status,
      j.attempts,
      j.last_error_code AS "lastErrorCode",
      j.created_at AS "createdAt",
      j.updated_at AS "updatedAt",

      COALESCE(
        (
          SELECT jsonb_agg(
            jsonb_build_object(
              'name', s.step_name,
              'status', s.status,
              'attempts', s.attempts,
              'lastErrorCode', s.last_error_code,
              'completedAt', s.completed_at
            )
            ORDER BY
              CASE s.step_name
                WHEN 'create_database' THEN 1
                WHEN 'configure_credentials' THEN 2
                WHEN 'migrate_tenant' THEN 3
                WHEN 'configure_storage' THEN 4
                WHEN 'configure_encryption' THEN 5
                WHEN 'configure_domain' THEN 6
                WHEN 'verify_resources' THEN 7
                WHEN 'activate_tenant' THEN 8
                ELSE 99
              END,
              s.step_name
          )
          FROM provisioning_steps AS s
          WHERE s.job_id = j.id
        ),
        '[]'::jsonb
      ) AS steps,

      (
        SELECT jsonb_build_object(
          'id', i.id,
          'email', i.email,
          'status', i.status,
          'emailVerifiedAt', i.email_verified_at
        )
        FROM tenant_invitations AS i
        WHERE i.tenant_id = j.tenant_id
          AND i.role = 'secretary'
          AND i.status IN ('pending_setup', 'pending')
        ORDER BY i.created_at DESC
        LIMIT 1
      ) AS "secretaryInvitation"

    FROM provisioning_jobs AS j
    WHERE j.id = $1
    `,
    [jobId],
  );

  return result.rows[0] ?? null;
}
/**
 * Re-opens a failed job for the worker. Only failed jobs qualify; steps that
 * succeeded stay succeeded (their resources are kept and reused), failed or
 * interrupted steps go back to pending. Never creates a new organization.
 */
export async function retryFailedJob(jobId: string): Promise<"retried" | "not_found" | "not_failed"> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const job = await client.query<{ tenantId: string; status: string }>(
      `SELECT tenant_id AS "tenantId", status FROM provisioning_jobs WHERE id = $1 FOR UPDATE`,
      [jobId],
    );
    const row = job.rows[0];
    if (!row) {
      await client.query("ROLLBACK");
      return "not_found";
    }
    if (row.status !== "failed") {
      await client.query("ROLLBACK");
      return "not_failed";
    }

    await client.query(
      `
      UPDATE provisioning_jobs
      SET status = 'pending', attempts = 0, next_run_at = now(),
          last_error_code = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
      WHERE id = $1
      `,
      [jobId],
    );
    await client.query(
      `UPDATE provisioning_steps SET status = 'pending' WHERE job_id = $1 AND status IN ('failed', 'running')`,
      [jobId],
    );
    await client.query(
      `UPDATE tenants SET status = 'provisioning', updated_at = now() WHERE id = $1 AND status = 'failed'`,
      [row.tenantId],
    );
    await client.query(
      `
      UPDATE tenant_domains SET status = 'pending', next_check_at = NULL, updated_at = now()
      WHERE tenant_id = $1 AND domain_type = 'platform' AND status = 'failed'
      `,
      [row.tenantId],
    );
    await client.query("COMMIT");
    return "retried";
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
