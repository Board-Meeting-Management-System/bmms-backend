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
                WHEN 'configure_encryption' THEN 4
                WHEN 'verify_resources' THEN 5
                WHEN 'activate_tenant' THEN 6
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