import { createHash, randomUUID } from "node:crypto";
import { pool } from "../../db.js";

export interface RegisterOrganizationInput {
  // Already validated and normalized by the service.
  name: string;
  slug: string;
  secretaryEmail: string;
  hostname: string;

  // Comes from the authenticated user, never the request body.
  requestedBy: string;

  idempotencyKey: string;
}

export interface RegistrationResult {
  tenantId: string;
  jobId: string;
  status: "provisioning";
}

export class RegistrationConflictError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RegistrationConflictError";
  }
}

interface ExistingJob {
  id: string;
  tenantId: string;
  requestHash: string;
  requestedBy: string | null;
}

const PROVISIONING_STEPS = [
  "create_database",
  "configure_credentials",
  "migrate_tenant",
  "configure_encryption",
  "verify_resources",
  "activate_tenant",
] as const;

export async function registerOrganization(
  input: RegisterOrganizationInput,
): Promise<RegistrationResult> {
  // Explicit field order makes the fingerprint deterministic.
  const requestHash = createHash("sha256")
    .update(
      JSON.stringify({
        name: input.name,
        slug: input.slug,
        secretaryEmail: input.secretaryEmail,
        hostname: input.hostname,
      }),
    )
    .digest("hex");

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Serialize requests using the same idempotency key.
    // The lock is automatically released at transaction completion.
    await client.query(
      `
      SELECT pg_advisory_xact_lock(
        hashtextextended($1::text, 0)
      )
      `,
      [`organization-registration:${input.idempotencyKey}`],
    );

    const existing = await client.query<ExistingJob>(
      `
      SELECT
        id,
        tenant_id AS "tenantId",
        request_hash AS "requestHash",
        requested_by AS "requestedBy"
      FROM provisioning_jobs
      WHERE idempotency_key = $1
      `,
      [input.idempotencyKey],
    );

    const previousJob = existing.rows[0];

    if (previousJob) {
      if (
        previousJob.requestedBy !== input.requestedBy ||
        previousJob.requestHash !== requestHash
      ) {
        throw new RegistrationConflictError(
          "IDEMPOTENCY_CONFLICT",
          "This idempotency key was already used for another request.",
        );
      }

      await client.query("COMMIT");

      // Replay the original acceptance response.
      // Current provisioning status comes from the job-status endpoint.
      return {
        tenantId: previousJob.tenantId,
        jobId: previousJob.id,
        status: "provisioning",
      };
    }

    const tenantId = randomUUID();
    const jobId = randomUUID();

    await client.query(
      `
      INSERT INTO tenants (
        id,
        name,
        slug,
        status,
        created_by
      )
      VALUES ($1, $2, $3, 'provisioning', $4)
      `,
      [
        tenantId,
        input.name,
        input.slug,
        input.requestedBy,
      ],
    );

    await client.query(
      `
      INSERT INTO tenant_domains (
        tenant_id,
        hostname,
        domain_type,
        status,
        is_primary
      )
      VALUES ($1, $2, 'platform', 'pending', TRUE)
      `,
      [tenantId, input.hostname],
    );

    await client.query(
      `
      INSERT INTO tenant_invitations (
        tenant_id,
        email,
        role,
        status,
        invited_by
      )
      VALUES ($1, $2, 'secretary', 'pending_setup', $3)
      `,
      [
        tenantId,
        input.secretaryEmail,
        input.requestedBy,
      ],
    );

    await client.query(
      `
      INSERT INTO tenant_resources (tenant_id)
      VALUES ($1)
      `,
      [tenantId],
    );

    await client.query(
      `
      INSERT INTO provisioning_jobs (
        id,
        tenant_id,
        idempotency_key,
        request_hash,
        requested_by,
        status
      )
      VALUES ($1, $2, $3, $4, $5, 'pending')
      `,
      [
        jobId,
        tenantId,
        input.idempotencyKey,
        requestHash,
        input.requestedBy,
      ],
    );

    await client.query(
      `
      INSERT INTO provisioning_steps (
        job_id,
        step_name,
        status
      )
      SELECT $1::uuid, step_name, 'pending'
      FROM unnest($2::text[]) AS steps(step_name)
      `,
      [jobId, [...PROVISIONING_STEPS]],
    );

    await client.query("COMMIT");

    return {
      tenantId,
      jobId,
      status: "provisioning",
    };
  } catch (error) {
    await client.query("ROLLBACK");

    const databaseError = error as {
      code?: string;
      constraint?: string;
    };

    if (
      databaseError.code === "23505" &&
      databaseError.constraint === "tenants_slug_key"
    ) {
      throw new RegistrationConflictError(
        "SLUG_ALREADY_EXISTS",
        "An organization already uses this slug.",
      );
    }

    if (
      databaseError.code === "23505" &&
      databaseError.constraint === "tenant_domains_hostname_key"
    ) {
      throw new RegistrationConflictError(
        "DOMAIN_ALREADY_EXISTS",
        "This hostname is already assigned.",
      );
    }

    throw error;
  } finally {
    client.release();
  }
}