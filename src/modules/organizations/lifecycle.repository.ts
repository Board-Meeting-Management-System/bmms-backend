import type { PoolClient } from "pg";

import { pool } from "../../db.js";
import { recordAudit, type AuditActor } from "../audit/audit.repository.js";

// Suspend, reactivate, and scheduled deletion. A suspended organization is
// no longer served (the internal API stops resolving it and hands out no
// credentials) but keeps all its data. Deletion is only possible for a
// suspended or failed organization and happens after a grace period, so it
// can still be cancelled.

export class LifecycleError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "LifecycleError";
  }
}

/** Hours between scheduling and deletion (TENANT_DELETION_GRACE_HOURS, default 7 days). */
export function deletionGraceHours(): number {
  const raw = process.env.TENANT_DELETION_GRACE_HOURS?.trim();
  const hours = raw === undefined || raw === "" ? 168 : Number(raw);
  if (!Number.isFinite(hours) || hours < 0 || hours > 24 * 365) {
    throw new Error("TENANT_DELETION_GRACE_HOURS must be between 0 and 8760.");
  }
  return hours;
}

interface TenantRow {
  id: string;
  name: string;
  slug: string;
  status: "provisioning" | "active" | "failed" | "suspended";
  deletionScheduledFor: Date | null;
}

async function inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout = '3s'");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function lockTenant(client: PoolClient, tenantId: string): Promise<TenantRow> {
  const result = await client.query<TenantRow>(
    `
    SELECT id, name, slug, status, deletion_scheduled_for AS "deletionScheduledFor"
    FROM tenants WHERE id = $1 FOR UPDATE
    `,
    [tenantId],
  );
  const tenant = result.rows[0];
  if (!tenant) throw new LifecycleError(404, "TENANT_NOT_FOUND", "Organization not found.");
  return tenant;
}

export async function suspendOrganization(tenantId: string, actor: AuditActor, reason: string | null) {
  return inTransaction(async (client) => {
    const tenant = await lockTenant(client, tenantId);
    if (tenant.status !== "active") {
      throw new LifecycleError(409, "NOT_ACTIVE", "Only active organizations can be suspended.");
    }
    await client.query(
      `UPDATE tenants SET status = 'suspended', suspended_at = now(), updated_at = now() WHERE id = $1`,
      [tenantId],
    );
    await recordAudit(
      { actor, action: "organization.suspended", tenantId, tenantName: tenant.name, metadata: { reason } },
      client,
    );
    return { status: "suspended" as const };
  });
}

export async function reactivateOrganization(tenantId: string, actor: AuditActor) {
  return inTransaction(async (client) => {
    const tenant = await lockTenant(client, tenantId);
    if (tenant.status !== "suspended") {
      throw new LifecycleError(409, "NOT_SUSPENDED", "Only suspended organizations can be reactivated.");
    }
    if (tenant.deletionScheduledFor) {
      throw new LifecycleError(409, "DELETION_SCHEDULED", "Cancel the scheduled deletion first.");
    }
    await client.query(
      `UPDATE tenants SET status = 'active', suspended_at = NULL, updated_at = now() WHERE id = $1`,
      [tenantId],
    );
    await recordAudit({ actor, action: "organization.reactivated", tenantId, tenantName: tenant.name }, client);
    return { status: "active" as const };
  });
}

export async function scheduleDeletion(tenantId: string, actor: { id: string; email: string | null }, confirmSlug: string) {
  return inTransaction(async (client) => {
    const tenant = await lockTenant(client, tenantId);
    if (confirmSlug.trim().toLowerCase() !== tenant.slug) {
      throw new LifecycleError(400, "CONFIRMATION_MISMATCH", "Type the organization's slug exactly to confirm.");
    }
    if (tenant.status !== "suspended" && tenant.status !== "failed") {
      throw new LifecycleError(409, "NOT_SUSPENDED", "Suspend the organization before deleting it.");
    }
    if (tenant.deletionScheduledFor) {
      throw new LifecycleError(409, "DELETION_SCHEDULED", "Deletion is already scheduled.");
    }
    const hours = deletionGraceHours();
    const result = await client.query<{ scheduledFor: Date }>(
      `
      UPDATE tenants
      SET deletion_requested_at = now(),
          deletion_requested_by = $2,
          deletion_scheduled_for = now() + ($3::numeric * interval '1 hour'),
          updated_at = now()
      WHERE id = $1
      RETURNING deletion_scheduled_for AS "scheduledFor"
      `,
      [tenantId, actor.id, hours],
    );
    const scheduledFor = result.rows[0]!.scheduledFor.toISOString();
    await recordAudit(
      {
        actor,
        action: "organization.deletion_scheduled",
        tenantId,
        tenantName: tenant.name,
        metadata: { scheduledFor, graceHours: hours },
      },
      client,
    );
    return { deletionScheduledFor: scheduledFor };
  });
}

export async function cancelDeletion(tenantId: string, actor: AuditActor) {
  return inTransaction(async (client) => {
    const tenant = await lockTenant(client, tenantId);
    if (!tenant.deletionScheduledFor) {
      throw new LifecycleError(409, "NO_DELETION_SCHEDULED", "No deletion is scheduled.");
    }
    await client.query(
      `
      UPDATE tenants
      SET deletion_requested_at = NULL, deletion_requested_by = NULL, deletion_scheduled_for = NULL, updated_at = now()
      WHERE id = $1
      `,
      [tenantId],
    );
    await recordAudit({ actor, action: "organization.deletion_cancelled", tenantId, tenantName: tenant.name }, client);
    return { deletionScheduledFor: null };
  });
}
