import { pool } from "../../db.js";
import { recordAudit } from "../audit/audit.repository.js";
import { provisioningPool } from "../provisioning/provisioning.db.js";
import { getTenantResourceNames, quoteResourceIdentifier } from "../provisioning/tenant-resource-names.js";
import { storageProvider } from "../storage/storage-provider.js";

// Carries out deletions whose grace period has passed: drops the
// organization's database and roles, removes its storage, then deletes its
// control-plane rows. Each step is idempotent, so an interrupted deletion
// simply runs again. The audit log keeps the record (by snapshot).

/** Deletes one due organization, if any. Returns its id. */
export async function purgeNextDueDeletion(): Promise<string | null> {
  const lock = await pool.connect();
  let tenant: { id: string; name: string; slug: string } | undefined;
  try {
    // An advisory lock per organization keeps two workers from deleting the
    // same one. Locks are tried one candidate at a time (never inside the
    // query's WHERE, which could lock rows it doesn't return).
    const due = await lock.query<{ id: string; name: string; slug: string }>(
      `
      SELECT id, name, slug
      FROM tenants
      WHERE deletion_scheduled_for <= now()
        AND status IN ('suspended', 'failed')
      ORDER BY deletion_scheduled_for
      LIMIT 10
      `,
    );
    for (const candidate of due.rows) {
      const locked = await lock.query<{ ok: boolean }>(
        `SELECT pg_try_advisory_lock(hashtextextended('tenant-deletion:' || $1::text, 0)) AS ok`,
        [candidate.id],
      );
      if (!locked.rows[0]?.ok) continue;
      // Re-check under the lock: it may have been cancelled or deleted meanwhile.
      const still = await lock.query(
        `SELECT 1 FROM tenants WHERE id = $1 AND deletion_scheduled_for <= now() AND status IN ('suspended', 'failed')`,
        [candidate.id],
      );
      if (still.rowCount === 1) {
        tenant = candidate;
        break;
      }
      await lock.query(`SELECT pg_advisory_unlock(hashtextextended('tenant-deletion:' || $1::text, 0))`, [candidate.id]);
    }
    if (!tenant) return null;

    const names = getTenantResourceNames(tenant.id);

    // 1. Database and roles (server level, outside any transaction).
    await provisioningPool.query(`DROP DATABASE IF EXISTS ${quoteResourceIdentifier(names.database)} WITH (FORCE)`);
    for (const role of [names.runtimeRole, names.ownerRole]) {
      const quoted = quoteResourceIdentifier(role);
      const exists = await provisioningPool.query(`SELECT 1 FROM pg_roles WHERE rolname = $1`, [role]);
      if (exists.rowCount) {
        await provisioningPool.query(`DROP OWNED BY ${quoted}`);
        await provisioningPool.query(`DROP ROLE ${quoted}`);
      }
    }

    // 2. Files.
    await storageProvider().deleteTenantStorage(tenant.id);

    // 3. Control-plane rows, in one transaction with the audit event.
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const ids = [tenant.id];
      const invitations = `SELECT id FROM tenant_invitations WHERE tenant_id = ANY($1)`;
      await client.query(`DELETE FROM invitation_deliveries WHERE invitation_id IN (${invitations})`, [ids]);
      await client.query(`DELETE FROM secretary_email_verifications WHERE invitation_id IN (${invitations})`, [ids]);
      await client.query(`DELETE FROM tenant_invitations WHERE tenant_id = ANY($1)`, [ids]);
      await client.query(
        `DELETE FROM provisioning_steps WHERE job_id IN (SELECT id FROM provisioning_jobs WHERE tenant_id = ANY($1))`,
        [ids],
      );
      for (const table of ["provisioning_jobs", "tenant_domains", "tenant_resources", "tenant_secrets", "tenant_data_keys"]) {
        await client.query(`DELETE FROM ${table} WHERE tenant_id = ANY($1)`, [ids]);
      }
      await client.query(`DELETE FROM tenants WHERE id = ANY($1)`, [ids]);
      await recordAudit(
        { actor: null, action: "organization.deleted", tenantId: tenant.id, tenantName: tenant.name, metadata: { slug: tenant.slug } },
        client,
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    console.log(JSON.stringify({ event: "organization_deleted", tenantId: tenant.id }));
    return tenant.id;
  } finally {
    if (tenant) {
      await lock.query(`SELECT pg_advisory_unlock(hashtextextended('tenant-deletion:' || $1::text, 0))`, [tenant.id]).catch(() => {});
    }
    lock.release();
  }
}
