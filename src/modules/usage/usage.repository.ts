import { pool } from "../../db.js";
import { provisioningPool } from "../provisioning/provisioning.db.js";
import { getTenantResourceNames } from "../provisioning/tenant-resource-names.js";
import { storageProvider } from "../storage/storage-provider.js";

// Per-organization infrastructure usage: database size and connections
// (from the PostgreSQL server) and storage size (from the storage provider).
// The worker refreshes stale measurements a few at a time; admins can
// refresh one on demand. A part that can't be measured is left empty with
// an error code — never a guessed value.

export interface TenantUsage {
  databaseBytes: number | null;
  databaseConnections: number | null;
  storageBytes: number | null;
  storageFiles: number | null;
  collectedAt: string;
  lastErrorCode: string | null;
}

const MB = 1024 * 1024;

function positiveNumber(name: string, fallback: number) {
  const raw = Number(process.env[name]?.trim() || fallback);
  return Number.isFinite(raw) && raw > 0 ? raw : fallback;
}

/** Minutes between measurements of the same organization (USAGE_INTERVAL_MINUTES, default 15). */
export const usageIntervalMinutes = () => positiveNumber("USAGE_INTERVAL_MINUTES", 15);

/** Levels at which an organization is flagged (TENANT_DATABASE_WARN_MB, TENANT_STORAGE_WARN_MB). */
export function usageLimits() {
  return {
    databaseWarnBytes: positiveNumber("TENANT_DATABASE_WARN_MB", 1024) * MB,
    storageWarnBytes: positiveNumber("TENANT_STORAGE_WARN_MB", 5120) * MB,
  };
}

export function usageWarnings(usage: TenantUsage | null): string[] {
  if (!usage) return [];
  const limits = usageLimits();
  const warnings: string[] = [];
  if (usage.databaseBytes !== null && usage.databaseBytes >= limits.databaseWarnBytes) warnings.push("DATABASE_NEAR_LIMIT");
  if (usage.storageBytes !== null && usage.storageBytes >= limits.storageWarnBytes) warnings.push("STORAGE_NEAR_LIMIT");
  return warnings;
}

/** Measures one organization now and stores the result. */
export async function collectTenantUsage(tenantId: string): Promise<TenantUsage> {
  const names = getTenantResourceNames(tenantId);
  const errors: string[] = [];

  let databaseBytes: number | null = null;
  let databaseConnections: number | null = null;
  try {
    const db = await provisioningPool.query<{ size: string | null; connections: string }>(
      `
      SELECT
        (SELECT pg_database_size(datname) FROM pg_database WHERE datname = $1) AS size,
        (SELECT count(*) FROM pg_stat_activity WHERE datname = $1) AS connections
      `,
      [names.database],
    );
    if (db.rows[0]?.size === null || db.rows[0]?.size === undefined) {
      errors.push("DATABASE_MISSING");
    } else {
      databaseBytes = Number(db.rows[0].size);
      databaseConnections = Number(db.rows[0].connections);
    }
  } catch {
    errors.push("DATABASE_UNREACHABLE");
  }

  let storageBytes: number | null = null;
  let storageFiles: number | null = null;
  try {
    const measured = await storageProvider().measure(tenantId);
    storageBytes = measured.bytes;
    storageFiles = measured.files;
  } catch {
    errors.push("STORAGE_UNAVAILABLE");
  }

  const result = await pool.query<{ collectedAt: Date }>(
    `
    INSERT INTO tenant_usage (tenant_id, database_bytes, database_connections, storage_bytes, storage_files, collected_at, last_error_code)
    VALUES ($1, $2, $3, $4, $5, now(), $6)
    ON CONFLICT (tenant_id) DO UPDATE SET
      database_bytes = EXCLUDED.database_bytes,
      database_connections = EXCLUDED.database_connections,
      storage_bytes = EXCLUDED.storage_bytes,
      storage_files = EXCLUDED.storage_files,
      collected_at = EXCLUDED.collected_at,
      last_error_code = EXCLUDED.last_error_code
    RETURNING collected_at AS "collectedAt"
    `,
    [tenantId, databaseBytes, databaseConnections, storageBytes, storageFiles, errors[0] ?? null],
  );

  return {
    databaseBytes,
    databaseConnections,
    storageBytes,
    storageFiles,
    collectedAt: result.rows[0]!.collectedAt.toISOString(),
    lastErrorCode: errors[0] ?? null,
  };
}

/** Refreshes up to `limit` organizations whose measurement is missing or stale. */
export async function collectStaleUsage(limit = 5): Promise<number> {
  const due = await pool.query<{ id: string }>(
    `
    SELECT tenant.id
    FROM tenants AS tenant
    LEFT JOIN tenant_usage AS usage ON usage.tenant_id = tenant.id
    WHERE tenant.status IN ('active', 'suspended')
      AND (usage.collected_at IS NULL OR usage.collected_at < now() - ($1::numeric * interval '1 minute'))
    ORDER BY usage.collected_at NULLS FIRST
    LIMIT $2
    `,
    [usageIntervalMinutes(), limit],
  );
  for (const row of due.rows) {
    await collectTenantUsage(row.id);
  }
  return due.rowCount ?? 0;
}

export async function getTenantUsage(tenantId: string): Promise<TenantUsage | null> {
  const result = await pool.query<{
    databaseBytes: string | null;
    databaseConnections: number | null;
    storageBytes: string | null;
    storageFiles: number | null;
    collectedAt: Date;
    lastErrorCode: string | null;
  }>(
    `
    SELECT database_bytes AS "databaseBytes", database_connections AS "databaseConnections",
           storage_bytes AS "storageBytes", storage_files AS "storageFiles",
           collected_at AS "collectedAt", last_error_code AS "lastErrorCode"
    FROM tenant_usage WHERE tenant_id = $1
    `,
    [tenantId],
  );
  const row = result.rows[0];
  return row ? toUsage(row) : null;
}

/** Converts a tenant_usage row (bigints arrive as strings). */
export function toUsage(row: {
  databaseBytes: string | number | null;
  databaseConnections: number | null;
  storageBytes: string | number | null;
  storageFiles: number | null;
  collectedAt: Date;
  lastErrorCode: string | null;
}): TenantUsage {
  return {
    databaseBytes: row.databaseBytes === null ? null : Number(row.databaseBytes),
    databaseConnections: row.databaseConnections,
    storageBytes: row.storageBytes === null ? null : Number(row.storageBytes),
    storageFiles: row.storageFiles,
    collectedAt: row.collectedAt.toISOString(),
    lastErrorCode: row.lastErrorCode,
  };
}
