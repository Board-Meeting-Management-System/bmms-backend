import { randomBytes } from "node:crypto";

import { pool } from "../../db.js";
import type { DomainCheck } from "./domain-provider.js";

export interface ResolvedTenant {
  tenantId: string;
  name: string;
  slug: string;
  tenantStatus: "provisioning" | "active" | "failed" | "suspended";
  domainId: string;
  hostname: string;
  domainType: "platform" | "custom";
  domainStatus: "pending" | "active" | "failed";
}

/**
 * The organization a hostname belongs to, by exact registered hostname.
 * `ready` (the default) requires an active domain and organization; the
 * routing probe uses `registered` to check a domain before it's active.
 * There is no default organization: unknown hosts resolve to null.
 */
export async function resolveTenantByHostname(
  hostname: string,
  mode: "ready" | "registered" = "ready",
): Promise<ResolvedTenant | null> {
  const result = await pool.query<ResolvedTenant>(
    `
    SELECT
      tenant.id AS "tenantId",
      tenant.name,
      tenant.slug,
      tenant.status AS "tenantStatus",
      domain.id AS "domainId",
      domain.hostname,
      domain.domain_type AS "domainType",
      domain.status AS "domainStatus"
    FROM tenant_domains AS domain
    JOIN tenants AS tenant ON tenant.id = domain.tenant_id
    WHERE domain.hostname = $1
    `,
    [hostname],
  );

  const row = result.rows[0];
  if (!row) return null;

  if (mode === "ready") {
    return row.domainStatus === "active" && row.tenantStatus === "active" ? row : null;
  }

  // A custom domain isn't routed until its ownership is proven.
  if (row.domainType === "custom" && row.domainStatus !== "active") return null;
  return row.tenantStatus === "suspended" ? null : row;
}

export async function primaryPlatformDomain(tenantId: string) {
  const result = await pool.query<{ id: string; hostname: string; status: string }>(
    `
    SELECT id, hostname, status
    FROM tenant_domains
    WHERE tenant_id = $1 AND is_primary AND domain_type = 'platform'
    `,
    [tenantId],
  );
  return result.rows[0] ?? null;
}

/**
 * Persists a check. Not-yet-active domains get a next_check_at with backoff
 * (1, 2, 4 … 60 minutes) for periodic re-checks.
 */
export async function recordDomainCheck(domainId: string, check: DomainCheck): Promise<void> {
  await pool.query(
    `
    UPDATE tenant_domains
    SET
      status = $2::text,
      last_error_code = $3::text,
      last_checked_at = now(),
      check_attempts = CASE WHEN $2::text = 'active' THEN 0 ELSE check_attempts + 1 END,
      next_check_at = CASE
        WHEN $2::text = 'active' THEN NULL
        ELSE now() + least(interval '1 minute' * power(2, least(check_attempts, 6)), interval '60 minutes')
      END,
      routing_verified_at = CASE WHEN $4::boolean THEN coalesce(routing_verified_at, now()) ELSE NULL END,
      tls_ready_at = CASE
        WHEN $5::boolean IS TRUE THEN coalesce(tls_ready_at, now())
        WHEN $5::boolean IS FALSE THEN NULL
        ELSE tls_ready_at
      END,
      ownership_verified_at = CASE
        WHEN $6::boolean IS TRUE THEN coalesce(ownership_verified_at, now())
        WHEN $6::boolean IS FALSE THEN NULL
        ELSE ownership_verified_at
      END,
      updated_at = now()
    WHERE id = $1
    `,
    [
      domainId,
      check.status,
      check.errorCode,
      check.routingVerified,
      check.tlsVerified,
      check.ownershipVerified ?? null,
    ],
  );
}

export class DomainConflictError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "DomainConflictError";
  }
}

export interface CustomDomain {
  id: string;
  hostname: string;
  status: "pending" | "active" | "failed";
  ownershipToken: string;
  ownershipVerifiedAt: string | null;
  routingVerifiedAt: string | null;
  tlsReadyAt: string | null;
  lastCheckedAt: string | null;
  lastErrorCode: string | null;
}

const customDomainColumns = `
  id,
  hostname,
  status,
  ownership_token AS "ownershipToken",
  ownership_verified_at AS "ownershipVerifiedAt",
  routing_verified_at AS "routingVerifiedAt",
  tls_ready_at AS "tlsReadyAt",
  last_checked_at AS "lastCheckedAt",
  last_error_code AS "lastErrorCode"
`;

function toCustomDomain(row: Record<string, unknown>): CustomDomain {
  const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : null);
  return {
    id: row.id as string,
    hostname: row.hostname as string,
    status: row.status as CustomDomain["status"],
    ownershipToken: row.ownershipToken as string,
    ownershipVerifiedAt: iso(row.ownershipVerifiedAt),
    routingVerifiedAt: iso(row.routingVerifiedAt),
    tlsReadyAt: iso(row.tlsReadyAt),
    lastCheckedAt: iso(row.lastCheckedAt),
    lastErrorCode: (row.lastErrorCode as string | null) ?? null,
  };
}

/** Registers a custom hostname as pending. It's never active on submission. */
export async function addCustomDomain(tenantId: string, hostname: string): Promise<CustomDomain> {
  try {
    const result = await pool.query(
      `
      INSERT INTO tenant_domains (tenant_id, hostname, domain_type, status, is_primary, ownership_token)
      SELECT id, $2, 'custom', 'pending', FALSE, $3
      FROM tenants
      WHERE id = $1
      RETURNING ${customDomainColumns}
      `,
      [tenantId, hostname, randomBytes(24).toString("base64url")],
    );
    if (result.rowCount !== 1) throw new DomainConflictError("TENANT_NOT_FOUND", "Organization not found.");
    return toCustomDomain(result.rows[0]);
  } catch (error) {
    if ((error as { code?: string }).code === "23505") {
      throw new DomainConflictError("DOMAIN_ALREADY_EXISTS", "This hostname is already registered.");
    }
    throw error;
  }
}

export async function listCustomDomains(tenantId: string): Promise<CustomDomain[]> {
  const result = await pool.query(
    `SELECT ${customDomainColumns} FROM tenant_domains WHERE tenant_id = $1 AND domain_type = 'custom' ORDER BY created_at`,
    [tenantId],
  );
  return result.rows.map(toCustomDomain);
}

export async function getCustomDomain(tenantId: string, domainId: string): Promise<CustomDomain | null> {
  const result = await pool.query(
    `SELECT ${customDomainColumns} FROM tenant_domains WHERE tenant_id = $1 AND id = $2 AND domain_type = 'custom'`,
    [tenantId, domainId],
  );
  return result.rows[0] ? toCustomDomain(result.rows[0]) : null;
}
