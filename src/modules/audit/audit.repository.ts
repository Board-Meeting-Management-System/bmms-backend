import type { PoolClient } from "pg";

import { pool } from "../../db.js";

// The control plane's audit log (audit_events, append-only).
//
// Action names are "<subject>.<verb>", e.g. organization.suspended. The
// actor is an admin-realm identity, or null for the system. Metadata is
// for small, non-secret facts (codes, counts, hostnames) — never tokens,
// codes, passwords or full email bodies.

/**
 * Who acted. An admin-realm identity (id, with email or looked up), someone
 * outside the admin realm such as the secretary (id null, email as label),
 * or null for the system.
 */
export type AuditActor = { id: string | null; email: string | null } | null;

export interface AuditInput {
  actor: AuditActor;
  action: string;
  tenantId?: string | null;
  /** Snapshot; looked up from tenantId when omitted. */
  tenantName?: string | null;
  metadata?: Record<string, string | number | boolean | null>;
}

const ACTION = /^[a-z][a-z_]*(\.[a-z][a-z_]*)+$/;

/**
 * Writes one event. Pass `client` to make it part of the action's own
 * transaction (it then commits or rolls back with it).
 */
export async function recordAudit(input: AuditInput, client?: PoolClient): Promise<void> {
  if (!ACTION.test(input.action)) throw new Error(`Invalid audit action: ${input.action}`);
  await (client ?? pool).query(
    `
    INSERT INTO audit_events (actor_identity_id, actor_label, action, tenant_id, tenant_name, metadata)
    VALUES (
      $1::uuid,
      CASE
        WHEN $1::uuid IS NULL THEN $2::text
        ELSE COALESCE($2::text, (SELECT email FROM identities WHERE id = $1::uuid), 'Administrator')
      END,
      $3, $4::uuid,
      COALESCE($5::text, (SELECT name FROM tenants WHERE id = $4::uuid)),
      $6::jsonb
    )
    `,
    [
      input.actor?.id ?? null,
      input.actor?.email ?? null,
      input.action,
      input.tenantId ?? null,
      input.tenantName ?? null,
      JSON.stringify(input.metadata ?? {}),
    ],
  );
}

/**
 * Best effort, for events recorded after the action already happened: a
 * failure to log is reported but never undoes or fails the action.
 */
export async function recordAuditSafely(input: AuditInput): Promise<void> {
  try {
    await recordAudit(input);
  } catch {
    console.error(JSON.stringify({ event: "audit_write_failed", action: input.action }));
  }
}

export interface AuditEvent {
  id: string;
  occurredAt: string;
  actorId: string | null;
  /** Who acted: an admin's email, "System", or e.g. the secretary's email in metadata. */
  actorLabel: string | null;
  action: string;
  tenantId: string | null;
  tenantName: string | null;
  metadata: Record<string, unknown>;
}

/** Newest first. `before` is the id of the last event of the previous page. */
export async function listAuditEvents(options: {
  tenantId?: string;
  limit?: number;
  before?: string;
}): Promise<AuditEvent[]> {
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200);
  const result = await pool.query<{
    id: string;
    occurredAt: Date;
    actorId: string | null;
    actorLabel: string | null;
    action: string;
    tenantId: string | null;
    tenantName: string | null;
    metadata: Record<string, unknown>;
  }>(
    `
    SELECT
      id::text AS id,
      occurred_at AS "occurredAt",
      actor_identity_id AS "actorId",
      actor_label AS "actorLabel",
      action,
      tenant_id AS "tenantId",
      tenant_name AS "tenantName",
      metadata
    FROM audit_events
    WHERE ($1::uuid IS NULL OR tenant_id = $1::uuid)
      AND ($2::bigint IS NULL OR id < $2::bigint)
    ORDER BY id DESC
    LIMIT $3
    `,
    [options.tenantId ?? null, options.before ?? null, limit],
  );
  return result.rows.map((row) => ({ ...row, occurredAt: row.occurredAt.toISOString() }));
}
