import type { FastifyInstance } from "fastify";

import { pool } from "../../db.js";
import { authenticate } from "../auth/authenticate.js";
import { authConfig } from "../auth/auth.config.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { domainProvider } from "../domains/domain-provider.js";
import { deletionGraceHours } from "../organizations/lifecycle.repository.js";
import { storageProvider } from "../storage/storage-provider.js";
import { usageIntervalMinutes, usageLimits } from "../usage/usage.repository.js";

const admin = { onRequest: [authenticate, requirePlatformAdmin] };

export interface PlatformNotification {
  /** Stable while the condition lasts, e.g. provisioning_failed:<tenantId>. */
  id: string;
  severity: "critical" | "warning" | "info";
  title: string;
  detail: string;
  tenantId: string | null;
  tenantName: string | null;
  since: string | null;
}

/**
 * Current conditions needing attention, derived live from state — so a
 * notification disappears as soon as its cause is fixed.
 */
async function currentNotifications(): Promise<PlatformNotification[]> {
  const limits = usageLimits();
  const [failedJobs, failedDomains, failedDeliveries, deletions, nearLimits, usageErrors, pendingAdmins] = await Promise.all([
    pool.query<{ tenantId: string; name: string; errorCode: string | null; since: Date }>(`
      SELECT DISTINCT ON (t.id) t.id AS "tenantId", t.name, j.last_error_code AS "errorCode", j.updated_at AS since
      FROM provisioning_jobs j JOIN tenants t ON t.id = j.tenant_id
      WHERE j.status = 'failed' AND t.deletion_scheduled_for IS NULL
      ORDER BY t.id, j.created_at DESC`),
    pool.query<{ tenantId: string; name: string; hostname: string; errorCode: string | null; since: Date | null }>(`
      SELECT t.id AS "tenantId", t.name, d.hostname, d.last_error_code AS "errorCode", d.last_checked_at AS since
      FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id
      WHERE d.is_primary AND d.status = 'failed' AND t.status = 'active'`),
    pool.query<{ tenantId: string; name: string; errorCode: string | null; since: Date }>(`
      SELECT t.id AS "tenantId", t.name, q.last_error_code AS "errorCode", q.updated_at AS since
      FROM invitation_deliveries q
      JOIN tenant_invitations i ON i.id = q.invitation_id
      JOIN tenants t ON t.id = i.tenant_id
      WHERE q.status = 'failed' AND i.status IN ('pending_setup', 'pending')`),
    pool.query<{ tenantId: string; name: string; due: Date }>(`
      SELECT id AS "tenantId", name, deletion_scheduled_for AS due
      FROM tenants WHERE deletion_scheduled_for IS NOT NULL ORDER BY deletion_scheduled_for`),
    pool.query<{ tenantId: string; name: string; databaseBytes: string | null; storageBytes: string | null; since: Date }>(
      `
      SELECT t.id AS "tenantId", t.name, u.database_bytes AS "databaseBytes", u.storage_bytes AS "storageBytes", u.collected_at AS since
      FROM tenant_usage u JOIN tenants t ON t.id = u.tenant_id
      WHERE u.database_bytes >= $1 OR u.storage_bytes >= $2`,
      [limits.databaseWarnBytes, limits.storageWarnBytes],
    ),
    pool.query<{ tenantId: string; name: string; errorCode: string; since: Date }>(`
      SELECT t.id AS "tenantId", t.name, u.last_error_code AS "errorCode", u.collected_at AS since
      FROM tenant_usage u JOIN tenants t ON t.id = u.tenant_id
      WHERE u.last_error_code IS NOT NULL AND t.status = 'active'`),
    pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM platform_admin_invitations`),
  ]);

  const iso = (d: Date | null) => (d ? d.toISOString() : null);
  const notes: PlatformNotification[] = [];

  for (const r of failedJobs.rows) {
    notes.push({ id: `provisioning_failed:${r.tenantId}`, severity: "critical", title: "Provisioning failed",
      detail: `Setup stopped${r.errorCode ? ` (${r.errorCode})` : ""}. Retry it from the organization's page.`,
      tenantId: r.tenantId, tenantName: r.name, since: iso(r.since) });
  }
  for (const r of failedDomains.rows) {
    notes.push({ id: `domain_failed:${r.tenantId}`, severity: "critical", title: "Address check failed",
      detail: `${r.hostname} isn't reaching this organization${r.errorCode ? ` (${r.errorCode})` : ""}.`,
      tenantId: r.tenantId, tenantName: r.name, since: iso(r.since) });
  }
  for (const r of failedDeliveries.rows) {
    notes.push({ id: `invitation_failed:${r.tenantId}`, severity: "warning", title: "Invitation email not delivered",
      detail: `The automatic secretary invitation failed${r.errorCode ? ` (${r.errorCode})` : ""}. Send it manually.`,
      tenantId: r.tenantId, tenantName: r.name, since: iso(r.since) });
  }
  for (const r of deletions.rows) {
    const soon = r.due.getTime() - Date.now() < 48 * 3600 * 1000;
    notes.push({ id: `deletion_scheduled:${r.tenantId}`, severity: soon ? "warning" : "info", title: "Deletion scheduled",
      detail: `All of this organization's data will be deleted on ${r.due.toISOString().slice(0, 16).replace("T", " ")} UTC.`,
      tenantId: r.tenantId, tenantName: r.name, since: null });
  }
  for (const r of nearLimits.rows) {
    const parts = [
      r.databaseBytes !== null && Number(r.databaseBytes) >= limits.databaseWarnBytes ? "database" : null,
      r.storageBytes !== null && Number(r.storageBytes) >= limits.storageWarnBytes ? "storage" : null,
    ].filter(Boolean);
    notes.push({ id: `usage_limit:${r.tenantId}`, severity: "warning", title: "Near usage limit",
      detail: `The organization's ${parts.join(" and ")} is above the warning level.`,
      tenantId: r.tenantId, tenantName: r.name, since: iso(r.since) });
  }
  for (const r of usageErrors.rows) {
    notes.push({ id: `usage_error:${r.tenantId}`, severity: "info", title: "Usage couldn't be measured",
      detail: `Last measurement reported ${r.errorCode}.`, tenantId: r.tenantId, tenantName: r.name, since: iso(r.since) });
  }
  const pending = pendingAdmins.rows[0]?.count ?? 0;
  if (pending > 0) {
    notes.push({ id: "admin_pending", severity: "info", title: "Administrator access pending",
      detail: `${pending} ${pending === 1 ? "person has" : "people have"} been granted access but haven't signed in yet.`,
      tenantId: null, tenantName: null, since: null });
  }

  const order = { critical: 0, warning: 1, info: 2 };
  return notes.sort((a, b) => order[a.severity] - order[b.severity]);
}

export async function platformRoutes(app: FastifyInstance) {
  app.get("/admin/notifications", admin, async (_request, reply) => {
    reply.header("Cache-Control", "no-store");
    return { notifications: await currentNotifications() };
  });

  // The effective configuration, for the Settings page. Read-only: it comes
  // from the environment. Never includes secrets — only whether they're set.
  app.get("/admin/platform/settings", admin, async (_request, reply) => {
    reply.header("Cache-Control", "no-store");
    const domains = domainProvider();
    const limits = usageLimits();
    const token = process.env.ORG_PLATFORM_SERVICE_TOKEN?.trim() ?? "";
    return {
      settings: {
        environment: process.env.NODE_ENV ?? "development",
        domains: {
          provider: domains.kind,
          baseDomain: domains.baseDomain,
          organizationUrlTemplate: domains.tenantUrl(domains.platformHostname("{slug}")),
        },
        storage: { provider: storageProvider().kind },
        email: { delivery: process.env.EMAIL_DELIVERY?.trim() || "smtp" },
        organizationPlatform: {
          origin: process.env.ORG_PLATFORM_ORIGIN?.trim() || null,
          internalApiEnabled: token.length >= 32,
          organizationRealmConfigured: Boolean(process.env.ORG_OIDC_ISSUER?.trim()),
        },
        security: {
          administratorMfaRequired: process.env.ADMIN_REQUIRE_MFA?.trim() === "true",
          // Keycloak's account console, where admins change password and set up MFA.
          accountConsoleUrl: `${authConfig.issuer.replace(/\/+$/, "")}/account`,
        },
        lifecycle: { deletionGraceHours: deletionGraceHours() },
        usage: {
          intervalMinutes: usageIntervalMinutes(),
          databaseWarnBytes: limits.databaseWarnBytes,
          storageWarnBytes: limits.storageWarnBytes,
        },
      },
    };
  });
}
