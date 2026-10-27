import { pool } from "../../db.js";
import { domainProvider } from "../domains/domain-provider.js";
import { listCustomDomains } from "../domains/domain.repository.js";

// Admin view of an organization's onboarding, as separate facts: each
// status reflects only its own source of truth. Built from an explicit
// column list so no secret reference, hash or credential can leak in.

export type EmailVerificationStatus =
  | "not_requested"
  /** SMTP outcome not recorded yet, or recording failed. */
  | "delivery_unconfirmed"
  | "delivery_failed"
  | "code_sent"
  | "code_expired"
  | "attempts_exhausted"
  | "verified";

export interface TenantOnboarding {
  tenant: {
    id: string;
    name: string;
    slug: string;
    status: "provisioning" | "active" | "failed" | "suspended";
    createdAt: string;
  };
  infrastructure: {
    /** Latest provisioning job; null if none exists. */
    jobId: string | null;
    status: "pending" | "running" | "failed" | "succeeded" | null;
  };
  domain: {
    hostname: string;
    type: "platform" | "custom";
    status: "pending" | "active" | "failed";
    /** The organization's address (shown once known; usable once active). */
    url: string;
    provider: "local" | "production";
    ownershipVerifiedAt: string | null;
    routingVerifiedAt: string | null;
    tlsReadyAt: string | null;
    lastCheckedAt: string | null;
    lastErrorCode: string | null;
  } | null;
  /** Private file storage configured by provisioning. */
  storage: { configured: boolean };
  customDomains: Array<{
    id: string;
    hostname: string;
    status: "pending" | "active" | "failed";
    lastErrorCode: string | null;
  }>;
  /** "Open organization" is offered only when provisioning and the domain are done. */
  readiness: { canOpen: boolean; organizationUrl: string | null };
  secretary: {
    invitationId: string;
    email: string;
    invitationStatus: "pending_setup" | "pending" | "accepted" | "expired" | "revoked";
    /** When the current invitation link stops working; null before it's sent. */
    linkExpiresAt: string | null;
    linkExpired: boolean;
    emailVerification: {
      status: EmailVerificationStatus;
      lastSentAt: string | null;
      codeExpiresAt: string | null;
      verifiedAt: string | null;
    };
    membership: {
      accepted: boolean;
      acceptedAt: string | null;
    };
    /** The automatic invitation queued at activation; null if none was queued. */
    delivery: {
      status: "queued" | "sending" | "sent" | "failed" | "skipped";
      attempts: number;
      lastErrorCode: string | null;
    } | null;
  } | null;
}

const iso = (value: Date | null) => (value ? value.toISOString() : null);

export async function getTenantOnboarding(
  tenantId: string,
): Promise<TenantOnboarding | null> {
  const tenants = await pool.query<{
    id: string;
    name: string;
    slug: string;
    status: TenantOnboarding["tenant"]["status"];
    createdAt: Date;
  }>(
    `
    SELECT id, name, slug, status, created_at AS "createdAt"
    FROM tenants
    WHERE id = $1
    `,
    [tenantId],
  );

  const tenant = tenants.rows[0];
  if (!tenant) return null;

  const [jobs, domains, invitations, storage, customDomains] = await Promise.all([
    pool.query<{ id: string; status: TenantOnboarding["infrastructure"]["status"] }>(
      `
      SELECT id, status
      FROM provisioning_jobs
      WHERE tenant_id = $1
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [tenantId],
    ),
    pool.query<{
      hostname: string;
      type: "platform" | "custom";
      status: "pending" | "active" | "failed";
      ownershipVerifiedAt: Date | null;
      routingVerifiedAt: Date | null;
      tlsReadyAt: Date | null;
      lastCheckedAt: Date | null;
      lastErrorCode: string | null;
    }>(
      `
      SELECT
        hostname,
        domain_type AS type,
        status,
        ownership_verified_at AS "ownershipVerifiedAt",
        routing_verified_at AS "routingVerifiedAt",
        tls_ready_at AS "tlsReadyAt",
        last_checked_at AS "lastCheckedAt",
        last_error_code AS "lastErrorCode"
      FROM tenant_domains
      WHERE tenant_id = $1
        AND is_primary = TRUE
      `,
      [tenantId],
    ),
    pool.query<{
      id: string;
      email: string;
      status: NonNullable<TenantOnboarding["secretary"]>["invitationStatus"];
      linkExpiresAt: Date | null;
      linkExpired: boolean;
      verifiedAt: Date | null;
      acceptedAt: Date | null;
      lastSentAt: Date | null;
      codeExpiresAt: Date | null;
      codeExpired: boolean | null;
      consumed: boolean | null;
      attempts: number | null;
      deliveryStatus: "pending" | "sent" | "failed" | null;
      challengeEmail: string | null;
      queueStatus: NonNullable<NonNullable<TenantOnboarding["secretary"]>["delivery"]>["status"] | null;
      queueAttempts: number | null;
      queueErrorCode: string | null;
    }>(
      `
      SELECT
        invitation.id,
        invitation.email,
        invitation.status,
        invitation.expires_at AS "linkExpiresAt",
        COALESCE(invitation.expires_at <= clock_timestamp(), FALSE) AS "linkExpired",
        invitation.email_verified_at AS "verifiedAt",
        invitation.accepted_at AS "acceptedAt",
        challenge.last_requested_at AS "lastSentAt",
        challenge.expires_at AS "codeExpiresAt",
        challenge.expires_at <= clock_timestamp() AS "codeExpired",
        challenge.consumed_at IS NOT NULL AS consumed,
        challenge.attempts,
        challenge.delivery_status AS "deliveryStatus",
        challenge.email AS "challengeEmail",
        queue.status AS "queueStatus",
        queue.attempts AS "queueAttempts",
        queue.last_error_code AS "queueErrorCode"
      FROM tenant_invitations AS invitation
      LEFT JOIN secretary_email_verifications AS challenge
        ON challenge.invitation_id = invitation.id
      LEFT JOIN invitation_deliveries AS queue
        ON queue.invitation_id = invitation.id
      WHERE invitation.tenant_id = $1
        AND invitation.role = 'secretary'
      ORDER BY invitation.created_at DESC
      LIMIT 1
      `,
      [tenantId],
    ),
    pool.query<{ configured: boolean }>(
      `SELECT storage_ref IS NOT NULL AS configured FROM tenant_resources WHERE tenant_id = $1`,
      [tenantId],
    ),
    listCustomDomains(tenantId),
  ]);

  const job = jobs.rows[0];
  const domain = domains.rows[0];
  const invitation = invitations.rows[0];
  const provider = domainProvider();
  const canOpen = job?.status === "succeeded" && tenant.status === "active" && domain?.status === "active";

  return {
    tenant: {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      status: tenant.status,
      createdAt: tenant.createdAt.toISOString(),
    },
    infrastructure: {
      jobId: job?.id ?? null,
      status: job?.status ?? null,
    },
    domain: domain
      ? {
          hostname: domain.hostname,
          type: domain.type,
          status: domain.status,
          url: provider.tenantUrl(domain.hostname),
          provider: provider.kind,
          ownershipVerifiedAt: iso(domain.ownershipVerifiedAt),
          routingVerifiedAt: iso(domain.routingVerifiedAt),
          tlsReadyAt: iso(domain.tlsReadyAt),
          lastCheckedAt: iso(domain.lastCheckedAt),
          lastErrorCode: domain.lastErrorCode,
        }
      : null,
    storage: { configured: storage.rows[0]?.configured ?? false },
    customDomains: customDomains.map((d) => ({
      id: d.id,
      hostname: d.hostname,
      status: d.status,
      lastErrorCode: d.lastErrorCode,
    })),
    readiness: {
      canOpen,
      organizationUrl: canOpen && domain ? provider.tenantUrl(domain.hostname) : null,
    },
    secretary: invitation
      ? {
          invitationId: invitation.id,
          email: invitation.email,
          invitationStatus: invitation.status,
          linkExpiresAt: iso(invitation.linkExpiresAt),
          linkExpired: invitation.linkExpired,
          emailVerification: {
            status: emailVerificationStatus(invitation),
            lastSentAt: iso(invitation.lastSentAt),
            codeExpiresAt: iso(invitation.codeExpiresAt),
            verifiedAt: iso(invitation.verifiedAt),
          },
          membership: {
            accepted: invitation.status === "accepted",
            acceptedAt: iso(invitation.acceptedAt),
          },
          delivery: invitation.queueStatus
            ? {
                status: invitation.queueStatus,
                attempts: invitation.queueAttempts ?? 0,
                lastErrorCode: invitation.queueErrorCode,
              }
            : null,
        }
      : null,
  };
}

function emailVerificationStatus(row: {
  email: string;
  verifiedAt: Date | null;
  challengeEmail: string | null;
  codeExpired: boolean | null;
  consumed: boolean | null;
  attempts: number | null;
  deliveryStatus: "pending" | "sent" | "failed" | null;
}): EmailVerificationStatus {
  if (row.verifiedAt) return "verified";
  // No challenge, or one for an earlier address.
  if (!row.deliveryStatus || row.challengeEmail !== row.email || row.consumed) {
    return "not_requested";
  }
  if (row.deliveryStatus === "failed") return "delivery_failed";
  if (row.deliveryStatus === "pending") return "delivery_unconfirmed";
  if (row.codeExpired) return "code_expired";
  if ((row.attempts ?? 0) >= 5) return "attempts_exhausted";
  return "code_sent";
}

/** One row per organization for admin lists and the dashboard. */
export interface TenantSummary {
  id: string;
  name: string;
  slug: string;
  status: TenantOnboarding["tenant"]["status"];
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  hostname: string | null;
  /** The organization's URL, once its domain is active. */
  url: string | null;
  domainType: "platform" | "custom" | null;
  domainStatus: "pending" | "active" | "failed" | null;
  jobId: string | null;
  jobStatus: TenantOnboarding["infrastructure"]["status"];
  /** When provisioning last finished (succeeded or failed). */
  jobFinishedAt: string | null;
  secretary: {
    invitationId: string;
    email: string;
    invitationStatus: NonNullable<TenantOnboarding["secretary"]>["invitationStatus"];
    lastSentAt: string | null;
    emailVerifiedAt: string | null;
    acceptedAt: string | null;
  } | null;
}

export async function listTenantSummaries(): Promise<TenantSummary[]> {
  const result = await pool.query<{
    id: string;
    name: string;
    slug: string;
    status: TenantSummary["status"];
    createdBy: string | null;
    createdAt: Date;
    updatedAt: Date;
    hostname: string | null;
    domainType: TenantSummary["domainType"];
    domainStatus: TenantSummary["domainStatus"];
    jobId: string | null;
    jobStatus: TenantSummary["jobStatus"];
    jobFinishedAt: Date | null;
    invitationId: string | null;
    secretaryEmail: string | null;
    invitationStatus: NonNullable<TenantSummary["secretary"]>["invitationStatus"] | null;
    lastSentAt: Date | null;
    emailVerifiedAt: Date | null;
    acceptedAt: Date | null;
  }>(
    `
    SELECT
      tenant.id,
      tenant.name,
      tenant.slug,
      tenant.status,
      tenant.created_by AS "createdBy",
      tenant.created_at AS "createdAt",
      tenant.updated_at AS "updatedAt",
      domain.hostname,
      domain.domain_type AS "domainType",
      domain.status AS "domainStatus",
      job.id AS "jobId",
      job.status AS "jobStatus",
      CASE WHEN job.status IN ('succeeded', 'failed') THEN job.updated_at END AS "jobFinishedAt",
      invitation.id AS "invitationId",
      invitation.email AS "secretaryEmail",
      invitation.status AS "invitationStatus",
      challenge.last_requested_at AS "lastSentAt",
      invitation.email_verified_at AS "emailVerifiedAt",
      invitation.accepted_at AS "acceptedAt"
    FROM tenants AS tenant
    LEFT JOIN tenant_domains AS domain
      ON domain.tenant_id = tenant.id AND domain.is_primary
    LEFT JOIN LATERAL (
      SELECT id, status, updated_at
      FROM provisioning_jobs
      WHERE tenant_id = tenant.id
      ORDER BY created_at DESC
      LIMIT 1
    ) AS job ON TRUE
    LEFT JOIN LATERAL (
      SELECT id, email, status, email_verified_at, accepted_at
      FROM tenant_invitations
      WHERE tenant_id = tenant.id AND role = 'secretary'
      ORDER BY created_at DESC
      LIMIT 1
    ) AS invitation ON TRUE
    LEFT JOIN secretary_email_verifications AS challenge
      ON challenge.invitation_id = invitation.id
    ORDER BY tenant.created_at DESC
    `,
  );

  return result.rows.map((row) => ({
    id: row.id,
    name: row.name,
    slug: row.slug,
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    hostname: row.hostname,
    url: row.hostname && row.domainStatus === "active" ? domainProvider().tenantUrl(row.hostname) : null,
    domainType: row.domainType,
    domainStatus: row.domainStatus,
    jobId: row.jobId,
    jobStatus: row.jobStatus,
    jobFinishedAt: iso(row.jobFinishedAt),
    secretary:
      row.invitationId && row.secretaryEmail && row.invitationStatus
        ? {
            invitationId: row.invitationId,
            email: row.secretaryEmail,
            invitationStatus: row.invitationStatus,
            lastSentAt: iso(row.lastSentAt),
            emailVerifiedAt: iso(row.emailVerifiedAt),
            acceptedAt: iso(row.acceptedAt),
          }
        : null,
  }));
}
