import type { FastifyReply, FastifyRequest } from "fastify";

import { authenticateSessionRecord } from "../auth/session-auth.service.js";
import type { AuthUser } from "../auth/auth.types.js";
import { pool } from "../../db.js";
import { domainProvider } from "../domains/domain-provider.js";
import { resolveTenantByHostname, type ResolvedTenant } from "../domains/domain.repository.js";
import { normalizeHostname } from "../domains/hostname.js";

// Central tenant resolution. The organization comes only from the request's
// hostname, matched exactly against registered domains. Forwarded host
// headers count only from TRUST_PROXY addresses (Fastify's request.host).
// Unknown hosts are rejected; there is no default organization.

export interface TenantMembership {
  role: "secretary";
}

declare module "fastify" {
  interface FastifyRequest {
    tenant: ResolvedTenant | null;
    membership: TenantMembership | null;
  }
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function requestHostname(request: FastifyRequest): string | null {
  return normalizeHostname(request.host);
}

function tenantNotFound(reply: FastifyReply) {
  return reply.code(404).send({ error: "TENANT_NOT_FOUND", message: "No organization is available at this address." });
}

/** Resolves the organization for this hostname (active domain and organization). */
export async function resolveTenant(request: FastifyRequest, reply: FastifyReply) {
  reply.header("Cache-Control", "no-store");
  const hostname = requestHostname(request);
  const tenant = hostname ? await resolveTenantByHostname(hostname, "ready") : null;
  if (!tenant) return tenantNotFound(reply);
  request.tenant = tenant;
}

/** Membership in a tenant, from the control database. */
export async function findMembership(tenantId: string, identityId: string): Promise<TenantMembership | null> {
  const result = await pool.query<TenantMembership>(
    `SELECT role FROM tenant_memberships WHERE tenant_id = $1 AND identity_id = $2`,
    [tenantId, identityId],
  );
  return result.rows[0] ?? null;
}

/**
 * Validates the session for the resolved organization: it must be bound to
 * this exact hostname (a platform session, or one from another
 * organization's domain, is refused). Writes need this host's Origin.
 */
export async function authenticateTenantSession(request: FastifyRequest, reply: FastifyReply) {
  const tenant = request.tenant;
  if (!tenant) return tenantNotFound(reply);

  const unauthorized = () =>
    reply.code(401).send({ error: "UNAUTHORIZED", message: "Sign in to this organization." });

  const token = request.cookies.bmms_session;
  if (!token) return unauthorized();

  if (!SAFE_METHODS.has(request.method) && request.headers.origin !== domainProvider().tenantOrigin(tenant.hostname)) {
    return reply.code(403).send({ error: "ORIGIN_NOT_ALLOWED", message: "Request origin is not allowed." });
  }

  let session: Awaited<ReturnType<typeof authenticateSessionRecord>>;
  try {
    session = await authenticateSessionRecord(token);
  } catch {
    request.log.error({ event: "tenant_session_failed" }, "Tenant session authentication failed");
    return reply.code(503).send({ error: "AUTH_UNAVAILABLE", message: "Authentication is temporarily unavailable." });
  }

  if (!session || session.boundHost !== tenant.hostname) return unauthorized();
  request.authUser = session.user;
}

/** Requires membership in the resolved organization. Platform admins get no implicit access. */
export async function requireTenantMember(request: FastifyRequest, reply: FastifyReply) {
  const user: AuthUser | null = request.authUser;
  if (!request.tenant || !user) return reply.code(401).send({ error: "UNAUTHORIZED", message: "Sign in to this organization." });

  const membership = await findMembership(request.tenant.tenantId, user.id);
  if (!membership) {
    return reply.code(403).send({ error: "NOT_A_MEMBER", message: "Your account isn't a member of this organization." });
  }
  request.membership = membership;
}
