import type { AuthUser } from "../auth/auth.types.js";
import type { CreateOrganizationBody } from "./organization.schemas.js";

import {
  registerOrganization,
  type RegistrationResult,
} from "./organization.repository.js";

export class OrganizationRequestError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "OrganizationRequestError";
  }
}

const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function readBaseDomain(): string {
  const value = process.env.PLATFORM_BASE_DOMAIN
    ?.trim()
    .toLowerCase();

  if (!value) {
    throw new Error("Missing PLATFORM_BASE_DOMAIN");
  }

  const labels = value.split(".");

  if (
    value.length > 253 ||
    labels.length < 2 ||
    !labels.every((label) => DNS_LABEL.test(label))
  ) {
    throw new Error(
      "PLATFORM_BASE_DOMAIN must be a hostname without protocol, port, or path",
    );
  }

  return value;
}

const baseDomain = readBaseDomain();

const reservedSlugs = new Set([
  "admin",
  "api",
  "app",
  "auth",
  "dashboard",
  "keycloak",
  "login",
  "mail",
  "static",
  "status",
  "support",
  "www",
]);

export async function createOrganization(
  body: CreateOrganizationBody,
  idempotencyKey: string,
  actor: AuthUser,
): Promise<RegistrationResult> {
  if (actor.status !== "active" || !actor.isPlatformAdmin) {
    throw new OrganizationRequestError(
      403,
      "FORBIDDEN",
      "An active platform administrator is required.",
    );
  }

  const name = body.name.trim();
  const slug = body.slug.trim().toLowerCase();
  const secretaryEmail = body.secretaryEmail.trim().toLowerCase();
  const normalizedKey = idempotencyKey.trim().toLowerCase();

  if (name.length < 2 || name.length > 150) {
    throw new OrganizationRequestError(
      400,
      "INVALID_NAME",
      "Organization name must contain between 2 and 150 characters.",
    );
  }

  if (
    slug.length < 3 ||
    slug.length > 63 ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)
  ) {
    throw new OrganizationRequestError(
      400,
      "INVALID_SLUG",
      "Use 3–63 lowercase letters, numbers, and separating hyphens.",
    );
  }

  if (reservedSlugs.has(slug)) {
    throw new OrganizationRequestError(
      400,
      "RESERVED_SLUG",
      "This slug is reserved. Choose another.",
    );
  }

  // The route's JSON schema performs email-format validation.
  if (
    !secretaryEmail ||
    secretaryEmail.length > 254
  ) {
    throw new OrganizationRequestError(
      400,
      "INVALID_EMAIL",
      "A valid secretary email address is required.",
    );
  }

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      normalizedKey,
    )
  ) {
    throw new OrganizationRequestError(
      400,
      "INVALID_IDEMPOTENCY_KEY",
      "Idempotency-Key must be a UUID.",
    );
  }

  const hostname = `${slug}.${baseDomain}`;

  if (hostname.length > 253) {
    throw new OrganizationRequestError(
      400,
      "INVALID_HOSTNAME",
      "The generated organization hostname is too long.",
    );
  }

  return registerOrganization({
    name,
    slug,
    secretaryEmail,
    hostname,
    requestedBy: actor.id,
    idempotencyKey: normalizedKey,
  });
}