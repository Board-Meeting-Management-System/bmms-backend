export interface TenantResourceNames {
  database: string;
  ownerRole: string;
  runtimeRole: string;
}

export function getTenantResourceNames(
  tenantId: string,
): TenantResourceNames {
  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  if (!uuidPattern.test(tenantId)) {
    throw new Error("Invalid tenant ID.");
  }

  const suffix = tenantId.replaceAll("-", "").toLowerCase();

  return {
    database: `bmms_t_${suffix}`,
    ownerRole: `bmms_owner_${suffix}`,
    runtimeRole: `bmms_app_${suffix}`,
  };
}

// SQL parameters cannot represent database or role identifiers.
// Only allow our generated identifier format before quoting it.
export function quoteResourceIdentifier(value: string): string {
  if (
    value.length > 63 ||
    !/^[a-z][a-z0-9_]*$/.test(value)
  ) {
    throw new Error("Invalid PostgreSQL resource identifier.");
  }

  return `"${value}"`;
}