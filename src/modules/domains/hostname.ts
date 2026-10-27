// Hostname normalization shared by registration, routing and checks.

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * "Org-A.Localhost:3000." → "org-a.localhost". Returns null for anything
 * that isn't a plain DNS hostname (IP literals, userinfo, paths, IDN without
 * punycode, empty labels).
 */
export function normalizeHostname(raw: unknown): string | null {
  if (typeof raw !== "string") return null;

  let value = raw.trim().toLowerCase();
  // Strip a port, but not from IPv6 literals (which we reject anyway).
  const port = /^([^:[\]]+):(\d{1,5})$/.exec(value);
  if (port) value = port[1]!;
  if (value.endsWith(".")) value = value.slice(0, -1);

  if (!value || value.length > 253) return null;
  const labels = value.split(".");
  if (!labels.every((label) => LABEL.test(label))) return null;
  // Reject IPv4 literals such as 127.0.0.1.
  if (labels.length === 4 && labels.every((label) => /^\d+$/.test(label))) return null;

  return value;
}

/** True when `hostname` is exactly one label below `baseDomain`. */
export function isDirectSubdomain(hostname: string, baseDomain: string): boolean {
  if (!hostname.endsWith(`.${baseDomain}`)) return false;
  const label = hostname.slice(0, -(baseDomain.length + 1));
  return LABEL.test(label);
}
