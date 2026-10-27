import { randomBytes } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";

import { isDirectSubdomain, normalizeHostname } from "./hostname.js";
import { isUnknownTenantResponse, probe, readRoutingIdentity, type ProbeResult } from "./http-probe.js";

// How organization hostnames are served and verified. One shared app serves
// every organization; a provider never creates per-organization servers.
//
//   DOMAIN_PROVIDER=local       <slug>.localhost on the dev server
//   DOMAIN_PROVIDER=production  <slug>.<PLATFORM_BASE_DOMAIN> behind
//                               preconfigured wildcard DNS, ingress and TLS
//
// Shared platform infrastructure (wildcard DNS, ingress, certificate) is
// checked by checkPlatform(); each organization's mapping by verifyHostname().

export type DomainStatus = "active" | "pending" | "failed";

export interface DomainCheck {
  status: DomainStatus;
  /** Why it isn't active; stable codes for UI and retries. */
  errorCode: string | null;
  routingVerified: boolean;
  /** null when TLS doesn't apply (local http). */
  tlsVerified: boolean | null;
  ownershipVerified?: boolean;
}

export interface PlatformCheck {
  status: DomainStatus;
  errorCode: string | null;
  provider: "local" | "production";
  baseDomain: string;
}

export interface DomainProvider {
  readonly kind: "local" | "production";
  readonly baseDomain: string;
  /** "<slug>.<base>" — the slug is validated by registration. */
  platformHostname(slug: string): string;
  /** The URL people open for an organization hostname. */
  tenantUrl(hostname: string): string;
  /** Origin the browser uses on a tenant hostname (for Origin checks). */
  tenantOrigin(hostname: string): string;
  checkPlatform(): Promise<PlatformCheck>;
  /** Does a request for `hostname` reach this app and resolve to `tenantId`? */
  verifyHostname(hostname: string, tenantId: string): Promise<DomainCheck>;
  /** Custom domains: ownership (DNS TXT), routing and TLS. */
  verifyCustomDomain(hostname: string, tenantId: string, ownershipToken: string): Promise<DomainCheck>;
}

const ROUTING_PATH = "/bmms-routing";
const TIMEOUT_MS = 5_000;

const pending = (errorCode: string, extra: Partial<DomainCheck> = {}): DomainCheck => ({
  status: "pending",
  errorCode,
  routingVerified: false,
  tlsVerified: null,
  ...extra,
});
const failed = (errorCode: string, extra: Partial<DomainCheck> = {}): DomainCheck => ({
  status: "failed",
  errorCode,
  routingVerified: false,
  tlsVerified: null,
  ...extra,
});

/** Interprets a /bmms-routing response for `hostname` → `tenantId`. */
function routingResult(result: ProbeResult, hostname: string, tenantId: string, tls: boolean | null): DomainCheck {
  if (!result.ok) {
    if (result.errorCode === "TLS_INVALID") return failed("TLS_INVALID", { tlsVerified: false });
    if (result.errorCode === "BAD_RESPONSE") return failed("ROUTING_UNEXPECTED_RESPONSE", { tlsVerified: tls });
    return pending(result.errorCode === "TIMEOUT" ? "ROUTING_TIMEOUT" : "ROUTING_UNREACHABLE");
  }
  if (isUnknownTenantResponse(result)) return failed("ROUTING_TENANT_UNKNOWN", { tlsVerified: tls });
  const identity = readRoutingIdentity(result.body);
  if (result.status !== 200 || !identity) return failed("ROUTING_UNEXPECTED_RESPONSE", { tlsVerified: tls });
  if (identity.hostname !== hostname || identity.organizationId !== tenantId) {
    return failed("ROUTING_WRONG_ORGANIZATION", { tlsVerified: tls });
  }
  return { status: "active", errorCode: null, routingVerified: true, tlsVerified: tls };
}

// ---- Local --------------------------------------------------------------------

export interface LocalProviderOptions {
  baseDomain: string;
  /** The frontend origin, e.g. http://localhost:3000: scheme and port for tenant URLs. */
  frontendOrigin: string;
  /** Loopback origin the routing check connects to. */
  routingCheckOrigin: string;
}

/**
 * Development: every organization is <slug>.localhost on the one dev server.
 * Browsers resolve *.localhost to this machine by themselves, so no DNS is
 * involved. Verification proves only that the dev server routes the hostname
 * to the right organization; it never claims DNS or TLS.
 */
export class LocalDomainProvider implements DomainProvider {
  readonly kind = "local" as const;
  readonly baseDomain: string;
  private readonly frontend: URL;
  private readonly check: URL;

  constructor(options: LocalProviderOptions) {
    this.baseDomain = options.baseDomain;
    this.frontend = new URL(options.frontendOrigin);
    this.check = new URL(options.routingCheckOrigin);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(this.check.hostname) || this.check.protocol !== "http:") {
      throw new Error("LOCAL_ROUTING_CHECK_ORIGIN must be an http loopback origin.");
    }
  }

  platformHostname(slug: string) {
    return `${slug}.${this.baseDomain}`;
  }

  tenantOrigin(hostname: string) {
    return `${this.frontend.protocol}//${hostname}${this.frontend.port ? `:${this.frontend.port}` : ""}`;
  }

  tenantUrl(hostname: string) {
    return `${this.tenantOrigin(hostname)}/`;
  }

  private probeHost(hostname: string) {
    return probe({
      protocol: "http:",
      address: this.check.hostname.replace(/^\[|\]$/g, ""),
      port: Number(this.check.port || 80),
      hostname,
      path: ROUTING_PATH,
      timeoutMs: TIMEOUT_MS,
    });
  }

  async checkPlatform(): Promise<PlatformCheck> {
    // Any unregistered name must reach the app and be refused by it.
    const result = await this.probeHost(`bmms-check-${randomBytes(6).toString("hex")}.${this.baseDomain}`);
    const base = { provider: this.kind, baseDomain: this.baseDomain };
    if (isUnknownTenantResponse(result)) return { ...base, status: "active", errorCode: null };
    if (!result.ok) return { ...base, status: "pending", errorCode: "LOCAL_APP_UNREACHABLE" };
    return { ...base, status: "failed", errorCode: "ROUTING_UNEXPECTED_RESPONSE" };
  }

  async verifyHostname(hostname: string, tenantId: string): Promise<DomainCheck> {
    if (!isDirectSubdomain(hostname, this.baseDomain)) return failed("HOSTNAME_OUTSIDE_BASE_DOMAIN");
    const result = await this.probeHost(hostname);
    if (!result.ok && result.errorCode !== "BAD_RESPONSE") return pending("LOCAL_APP_UNREACHABLE");
    return routingResult(result, hostname, tenantId, null);
  }

  async verifyCustomDomain(): Promise<DomainCheck> {
    // Ownership and certificates can't be proven on a developer machine.
    return failed("CUSTOM_DOMAINS_REQUIRE_PRODUCTION_PROVIDER");
  }
}

// ---- Production -----------------------------------------------------------------

export interface DnsResolver {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
  resolveTxt(hostname: string): Promise<string[][]>;
}

export interface ProductionProviderOptions {
  baseDomain: string;
  /** Addresses the wildcard record and custom domains must point to. */
  ingressAddresses: string[];
  /** HTTPS port of the ingress (443 unless testing). */
  httpsPort?: number;
  resolver?: DnsResolver;
  /** Test hook: extra trusted CAs. */
  ca?: string | Buffer;
}

/**
 * Production: assumes shared infrastructure that an operator configures
 * once — a wildcard DNS record *.<base> → ingress, an ingress that sends
 * every host to this app, and a wildcard certificate. Nothing is created per
 * organization; each hostname is verified end to end before activation.
 */
export class ProductionDomainProvider implements DomainProvider {
  readonly kind = "production" as const;
  readonly baseDomain: string;
  private readonly ingress: Set<string>;
  private readonly port: number;
  private readonly resolver: DnsResolver;
  private readonly ca: string | Buffer | undefined;

  constructor(options: ProductionProviderOptions) {
    this.baseDomain = options.baseDomain;
    this.ingress = new Set(options.ingressAddresses);
    if (this.ingress.size === 0 || [...this.ingress].some((a) => !isIP(a))) {
      throw new Error("PLATFORM_INGRESS_ADDRESSES must list the ingress IP addresses.");
    }
    this.port = options.httpsPort ?? 443;
    this.resolver = options.resolver ?? new Resolver({ timeout: 3_000, tries: 2 });
    this.ca = options.ca;
  }

  platformHostname(slug: string) {
    return `${slug}.${this.baseDomain}`;
  }

  tenantOrigin(hostname: string) {
    return `https://${hostname}${this.port === 443 ? "" : `:${this.port}`}`;
  }

  tenantUrl(hostname: string) {
    return `${this.tenantOrigin(hostname)}/`;
  }

  /** Resolves `hostname`; every address must be one of the ingress addresses. */
  private async resolveToIngress(hostname: string): Promise<{ address: string } | DomainCheck> {
    const lookups = await Promise.allSettled([this.resolver.resolve4(hostname), this.resolver.resolve6(hostname)]);
    const addresses = lookups.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
    if (addresses.length === 0) {
      const codes = lookups.map((r) => (r.status === "rejected" ? (r.reason as { code?: string }).code : null));
      return pending(codes.some((c) => c === "ETIMEOUT" || c === "ECONNREFUSED") ? "DNS_LOOKUP_FAILED" : "DNS_NOT_FOUND");
    }
    // Connecting only to approved ingress addresses is the SSRF guard.
    if (!addresses.every((a) => this.ingress.has(a))) return failed("DNS_NOT_INGRESS");
    return { address: addresses[0]! };
  }

  private async verifyRouting(hostname: string, tenantId: string): Promise<DomainCheck> {
    const resolved = await this.resolveToIngress(hostname);
    if (!("address" in resolved)) return resolved;
    const result = await probe({
      protocol: "https:",
      address: resolved.address,
      port: this.port,
      hostname,
      path: ROUTING_PATH,
      timeoutMs: TIMEOUT_MS,
      ca: this.ca,
    });
    return routingResult(result, hostname, tenantId, result.ok ? true : null);
  }

  async checkPlatform(): Promise<PlatformCheck> {
    const base = { provider: this.kind, baseDomain: this.baseDomain };
    // A random label tests the wildcard record, not some existing name.
    const probeHost = `bmms-check-${randomBytes(6).toString("hex")}.${this.baseDomain}`;
    const resolved = await this.resolveToIngress(probeHost);
    if (!("address" in resolved)) {
      return { ...base, status: resolved.status, errorCode: resolved.errorCode === "DNS_NOT_FOUND" ? "WILDCARD_DNS_MISSING" : resolved.errorCode };
    }
    const result = await probe({
      protocol: "https:",
      address: resolved.address,
      port: this.port,
      hostname: probeHost,
      path: ROUTING_PATH,
      timeoutMs: TIMEOUT_MS,
      ca: this.ca,
    });
    if (isUnknownTenantResponse(result)) return { ...base, status: "active", errorCode: null };
    if (!result.ok && result.errorCode === "TLS_INVALID") return { ...base, status: "failed", errorCode: "WILDCARD_TLS_INVALID" };
    if (!result.ok) return { ...base, status: "pending", errorCode: "INGRESS_UNREACHABLE" };
    return { ...base, status: "failed", errorCode: "INGRESS_NOT_ROUTING_TO_APP" };
  }

  async verifyHostname(hostname: string, tenantId: string): Promise<DomainCheck> {
    if (!isDirectSubdomain(hostname, this.baseDomain)) return failed("HOSTNAME_OUTSIDE_BASE_DOMAIN");
    return this.verifyRouting(hostname, tenantId);
  }

  async verifyCustomDomain(hostname: string, tenantId: string, ownershipToken: string): Promise<DomainCheck> {
    if (hostname === this.baseDomain || hostname.endsWith(`.${this.baseDomain}`)) {
      return failed("CUSTOM_DOMAIN_INSIDE_PLATFORM_DOMAIN");
    }
    let records: string[][];
    try {
      records = await this.resolver.resolveTxt(`_bmms-challenge.${hostname}`);
    } catch {
      return pending("OWNERSHIP_RECORD_MISSING");
    }
    if (!records.some((parts) => parts.join("") === ownershipToken)) {
      return pending("OWNERSHIP_RECORD_MISMATCH");
    }
    const routing = await this.verifyRouting(hostname, tenantId);
    return { ...routing, ownershipVerified: true };
  }
}

// ---- Configuration --------------------------------------------------------------

export function createDomainProviderFromEnv(env: NodeJS.ProcessEnv = process.env): DomainProvider {
  const production = env.NODE_ENV === "production";
  const kind = env.DOMAIN_PROVIDER?.trim() || (production ? "" : "local");

  if (kind === "local") {
    if (production) throw new Error("DOMAIN_PROVIDER=local is not allowed in production.");
    const baseDomain = normalizeHostname(env.PLATFORM_BASE_DOMAIN?.trim() || "localhost");
    if (!baseDomain) throw new Error("PLATFORM_BASE_DOMAIN is not a valid hostname.");
    const frontendOrigin = env.FRONTEND_ORIGIN ?? "http://localhost:3000";
    const port = new URL(frontendOrigin).port || "80";
    return new LocalDomainProvider({
      baseDomain,
      frontendOrigin,
      routingCheckOrigin: env.LOCAL_ROUTING_CHECK_ORIGIN?.trim() || `http://127.0.0.1:${port}`,
    });
  }

  if (kind === "production") {
    const baseDomain = normalizeHostname(env.PLATFORM_BASE_DOMAIN);
    if (!baseDomain || !baseDomain.includes(".")) {
      throw new Error("PLATFORM_BASE_DOMAIN must be the registered platform domain, e.g. bmms.example.com.");
    }
    return new ProductionDomainProvider({
      baseDomain,
      ingressAddresses: (env.PLATFORM_INGRESS_ADDRESSES ?? "").split(",").map((a) => a.trim()).filter(Boolean),
    });
  }

  throw new Error("DOMAIN_PROVIDER must be local or production.");
}

let provider: DomainProvider | undefined;

/** The configured provider (validated on first use). */
export function domainProvider(): DomainProvider {
  provider ??= createDomainProviderFromEnv();
  return provider;
}
