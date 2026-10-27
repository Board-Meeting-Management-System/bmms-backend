import { domainProvider } from "../domains/domain-provider.js";
import { primaryPlatformDomain, recordDomainCheck } from "../domains/domain.repository.js";
import { runTrackedStep } from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export class DomainNotReadyError extends Error {
  constructor(public readonly code: string) {
    super(`Domain not ready: ${code}`);
    this.name = "DomainNotReadyError";
  }
}

/**
 * Verifies that the organization's platform hostname reaches this app and
 * resolves to this organization. Nothing is created per organization: the
 * provider relies on shared, preconfigured routing. The check result (with
 * its specific error code) is stored on the domain; the job retries with
 * backoff while it's pending.
 */
export function runConfigureDomainStep(job: ClaimedProvisioningJob, signal: AbortSignal): Promise<void> {
  return runTrackedStep(job, "configure_domain", "DOMAIN_NOT_READY", signal, async () => {
    const domain = await primaryPlatformDomain(job.tenantId);
    if (!domain) throw new DomainNotReadyError("DOMAIN_MISSING");

    const check = await domainProvider().verifyHostname(domain.hostname, job.tenantId);
    await recordDomainCheck(domain.id, check);

    if (check.status !== "active") throw new DomainNotReadyError(check.errorCode ?? "DOMAIN_NOT_READY");
    return domain.hostname;
  });
}
