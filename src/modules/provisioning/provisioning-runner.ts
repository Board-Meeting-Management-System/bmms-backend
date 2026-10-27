import { claimDueDelivery, processDelivery } from "../invitations/invitation-delivery.js";
import { runActivateTenantStep } from "./activate-tenant.step.js";
import { runConfigureCredentialsStep } from "./configure-credentials.step.js";
import { runConfigureDomainStep } from "./configure-domain.step.js";
import { runConfigureEncryptionStep } from "./configure-enryption.step.js";
import { runConfigureStorageStep } from "./configure-storage.step.js";
import { runCreateDatabaseStep } from "./create-database.step.js";
import { runMigrateTenantStep } from "./migrate-tenant.step.js";
import { withProvisioningLease } from "./provisioning-lease.js";
import { ProvisioningLeaseLostError } from "./provisioning-step.repository.js";
import {
  claimNextProvisioningJob,
  failExhaustedProvisioningJobs,
  recordProvisioningFailure,
  renewProvisioningLease,
  type ClaimedProvisioningJob,
  type ProvisioningFailureCode,
} from "./provisioning-worker.repository.js";
import { runVerifyResourcesStep } from "./verify-resources.step.js";

function log(event: Record<string, unknown>, level: "log" | "warn" | "error" = "log") {
  console[level](JSON.stringify(event));
}

export type JobOutcome = "succeeded" | "retry" | "failed" | "lease_lost" | "unrecorded";

/**
 * Runs a claimed job's steps in order. Steps that already succeeded are
 * skipped, so a job resumes where a previous attempt (or a crashed worker)
 * stopped. A failure records a code and reschedules with backoff; nothing
 * that already succeeded is undone.
 */
export async function processJob(job: ClaimedProvisioningJob): Promise<JobOutcome> {
  let failureCode: ProvisioningFailureCode = "PROVISIONING_FAILED";

  log({ event: "provisioning_started", jobId: job.id, tenantId: job.tenantId, attempt: job.attempts });

  try {
    await withProvisioningLease(job, async (signal) => {
      failureCode = "DATABASE_SETUP_FAILED";
      await runCreateDatabaseStep(job, signal);

      failureCode = "CREDENTIAL_SETUP_FAILED";
      await runConfigureCredentialsStep(job, signal);

      failureCode = "TENANT_MIGRATION_FAILED";
      await runMigrateTenantStep(job, signal);

      failureCode = "STORAGE_SETUP_FAILED";
      await runConfigureStorageStep(job, signal);

      failureCode = "ENCRYPTION_SETUP_FAILED";
      await runConfigureEncryptionStep(job, signal);

      failureCode = "DOMAIN_NOT_READY";
      await runConfigureDomainStep(job, signal);

      failureCode = "RESOURCE_VERIFICATION_FAILED";
      await runVerifyResourcesStep(job, signal);
    });

    // withProvisioningLease has stopped and drained its heartbeat.
    // Obtain a fresh lease window for the short activation transaction.
    failureCode = "TENANT_ACTIVATION_FAILED";

    if (!(await renewProvisioningLease(job))) {
      throw new ProvisioningLeaseLostError();
    }

    await runActivateTenantStep(job, new AbortController().signal);

    log({ event: "provisioning_succeeded", jobId: job.id, tenantId: job.tenantId });
    return "succeeded";
  } catch (error) {
    if (error instanceof ProvisioningLeaseLostError) {
      log({ event: "provisioning_lease_lost", jobId: job.id }, "warn");
      return "lease_lost";
    }

    // Log predefined codes only, never raw errors that may contain SQL,
    // credentials, connection strings, or nested AggregateError details.
    try {
      const status = await recordProvisioningFailure(job, failureCode);
      log(
        {
          event: status === null ? "provisioning_failure_not_recorded" : "provisioning_attempt_failed",
          jobId: job.id,
          errorCode: failureCode,
          status,
        },
        "error",
      );
      return status === "failed" ? "failed" : status === "pending" ? "retry" : "unrecorded";
    } catch {
      // Leave recovery to lease expiry if persistence is unavailable.
      log({ event: "provisioning_failure_persistence_failed", jobId: job.id, errorCode: failureCode }, "error");
      return "unrecorded";
    }
  }
}

/**
 * One unit of worker work: a due provisioning job if there is one,
 * otherwise one due invitation delivery. Returns what it did.
 */
export async function runWorkerIteration(workerId: string): Promise<"job" | "delivery" | "idle"> {
  await failExhaustedProvisioningJobs();

  const job = await claimNextProvisioningJob(workerId);
  if (job) {
    await processJob(job);
    return "job";
  }

  const delivery = await claimDueDelivery();
  if (delivery) {
    const outcome = await processDelivery(delivery);
    log({ event: "invitation_delivery", outcome, attempt: delivery.attempts });
    return "delivery";
  }

  return "idle";
}
