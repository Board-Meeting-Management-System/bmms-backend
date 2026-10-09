import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import { pool } from "./db.js";
import { provisioningPool } from "./modules/provisioning/provisioning.db.js";
import {
  claimNextProvisioningJob,
  failExhaustedProvisioningJobs,
  recordProvisioningFailure,
  renewProvisioningLease,
  type ClaimedProvisioningJob,
  type ProvisioningFailureCode,
} from "./modules/provisioning/provisioning-worker.repository.js";
import { withProvisioningLease } from "./modules/provisioning/provisioning-lease.js";
import { ProvisioningLeaseLostError } from "./modules/provisioning/provisioning-step.repository.js";

import { runCreateDatabaseStep } from "./modules/provisioning/create-database.step.js";
import { runConfigureCredentialsStep } from "./modules/provisioning/configure-credentials.step.js";
import { runMigrateTenantStep } from "./modules/provisioning/migrate-tenant.step.js";
import { runConfigureEncryptionStep } from "./modules/provisioning/configure-enryption.step.js";
import { runVerifyResourcesStep } from "./modules/provisioning/verify-resources.step.js";
import { runActivateTenantStep } from "./modules/provisioning/activate-tenant.step.js";

const workerId = randomUUID();
const idleController = new AbortController();

let stopping = false;

function requestShutdown() {
  if (stopping) {
    return;
  }

  stopping = true;
  idleController.abort();

  console.log(
    "Shutdown requested. Finishing the current job before exiting.",
  );
}

process.on("SIGINT", requestShutdown);
process.on("SIGTERM", requestShutdown);

async function processJob(
  job: ClaimedProvisioningJob,
): Promise<void> {
  let failureCode: ProvisioningFailureCode = "PROVISIONING_FAILED";

  console.log(
    JSON.stringify({
      event: "provisioning_started",
      jobId: job.id,
      tenantId: job.tenantId,
      attempt: job.attempts,
    }),
  );

  try {
    await withProvisioningLease(job, async (signal) => {
      failureCode = "DATABASE_SETUP_FAILED";
      await runCreateDatabaseStep(job, signal);

      failureCode = "CREDENTIAL_SETUP_FAILED";
      await runConfigureCredentialsStep(job, signal);

      failureCode = "TENANT_MIGRATION_FAILED";
      await runMigrateTenantStep(job, signal);

      failureCode = "ENCRYPTION_SETUP_FAILED";
      await runConfigureEncryptionStep(job, signal);

      failureCode = "RESOURCE_VERIFICATION_FAILED";
      await runVerifyResourcesStep(job, signal);
    });

    // withProvisioningLease has stopped and drained its heartbeat.
    // Obtain a fresh lease window for the short activation transaction.
    failureCode = "TENANT_ACTIVATION_FAILED";

    const renewed = await renewProvisioningLease(job);

    if (!renewed) {
      throw new ProvisioningLeaseLostError();
    }

    await runActivateTenantStep(
      job,
      new AbortController().signal,
    );

    console.log(
      JSON.stringify({
        event: "provisioning_succeeded",
        jobId: job.id,
        tenantId: job.tenantId,
      }),
    );
  } catch (error) {
    if (error instanceof ProvisioningLeaseLostError) {
      console.warn(
        JSON.stringify({
          event: "provisioning_lease_lost",
          jobId: job.id,
        }),
      );

      return;
    }

    // Log predefined codes only, never raw errors that may contain SQL,
    // credentials, connection strings, or nested AggregateError details.
    try {
      const status = await recordProvisioningFailure(
        job,
        failureCode,
      );

      console.error(
        JSON.stringify({
          event:
            status === null
              ? "provisioning_failure_not_recorded"
              : "provisioning_attempt_failed",
          jobId: job.id,
          errorCode: failureCode,
          status,
        }),
      );
    } catch {
      // Leave recovery to lease expiry if persistence is unavailable.
      console.error(
        JSON.stringify({
          event: "provisioning_failure_persistence_failed",
          jobId: job.id,
          errorCode: failureCode,
        }),
      );
    }
  }
}

async function main(): Promise<void> {
  // The current adapters use local credentials and local key storage.
  if (process.env.NODE_ENV !== "development") {
    throw new Error("This provisioning worker requires development mode.");
  }

  console.log(
    JSON.stringify({
      event: "provisioning_worker_started",
      workerId,
    }),
  );

  while (!stopping) {
    try {
      await failExhaustedProvisioningJobs();

      if (stopping) {
        break;
      }

      const job = await claimNextProvisioningJob(workerId);

      if (job) {
        // Finish a claimed job even if shutdown was requested
        // while the claim query was running.
        await processJob(job);
        continue;
      }
    } catch {
      console.error(
        JSON.stringify({
          event: "provisioning_queue_poll_failed",
          workerId,
        }),
      );
    }

    if (!stopping) {
      try {
        await delay(2_000, undefined, {
          signal: idleController.signal,
        });
      } catch {
        if (!stopping) {
          throw new Error("Worker polling delay failed.");
        }
      }
    }
  }
}

try {
  await main();
} catch {
  console.error("Provisioning worker stopped unexpectedly.");
  process.exitCode = 1;
} finally {
  process.off("SIGINT", requestShutdown);
  process.off("SIGTERM", requestShutdown);

  const closed = await Promise.allSettled([
    provisioningPool.end(),
    pool.end(),
  ]);

  if (closed.some((result) => result.status === "rejected")) {
    console.error("A worker database pool did not close cleanly.");
    process.exitCode = 1;
  }
}