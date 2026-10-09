import { migrateTenantDatabase } from "./migrate-tenant-database.js";
import {
  startProvisioningStep,
  completeProvisioningStep,
  failProvisioningStep,
  ProvisioningLeaseLostError,
} from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function runMigrateTenantStep(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const action = await startProvisioningStep(
    job,
    "migrate_tenant",
  );

  if (action === "already_succeeded") {
    return;
  }

  try {
    signal.throwIfAborted();

    const databaseName = await migrateTenantDatabase(
      job.tenantId,
      signal,
    );

    signal.throwIfAborted();

    await completeProvisioningStep(
      job,
      "migrate_tenant",
      databaseName,
    );
  } catch (error) {
    if (
      signal.aborted ||
      error instanceof ProvisioningLeaseLostError
    ) {
      throw error;
    }

    try {
      await failProvisioningStep(
        job,
        "migrate_tenant",
        "TENANT_MIGRATION_FAILED",
      );
    } catch (trackingError) {
      if (trackingError instanceof ProvisioningLeaseLostError) {
        throw trackingError;
      }

      throw new AggregateError(
        [error, trackingError],
        "Tenant migration failed and step failure could not be recorded.",
      );
    }

    throw error;
  }
}