import { createTenantDatabase } from "./create-tenant-database.js";
import {
  startProvisioningStep,
  completeProvisioningStep,
  failProvisioningStep,
  ProvisioningLeaseLostError,
} from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function runCreateDatabaseStep(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const action = await startProvisioningStep(
    job,
    "create_database",
  );

  if (action === "already_succeeded") {
    return;
  }

  try {
    signal.throwIfAborted();

    const resources = await createTenantDatabase(
      job.tenantId,
      signal,
    );

    signal.throwIfAborted();

    await completeProvisioningStep(
      job,
      "create_database",
      resources.database,
    );
  } catch (error) {
    // A worker that lost ownership must not update step state.
    if (
      signal.aborted ||
      error instanceof ProvisioningLeaseLostError
    ) {
      throw error;
    }

    try {
      await failProvisioningStep(
        job,
        "create_database",
        "DATABASE_SETUP_FAILED",
      );
    } catch (trackingError) {
      if (trackingError instanceof ProvisioningLeaseLostError) {
        throw trackingError;
      }

      // Preserve both failures without logging sensitive details.
      throw new AggregateError(
        [error, trackingError],
        "Database setup failed and step failure could not be recorded.",
      );
    }

    throw error;
  }
}