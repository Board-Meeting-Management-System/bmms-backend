import { verifyTenantDatabase } from "./verify-tenant-database.js";
import {
  startProvisioningStep,
  completeProvisioningStep,
  failProvisioningStep,
  ProvisioningLeaseLostError,
} from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function runVerifyResourcesStep(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const action = await startProvisioningStep(
    job,
    "verify_resources",
  );

  if (action === "already_succeeded") {
    return;
  }

  try {
    signal.throwIfAborted();

    const databaseName = await verifyTenantDatabase(
      job,
      signal,
    );

    signal.throwIfAborted();

    await completeProvisioningStep(
      job,
      "verify_resources",
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
        "verify_resources",
        "RESOURCE_VERIFICATION_FAILED",
      );
    } catch (trackingError) {
      if (trackingError instanceof ProvisioningLeaseLostError) {
        throw trackingError;
      }

      throw new AggregateError(
        [error, trackingError],
        "Resource verification failed and step failure could not be recorded.",
      );
    }

    throw error;
  }
}