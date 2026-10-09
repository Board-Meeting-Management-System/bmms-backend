import { activateTenant } from "./activate-tenant.repository.js";
import {
  startProvisioningStep,
  failProvisioningStep,
  ProvisioningLeaseLostError,
} from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function runActivateTenantStep(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const action = await startProvisioningStep(
    job,
    "activate_tenant",
  );

  if (action === "already_succeeded") {
    // Normal activation completes the job in the same transaction.
    // A running job with an already-completed activation is inconsistent.
    throw new Error(
      "Activation is already complete but the job is still running.",
    );
  }

  try {
    signal.throwIfAborted();

    // Atomically completes the tenant, step, and job.
    // Do not call completeProvisioningStep() afterward.
    await activateTenant(job, signal);
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
        "activate_tenant",
        "TENANT_ACTIVATION_FAILED",
      );
    } catch (trackingError) {
      if (trackingError instanceof ProvisioningLeaseLostError) {
        throw trackingError;
      }

      throw new AggregateError(
        [error, trackingError],
        "Activation failed and step failure could not be recorded.",
      );
    }

    throw error;
  }
}