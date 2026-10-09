import { ensureTenantDataKey } from "./tenant-data-key.repository.js";
import {
  startProvisioningStep,
  completeProvisioningStep,
  failProvisioningStep,
  ProvisioningLeaseLostError,
} from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function runConfigureEncryptionStep(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const action = await startProvisioningStep(
    job,
    "configure_encryption",
  );

  if (action === "already_succeeded") {
    return;
  }

  try {
    signal.throwIfAborted();

    // Reuse an existing active key or create the initial key.
    // The repository verifies that the stored key can be unwrapped.
    const keyRef = await ensureTenantDataKey(job);

    signal.throwIfAborted();

    await completeProvisioningStep(
      job,
      "configure_encryption",
      keyRef,
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
        "configure_encryption",
        "ENCRYPTION_SETUP_FAILED",
      );
    } catch (trackingError) {
      if (trackingError instanceof ProvisioningLeaseLostError) {
        throw trackingError;
      }

      throw new AggregateError(
        [error, trackingError],
        "Encryption setup failed and step failure could not be recorded.",
      );
    }

    throw error;
  }
}