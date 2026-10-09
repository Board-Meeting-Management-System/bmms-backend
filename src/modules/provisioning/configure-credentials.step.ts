import { configureTenantRole } from "./configure-tenant-role.js";
import { getOrCreateTenantDatabaseCredentials } from "./tenant-secret.repository.js";
import { saveTenantDatabaseResources } from "./tenant-resource.repository.js";
import {
  startProvisioningStep,
  completeProvisioningStep,
  failProvisioningStep,
  ProvisioningLeaseLostError,
} from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

export async function runConfigureCredentialsStep(
  job: ClaimedProvisioningJob,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();

  const action = await startProvisioningStep(
    job,
    "configure_credentials",
  );

  if (action === "already_succeeded") {
    return;
  }

  try {
    signal.throwIfAborted();

    // Persist credentials before changing the PostgreSQL role.
    // Retries retrieve the same username and password.
    const credentials =
      await getOrCreateTenantDatabaseCredentials(job);

    signal.throwIfAborted();

    await configureTenantRole(
      job.tenantId,
      credentials,
      signal,
    );

    signal.throwIfAborted();

    await saveTenantDatabaseResources(
      job,
      credentials.secretRef,
    );

    signal.throwIfAborted();

    await completeProvisioningStep(
      job,
      "configure_credentials",
      credentials.secretRef,
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
        "configure_credentials",
        "CREDENTIAL_SETUP_FAILED",
      );
    } catch (trackingError) {
      if (trackingError instanceof ProvisioningLeaseLostError) {
        throw trackingError;
      }

      throw new AggregateError(
        [error, trackingError],
        "Credential setup failed and step failure could not be recorded.",
      );
    }

    throw error;
  }
}