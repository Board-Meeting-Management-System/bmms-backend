import { storageProvider } from "../storage/storage-provider.js";
import { runTrackedStep, withOwnedJob } from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

/** Creates the organization's private storage and records its reference. */
export function runConfigureStorageStep(job: ClaimedProvisioningJob, signal: AbortSignal): Promise<void> {
  return runTrackedStep(job, "configure_storage", "STORAGE_SETUP_FAILED", signal, async () => {
    const storage = storageProvider();
    const ref = await storage.ensureTenantStorage(job.tenantId);
    if (!(await storage.verifyTenantStorage(job.tenantId, ref))) {
      throw new Error("Tenant storage could not be verified.");
    }

    await withOwnedJob(job, async (client) => {
      // Never replace a different reference: that would orphan stored files.
      const updated = await client.query(
        `
        UPDATE tenant_resources
        SET storage_ref = $2, updated_at = now()
        WHERE tenant_id = $1 AND (storage_ref IS NULL OR storage_ref = $2)
        `,
        [job.tenantId, ref],
      );
      if (updated.rowCount !== 1) throw new Error("Tenant storage reference conflicts.");
    });

    return ref;
  });
}
