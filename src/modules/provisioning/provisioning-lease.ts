import {
  renewProvisioningLease,
  type ClaimedProvisioningJob,
} from "./provisioning-worker.repository.js";

export async function withProvisioningLease<T>(
  job: ClaimedProvisioningJob,
  work: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();

  let renewal: Promise<void> | null = null;
  let leaseFailure: Error | null = null;

  function loseLease() {
    leaseFailure = new Error(
      "Provisioning lease could not be renewed.",
    );

    controller.abort(leaseFailure);
  }

  async function heartbeat(): Promise<void> {
    try {
      const renewed = await renewProvisioningLease(job);

      if (!renewed) {
        loseLease();
      }
    } catch {
      // If ownership cannot be confirmed, stop further work.
      loseLease();
    }
  }

  // Confirm ownership before starting any provisioning operation.
  await heartbeat();

  if (leaseFailure) {
    throw leaseFailure;
  }

  const timer = setInterval(() => {
    if (renewal || controller.signal.aborted) {
      return;
    }

    // Keep only one renewal query in flight.
    renewal = heartbeat().finally(() => {
      renewal = null;
    });
  }, 15_000);

  try {
    const result = await work(controller.signal);

    // Wait for an in-flight renewal before reporting success.
    clearInterval(timer);

    if (renewal) {
      await renewal;
    }

    if (leaseFailure) {
      throw leaseFailure;
    }

    return result;
  } finally {
    clearInterval(timer);

    if (renewal) {
      await renewal;
    }
  }
}