import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import { pool } from "./db.js";
import { provisioningPool } from "./modules/provisioning/provisioning.db.js";
import { runWorkerIteration } from "./modules/provisioning/provisioning-runner.js";

// Provisioning worker: a separate process from the API. Runs provisioning
// jobs and, between them, queued invitation deliveries.

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
      // Finish claimed work even if shutdown was requested meanwhile.
      if ((await runWorkerIteration(workerId)) !== "idle") {
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
