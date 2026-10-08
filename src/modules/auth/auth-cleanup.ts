import type { FastifyInstance } from "fastify";

import {
  deleteExpiredLoginAttempts,
} from "./login-attempt.repository.js";

import {
  deleteExpiredSessions,
} from "./session.repository.js";

export function registerAuthCleanup(app: FastifyInstance): void {
  let timer: ReturnType<typeof setInterval> | undefined;
  let running: Promise<void> | undefined;
  let stopping = false;

  async function cleanup(): Promise<void> {
    try {
      const loginAttempts = await deleteExpiredLoginAttempts();
      const sessions = await deleteExpiredSessions();

      if (loginAttempts > 0 || sessions > 0) {
        app.log.info(
          { loginAttempts, sessions },
          "Expired authentication records removed",
        );
      }
    } catch {
      app.log.error(
        { event: "auth_cleanup_failed" },
        "Authentication cleanup failed; will retry next interval",
      );
    }
  }

  function startCleanup(): void {
    // Prevent overlapping cleanup runs in this process.
    if (stopping || running) {
      return;
    }

    running = cleanup().finally(() => {
      running = undefined;
    });
  }

  app.addHook("onReady", async () => {
    startCleanup();

    timer = setInterval(startCleanup, 5 * 60 * 1000);
    timer.unref();
  });

  app.addHook("onClose", async () => {
    stopping = true;

    if (timer) {
      clearInterval(timer);
    }

    // Finish any active cleanup before closing the database pool.
    await running;
  });
}