// A throwaway control database for integration tests: created on the
// server in CONTROL_DATABASE_URL, migrated, and dropped afterwards. The
// development database itself is never touched.

import { randomBytes } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";

export interface TestDatabase {
  url: string;
  drop(): Promise<void>;
}

export async function createTestDatabase(): Promise<TestDatabase> {
  const serverUrl = process.env.CONTROL_DATABASE_URL;
  if (!serverUrl) throw new Error("CONTROL_DATABASE_URL is required to reach the test server.");

  const name = `bmms_test_${randomBytes(6).toString("hex")}`;
  const admin = new pg.Client({ connectionString: serverUrl });
  await admin.connect();

  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }

  const url = new URL(serverUrl);
  url.pathname = `/${name}`;

  const client = new pg.Client({ connectionString: url.href });
  await client.connect();

  try {
    const folder = resolve("migrations/control");
    for (const file of (await readdir(folder)).filter((n) => n.endsWith(".sql")).sort()) {
      await client.query("BEGIN");
      await client.query(await readFile(resolve(folder, file), "utf8"));
      await client.query("COMMIT");
    }
  } finally {
    await client.end();
  }

  return {
    url: url.href,
    async drop() {
      const cleanup = new pg.Client({ connectionString: serverUrl });
      await cleanup.connect();
      try {
        // Only ever the database created above.
        await cleanup.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      } finally {
        await cleanup.end();
      }
    },
  };
}
