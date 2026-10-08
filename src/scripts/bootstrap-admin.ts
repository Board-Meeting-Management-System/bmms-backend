import { pool } from "../db.js";

async function main(): Promise<void> {
  const userId = process.argv[2];

  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  if (!userId || !uuidPattern.test(userId)) {
    throw new Error(
      "Usage: npm run admin:bootstrap -- <identity-uuid>",
    );
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Prevent simultaneous bootstrap attempts.
    await client.query(
      "SELECT pg_advisory_xact_lock(732105)",
    );

    const existing = await client.query<{
      id: string;
      status: string;
    }>(
      `
      SELECT id, status
      FROM identities
      WHERE is_platform_admin = true
      `,
    );

    const anotherAdmin = existing.rows.find(
      (admin) => admin.id !== userId.toLowerCase(),
    );

    if (anotherAdmin) {
      throw new Error(
        `Another platform administrator already exists: ${anotherAdmin.id}. ` +
          "No permissions were changed.",
      );
    }

    const currentAdmin = existing.rows.find(
      (admin) => admin.id === userId.toLowerCase(),
    );

    if (currentAdmin) {
      await client.query("COMMIT");

      console.log(
        `This user is already a platform administrator: ${currentAdmin.id}`,
      );
      console.log(`Account status: ${currentAdmin.status}`);
      return;
    }

    const updated = await client.query<{ id: string }>(
      `
      UPDATE identities
      SET
        is_platform_admin = true,
        updated_at = now()
      WHERE id = $1
        AND status = 'active'
        AND email IS NOT NULL
        AND email_verified = true
      RETURNING id
      `,
      [userId],
    );

    const user = updated.rows[0];

    if (!user) {
      throw new Error(
        "User must exist, be active, and have a verified email. " +
          "Call /auth/me with a fresh token after verifying the email.",
      );
    }

    await client.query("COMMIT");

    console.log(
      `Initial platform administrator created: ${user.id}`,
    );
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

try {
  await main();
} catch (error) {
  console.error(
    error instanceof Error
      ? error.message
      : "Administrator setup failed",
  );

  process.exitCode = 1;
} finally {
  await pool.end();
}