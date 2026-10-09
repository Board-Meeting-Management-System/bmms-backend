import pg from "pg";

function getProvisioningDatabaseUrl(): string {
  const value = process.env.PROVISIONING_DATABASE_URL;

  if (!value) {
    throw new Error(
      "Missing environment variable: PROVISIONING_DATABASE_URL",
    );
  }

  let url: URL;

  try {
    url = new URL(value);
  } catch {
    throw new Error("PROVISIONING_DATABASE_URL is invalid.");
  }

  if (
    !["postgres:", "postgresql:"].includes(url.protocol) ||
    !url.hostname ||
    url.pathname !== "/postgres"
  ) {
    throw new Error(
      "PROVISIONING_DATABASE_URL must point to the postgres maintenance database.",
    );
  }

  return value;
}

export const provisioningPool = new pg.Pool({
  connectionString: getProvisioningDatabaseUrl(),
  application_name: "bmms-provisioning",
  max: 1,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 30_000,
});

provisioningPool.on("error", () => {
  // Do not log connection strings or credentials.
  console.error("Provisioning database connection failed.");
});