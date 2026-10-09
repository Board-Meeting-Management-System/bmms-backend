import { randomBytes } from "node:crypto";

import {
  encryptTenantSecret,
  decryptTenantSecret,
  type EncryptedTenantSecret,
} from "./tenant-secret.crypto.js";
import { getTenantResourceNames } from "./tenant-resource-names.js";
import { withOwnedJob } from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

interface SecretRow extends EncryptedTenantSecret {
  id: string;
}

export interface TenantDatabaseCredentials {
  secretRef: string;
  username: string;
  password: string;
}

export function readCredentials(
  tenantId: string,
  row: SecretRow,
): TenantDatabaseCredentials {
  const plaintext = decryptTenantSecret(tenantId, row);

  let parsed: unknown;

  try {
    parsed = JSON.parse(plaintext);
  } catch {
    // Do not expose decrypted contents through a JSON parsing error.
    throw new Error("Stored tenant credentials are invalid.");
  }

  if (
    parsed === null ||
    typeof parsed !== "object" ||
    !("username" in parsed) ||
    !("password" in parsed) ||
    typeof parsed.username !== "string" ||
    typeof parsed.password !== "string"
  ) {
    throw new Error("Stored tenant credentials are invalid.");
  }

  const names = getTenantResourceNames(tenantId);

  if (
    parsed.username !== names.runtimeRole ||
    !/^[A-Za-z0-9_-]{43}$/.test(parsed.password)
  ) {
    throw new Error("Stored tenant credentials are unexpected.");
  }

  return {
    secretRef: `local-db:${row.id}`,
    username: parsed.username,
    password: parsed.password,
  };
}

export async function getOrCreateTenantDatabaseCredentials(
  job: ClaimedProvisioningJob,
): Promise<TenantDatabaseCredentials> {
  return withOwnedJob(job, async (client) => {
    // Serialize credential creation even if multiple jobs target one tenant.
    const resource = await client.query(
      `
      SELECT tenant_id
      FROM tenant_resources
      WHERE tenant_id = $1
      FOR UPDATE
      `,
      [job.tenantId],
    );

    if (resource.rowCount !== 1) {
      throw new Error("Tenant resource record is missing.");
    }

    const existing = await client.query<SecretRow>(
      `
      SELECT
        id,
        key_version AS "keyVersion",
        ciphertext,
        nonce,
        auth_tag AS "authTag"
      FROM tenant_secrets
      WHERE tenant_id = $1
        AND purpose = 'database_credentials'
      `,
      [job.tenantId],
    );

    const stored = existing.rows[0];

    if (stored) {
      return readCredentials(job.tenantId, stored);
    }

    const names = getTenantResourceNames(job.tenantId);
    const password = randomBytes(32).toString("base64url");

    const encrypted = encryptTenantSecret(
      job.tenantId,
      JSON.stringify({
        username: names.runtimeRole,
        password,
      }),
    );

    const inserted = await client.query<{ id: string }>(
      `
      INSERT INTO tenant_secrets (
        tenant_id,
        purpose,
        key_version,
        ciphertext,
        nonce,
        auth_tag
      )
      VALUES ($1, 'database_credentials', $2, $3, $4, $5)
      RETURNING id
      `,
      [
        job.tenantId,
        encrypted.keyVersion,
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.authTag,
      ],
    );

    const secret = inserted.rows[0];

    if (!secret) {
      throw new Error("Tenant credential storage failed.");
    }

    return {
      secretRef: `local-db:${secret.id}`,
      username: names.runtimeRole,
      password,
    };
  });
}