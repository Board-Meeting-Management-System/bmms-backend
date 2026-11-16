import { pool } from "../../db.js";
import { getTenantResourceNames } from "../provisioning/tenant-resource-names.js";
import { readCredentials } from "../provisioning/tenant-secret.repository.js";
import type { EncryptedTenantSecret } from "../provisioning/tenant-secret.crypto.js";
import { storageProvider } from "../storage/storage-provider.js";

// What the organization platform needs to serve an organization: its
// database connection (as the restricted runtime role) and its storage
// location. Only for active organizations, and only by tenant id resolved
// from a registered hostname.
//
// Interim: credentials are decrypted here with the local key and returned
// over the authenticated internal API. With AWS KMS, return the ciphertext
// instead and let the platform's IAM role decrypt it.

export interface TenantDatabaseConnection {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  /** "disable" only for loopback development databases. */
  sslMode: "disable" | "verify-full";
}

export async function tenantDatabaseConnection(tenantId: string): Promise<TenantDatabaseConnection | null> {
  const names = getTenantResourceNames(tenantId);

  const resources = await pool.query<{
    host: string | null;
    port: number | null;
    database: string | null;
    runtimeRole: string | null;
    secretRef: string | null;
  }>(
    `
    SELECT
      resource.database_host AS host,
      resource.database_port AS port,
      resource.database_name AS database,
      resource.runtime_role_ref AS "runtimeRole",
      resource.database_secret_ref AS "secretRef"
    FROM tenant_resources AS resource
    JOIN tenants AS tenant ON tenant.id = resource.tenant_id
    WHERE resource.tenant_id = $1 AND tenant.status = 'active'
    `,
    [tenantId],
  );
  const resource = resources.rows[0];

  if (
    !resource?.host ||
    resource.port === null ||
    resource.database !== names.database ||
    resource.runtimeRole !== names.runtimeRole ||
    !resource.secretRef
  ) {
    return null;
  }

  const secrets = await pool.query<EncryptedTenantSecret & { id: string }>(
    `
    SELECT id, key_version AS "keyVersion", ciphertext, nonce, auth_tag AS "authTag"
    FROM tenant_secrets
    WHERE tenant_id = $1
      AND purpose = 'database_credentials'
      AND ('local-db:' || id::text) = $2
    `,
    [tenantId, resource.secretRef],
  );
  const secret = secrets.rows[0];
  if (!secret) return null;

  const credentials = readCredentials(tenantId, secret);
  const loopback = ["127.0.0.1", "localhost", "::1"].includes(resource.host);

  return {
    host: resource.host,
    port: resource.port,
    database: resource.database,
    username: credentials.username,
    password: credentials.password,
    sslMode: loopback ? "disable" : "verify-full",
  };
}

export interface TenantStorageLocation {
  provider: string;
  ref: string;
  /** Local provider only: the organization's directory on this machine. */
  path: string | null;
}

export async function tenantStorageLocation(tenantId: string): Promise<TenantStorageLocation | null> {
  const result = await pool.query<{ ref: string | null }>(
    `
    SELECT resource.storage_ref AS ref
    FROM tenant_resources AS resource
    JOIN tenants AS tenant ON tenant.id = resource.tenant_id
    WHERE resource.tenant_id = $1 AND tenant.status = 'active'
    `,
    [tenantId],
  );
  const ref = result.rows[0]?.ref;
  if (!ref) return null;

  const storage = storageProvider();
  if (!(await storage.verifyTenantStorage(tenantId, ref))) return null;

  return {
    provider: storage.kind,
    ref,
    path: storage.rootPath(tenantId),
  };
}
