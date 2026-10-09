import { withOwnedJob } from "./provisioning-step.repository.js";
import { getTenantResourceNames } from "./tenant-resource-names.js";
import { readCredentials } from "./tenant-secret.repository.js";
import {
  unwrapTenantDataKey,
  type WrappedTenantDataKey,
} from "./tenant-data-key.crypto.js";
import type { EncryptedTenantSecret } from "./tenant-secret.crypto.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

interface ResourceRow {
  host: string | null;
  port: number | null;
  database: string | null;
  runtimeRole: string | null;
  secretRef: string | null;
  keyRef: string | null;
}

interface SecretRow extends EncryptedTenantSecret {
  id: string;
}

interface DataKeyRow extends WrappedTenantDataKey {
  id: string;
}

export interface VerificationResources {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}

export async function loadVerificationResources(
  job: ClaimedProvisioningJob,
): Promise<VerificationResources> {
  return withOwnedJob(job, async (client) => {
    const result = await client.query<ResourceRow>(
      `
      SELECT
        database_host AS host,
        database_port AS port,
        database_name AS database,
        runtime_role_ref AS "runtimeRole",
        database_secret_ref AS "secretRef",
        kms_key_ref AS "keyRef"
      FROM tenant_resources
      WHERE tenant_id = $1
      FOR UPDATE
      `,
      [job.tenantId],
    );

    const resource = result.rows[0];
    const names = getTenantResourceNames(job.tenantId);

    if (
      !resource ||
      !resource.host ||
      resource.port === null ||
      resource.port < 1 ||
      resource.port > 65535 ||
      resource.database !== names.database ||
      resource.runtimeRole !== names.runtimeRole ||
      !resource.secretRef ||
      !resource.keyRef
    ) {
      throw new Error("Tenant resource configuration is incomplete.");
    }

    const secrets = await client.query<SecretRow>(
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
        AND ('local-db:' || id::text) = $2
      `,
      [job.tenantId, resource.secretRef],
    );

    const secret = secrets.rows[0];

    if (!secret) {
      throw new Error("Referenced tenant credentials are missing.");
    }

    const credentials = readCredentials(job.tenantId, secret);

    const keys = await client.query<DataKeyRow>(
      `
      SELECT
        id,
        key_version AS "keyVersion",
        wrapping_key_version AS "wrappingKeyVersion",
        ciphertext,
        nonce,
        auth_tag AS "authTag"
      FROM tenant_data_keys
      WHERE tenant_id = $1
        AND status = 'active'
        AND algorithm = 'AES-256-GCM'
        AND ('local-key:' || id::text) = $2
      `,
      [job.tenantId, resource.keyRef],
    );

    const key = keys.rows[0];

    if (!key) {
      throw new Error("Referenced active tenant data key is missing.");
    }

    const plaintextKey = unwrapTenantDataKey(job.tenantId, key);
    plaintextKey.fill(0);

    return {
      host: resource.host,
      port: resource.port,
      database: resource.database,
      username: credentials.username,
      password: credentials.password,
    };
  });
}