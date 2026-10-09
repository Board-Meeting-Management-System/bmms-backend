import {
  generateWrappedTenantDataKey,
  unwrapTenantDataKey,
  type WrappedTenantDataKey,
} from "./tenant-data-key.crypto.js";
import { withOwnedJob } from "./provisioning-step.repository.js";
import type { ClaimedProvisioningJob } from "./provisioning-worker.repository.js";

interface DataKeyRow extends WrappedTenantDataKey {
  id: string;
}

export async function ensureTenantDataKey(
  job: ClaimedProvisioningJob,
): Promise<string> {
  return withOwnedJob(job, async (client) => {
    const resources = await client.query<{
      keyRef: string | null;
    }>(
      `
      SELECT kms_key_ref AS "keyRef"
      FROM tenant_resources
      WHERE tenant_id = $1
      FOR UPDATE
      `,
      [job.tenantId],
    );

    const resource = resources.rows[0];

    if (!resource) {
      throw new Error("Tenant resource record is missing.");
    }

    const existing = await client.query<DataKeyRow>(
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
      `,
      [job.tenantId],
    );

    let key = existing.rows[0];

    if (!key) {
      if (resource.keyRef !== null) {
        throw new Error(
          "Tenant key reference exists but its active key is missing.",
        );
      }

      const history = await client.query(
        `
        SELECT id
        FROM tenant_data_keys
        WHERE tenant_id = $1
        LIMIT 1
        `,
        [job.tenantId],
      );

      if (history.rowCount !== 0) {
        throw new Error(
          "Tenant has existing key history; explicit key recovery is required.",
        );
      }

      const wrapped = generateWrappedTenantDataKey(job.tenantId);

      const inserted = await client.query<DataKeyRow>(
        `
        INSERT INTO tenant_data_keys (
          tenant_id,
          key_version,
          wrapping_key_version,
          ciphertext,
          nonce,
          auth_tag
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
          id,
          key_version AS "keyVersion",
          wrapping_key_version AS "wrappingKeyVersion",
          ciphertext,
          nonce,
          auth_tag AS "authTag"
        `,
        [
          job.tenantId,
          wrapped.keyVersion,
          wrapped.wrappingKeyVersion,
          wrapped.ciphertext,
          wrapped.nonce,
          wrapped.authTag,
        ],
      );

      key = inserted.rows[0];

      if (!key) {
        throw new Error("Tenant data-key storage failed.");
      }
    }

    // Verify the stored key before attaching its reference.
    const plaintextKey = unwrapTenantDataKey(job.tenantId, key);
    plaintextKey.fill(0);

    const keyRef = `local-key:${key.id}`;

    if (
      resource.keyRef !== null &&
      resource.keyRef !== keyRef
    ) {
      throw new Error("Tenant data-key reference does not match.");
    }

    await client.query(
      `
      UPDATE tenant_resources
      SET
        kms_key_ref = $2,
        updated_at = now()
      WHERE tenant_id = $1
      `,
      [job.tenantId, keyRef],
    );

    return keyRef;
  });
}