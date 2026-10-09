CREATE TABLE tenant_data_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL REFERENCES tenants(id),

    -- Version of this tenant's data-encryption key.
    key_version INTEGER NOT NULL
        CHECK (key_version > 0),

    -- Version of the external key used to encrypt this key.
    wrapping_key_version INTEGER NOT NULL
        CHECK (wrapping_key_version > 0),

    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM'
        CHECK (algorithm = 'AES-256-GCM'),

    -- A 32-byte data key encrypted with AES-GCM.
    ciphertext BYTEA NOT NULL
        CHECK (octet_length(ciphertext) = 32),

    nonce BYTEA NOT NULL
        CHECK (octet_length(nonce) = 12),

    auth_tag BYTEA NOT NULL
        CHECK (octet_length(auth_tag) = 16),

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'retired')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, key_version)
);

CREATE UNIQUE INDEX tenant_data_keys_one_active
    ON tenant_data_keys (tenant_id)
    WHERE status = 'active';