-- Local-development encrypted secret storage.
-- The encryption key must never be stored in this database.

CREATE TABLE tenant_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL REFERENCES tenants(id),

    purpose TEXT NOT NULL
        CHECK (purpose IN ('database_credentials')),

    -- Identifies the external encryption key used.
    key_version INTEGER NOT NULL
        CHECK (key_version > 0),

    -- AES-256-GCM encrypted payload and authentication metadata.
    ciphertext BYTEA NOT NULL
        CHECK (octet_length(ciphertext) > 0),

    nonce BYTEA NOT NULL
        CHECK (octet_length(nonce) = 12),

    auth_tag BYTEA NOT NULL
        CHECK (octet_length(auth_tag) = 16),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, purpose)
);