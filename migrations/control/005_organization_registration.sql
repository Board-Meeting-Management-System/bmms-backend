-- Nullable for compatibility with any existing tenant records.
-- The registration API must supply the authenticated administrator.
ALTER TABLE tenants
ADD COLUMN created_by UUID REFERENCES identities(id);

ALTER TABLE provisioning_jobs
ADD COLUMN requested_by UUID REFERENCES identities(id);


-- Organization hostname, for example abc.bmms.test.
-- Store only the hostname, without protocol, port, or path.
CREATE TABLE tenant_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL REFERENCES tenants(id),

    hostname TEXT NOT NULL UNIQUE,

    domain_type TEXT NOT NULL
        CHECK (domain_type IN ('platform', 'custom')),

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'failed')),

    is_primary BOOLEAN NOT NULL DEFAULT TRUE,

    ownership_verified_at TIMESTAMPTZ,
    tls_ready_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (
        hostname = lower(hostname)
        AND hostname = btrim(hostname)
        AND length(hostname) BETWEEN 1 AND 253
    )
);

CREATE INDEX tenant_domains_tenant_idx
    ON tenant_domains (tenant_id);

CREATE UNIQUE INDEX tenant_domains_one_primary_idx
    ON tenant_domains (tenant_id)
    WHERE is_primary = TRUE;


-- Initial company-secretary invitation.
-- It cannot be used while organization setup is incomplete.
CREATE TABLE tenant_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL REFERENCES tenants(id),

    email TEXT NOT NULL,

    role TEXT NOT NULL DEFAULT 'secretary'
        CHECK (role = 'secretary'),

    status TEXT NOT NULL DEFAULT 'pending_setup'
        CHECK (
            status IN (
                'pending_setup',
                'pending',
                'accepted',
                'expired',
                'revoked'
            )
        ),

    invited_by UUID NOT NULL REFERENCES identities(id),

    -- Generate the invitation token after provisioning succeeds.
    -- Store its SHA-256 hash, never the original token.
    token_hash TEXT UNIQUE,
    expires_at TIMESTAMPTZ,

    accepted_by UUID REFERENCES identities(id),
    accepted_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (
        email = lower(email)
        AND email = btrim(email)
        AND length(email) BETWEEN 3 AND 254
    ),

    CHECK (
        token_hash IS NULL
        OR token_hash ~ '^[0-9a-f]{64}$'
    ),

    CHECK (
        (token_hash IS NULL) = (expires_at IS NULL)
    ),

    CHECK (
        status <> 'pending_setup'
        OR (token_hash IS NULL AND expires_at IS NULL)
    ),

    CHECK (
        status NOT IN ('pending', 'accepted', 'expired')
        OR (token_hash IS NOT NULL AND expires_at IS NOT NULL)
    ),

    CHECK (
        (
            status = 'accepted'
            AND accepted_by IS NOT NULL
            AND accepted_at IS NOT NULL
        )
        OR
        (
            status <> 'accepted'
            AND accepted_by IS NULL
            AND accepted_at IS NULL
        )
    )
);

CREATE INDEX tenant_invitations_tenant_idx
    ON tenant_invitations (tenant_id);

CREATE UNIQUE INDEX tenant_invitations_one_open_email_idx
    ON tenant_invitations (tenant_id, email)
    WHERE status IN ('pending_setup', 'pending');


-- References to resources created by the provisioning worker.
-- No database passwords or plaintext encryption keys.
CREATE TABLE tenant_resources (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),

    database_host TEXT,
    database_port INTEGER
        CHECK (database_port BETWEEN 1 AND 65535),
    database_name TEXT,

    database_secret_ref TEXT,
    kms_key_ref TEXT,
    runtime_role_ref TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);