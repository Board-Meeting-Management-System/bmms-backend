-- Tenant domains, private storage, tenant-host sessions and invitation
-- delivery. Platform metadata only: no tenant business data.

-- ---- Domain verification state ----------------------------------------------

ALTER TABLE tenant_domains
ADD COLUMN last_checked_at TIMESTAMPTZ,
ADD COLUMN last_error_code TEXT
    CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
ADD COLUMN check_attempts INTEGER NOT NULL DEFAULT 0
    CHECK (check_attempts >= 0),
ADD COLUMN next_check_at TIMESTAMPTZ,
-- When a request to the hostname was seen reaching this organization.
ADD COLUMN routing_verified_at TIMESTAMPTZ,
-- Custom domains only: the value expected in the _bmms-challenge TXT record.
-- Published in DNS by design, so it is not a secret.
ADD COLUMN ownership_token TEXT
    CHECK (ownership_token IS NULL OR ownership_token ~ '^[A-Za-z0-9_-]{32,64}$');

-- Platform subdomains need no ownership proof; custom domains always do.
ALTER TABLE tenant_domains
ADD CONSTRAINT tenant_domains_custom_ownership_check
CHECK (domain_type = 'platform' OR ownership_token IS NOT NULL);

-- A custom domain is active only with ownership, routing and TLS proven.
ALTER TABLE tenant_domains
ADD CONSTRAINT tenant_domains_custom_active_check
CHECK (
    domain_type = 'platform'
    OR status <> 'active'
    OR (
        ownership_verified_at IS NOT NULL
        AND routing_verified_at IS NOT NULL
        AND tls_ready_at IS NOT NULL
    )
);


-- ---- Private storage --------------------------------------------------------

-- Reference to the organization's private storage (e.g. local-fs:<id>).
ALTER TABLE tenant_resources
ADD COLUMN storage_ref TEXT;


-- ---- New provisioning steps for jobs that haven't finished ------------------

INSERT INTO provisioning_steps (job_id, step_name, status)
SELECT job.id, step.name, 'pending'
FROM provisioning_jobs AS job
CROSS JOIN (VALUES ('configure_storage'), ('configure_domain')) AS step(name)
WHERE job.status <> 'succeeded'
ON CONFLICT (job_id, step_name) DO NOTHING;


-- ---- Tenant-host sessions ---------------------------------------------------

-- Where the browser returns after login, when it's an organization domain.
-- Validated against active tenant_domains before it's stored.
ALTER TABLE auth_login_attempts
ADD COLUMN return_host TEXT
    CHECK (return_host IS NULL OR (return_host = lower(return_host) AND length(return_host) <= 253));

-- Sessions bound to one organization hostname. NULL = platform session,
-- usable only on platform routes; bound sessions only on their host.
ALTER TABLE auth_sessions
ADD COLUMN bound_host TEXT
    CHECK (bound_host IS NULL OR (bound_host = lower(bound_host) AND length(bound_host) <= 253));

-- One-time codes that carry a login from the platform domain to an
-- organization domain. Only the hash is stored; single use, short-lived.
CREATE TABLE auth_handoffs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    code_hash TEXT NOT NULL UNIQUE
        CHECK (code_hash ~ '^[0-9a-f]{64}$'),

    -- The platform session the new host session is derived from.
    source_session_id UUID NOT NULL
        REFERENCES auth_sessions(id) ON DELETE CASCADE,

    target_host TEXT NOT NULL
        CHECK (target_host = lower(target_host) AND length(target_host) <= 253),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '60 seconds'),
    consumed_at TIMESTAMPTZ,

    CHECK (expires_at > created_at)
);

CREATE INDEX auth_handoffs_expires_at_idx ON auth_handoffs (expires_at);


-- ---- Invitation delivery queue ----------------------------------------------

-- Queued when an organization becomes ready; processed by the worker
-- separately from provisioning, so delivery problems never touch
-- infrastructure. One row per invitation.
CREATE TABLE invitation_deliveries (
    invitation_id UUID PRIMARY KEY
        REFERENCES tenant_invitations(id) ON DELETE CASCADE,

    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'sending', 'sent', 'failed', 'skipped')),

    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_expires_at TIMESTAMPTZ,
    last_error_code TEXT
        CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX invitation_deliveries_due_idx
    ON invitation_deliveries (status, next_attempt_at);
