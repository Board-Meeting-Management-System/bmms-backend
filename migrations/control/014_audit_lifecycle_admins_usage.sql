-- Audit log, organization lifecycle (suspend / scheduled deletion),
-- administrator management and per-organization usage.

-- ---- Audit log ---------------------------------------------------------------

-- Append-only record of who did what. Snapshots (actor_label, tenant_name)
-- keep entries readable after identities or organizations are gone, so there
-- are deliberately no foreign keys. Never store secrets in metadata.
CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- NULL actor = the system (worker, scheduled jobs).
    actor_identity_id UUID,
    actor_label TEXT,

    action TEXT NOT NULL
        CHECK (action ~ '^[a-z][a-z_]*(\.[a-z][a-z_]*)+$'),

    tenant_id UUID,
    tenant_name TEXT,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at DESC, id DESC);
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_identity_id, occurred_at DESC);

CREATE FUNCTION audit_events_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only'
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_events_no_update_or_delete
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION audit_events_append_only();

-- Like the other control tables, audit history starts now; earlier events
-- were not recorded.


-- ---- Organization lifecycle -----------------------------------------------

-- Deletion is scheduled, not immediate: the organization stays suspended
-- until deletion_scheduled_for, then the worker removes its database,
-- roles, storage and control rows. Cancelling clears both columns.
ALTER TABLE tenants
ADD COLUMN suspended_at TIMESTAMPTZ,
ADD COLUMN deletion_requested_at TIMESTAMPTZ,
ADD COLUMN deletion_requested_by UUID REFERENCES identities(id),
ADD COLUMN deletion_scheduled_for TIMESTAMPTZ;

ALTER TABLE tenants
ADD CONSTRAINT tenants_deletion_check
CHECK (
    (deletion_requested_at IS NULL AND deletion_scheduled_for IS NULL)
    OR (
        deletion_requested_at IS NOT NULL
        AND deletion_scheduled_for IS NOT NULL
        AND status IN ('suspended', 'failed')
    )
);

CREATE INDEX tenants_deletion_due_idx
    ON tenants (deletion_scheduled_for)
    WHERE deletion_scheduled_for IS NOT NULL;


-- ---- Administrators -----------------------------------------------------------

-- Administrator access granted by email before that person has signed in.
-- Applied at their next admin-realm sign-in with a verified, matching email.
CREATE TABLE platform_admin_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    email TEXT NOT NULL UNIQUE
        CHECK (email = lower(btrim(email)) AND length(email) BETWEEN 3 AND 254),

    invited_by UUID NOT NULL REFERENCES identities(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ---- Usage ------------------------------------------------------------------

-- Latest measurement per organization, collected by the worker.
CREATE TABLE tenant_usage (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    database_bytes BIGINT CHECK (database_bytes >= 0),
    database_connections INTEGER CHECK (database_connections >= 0),
    storage_bytes BIGINT CHECK (storage_bytes >= 0),
    storage_files INTEGER CHECK (storage_files >= 0),

    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Why a measurement is missing, e.g. DATABASE_UNREACHABLE.
    last_error_code TEXT
        CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$')
);
