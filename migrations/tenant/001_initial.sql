-- Run by the tenant migration runner under the tenant owner role.

-- Remove default public schema access.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Application tables live in a dedicated schema.
CREATE SCHEMA bmms;

REVOKE ALL ON SCHEMA bmms FROM PUBLIC;

-- Exactly one organization identity may exist in this database.
-- The migration runner inserts the expected tenant UUID.
CREATE TABLE bmms.tenant_metadata (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CHECK (singleton = TRUE),

    tenant_id UUID NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent future objects created by the tenant owner in this
-- schema from receiving implicit PUBLIC privileges.
ALTER DEFAULT PRIVILEGES IN SCHEMA bmms
    REVOKE ALL ON TABLES FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA bmms
    REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- PostgreSQL grants PUBLIC function execution by default.
-- Revoke it globally for functions created by this owner.
ALTER DEFAULT PRIVILEGES
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;