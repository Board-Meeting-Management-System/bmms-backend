-- The organization platform is a separate application with its own
-- Keycloak realm. Organization members sign in there; their memberships live
-- in each organization's own database. The control plane keeps only
-- platform metadata, so tenant-side login and membership state goes.

-- Acceptance now records the organization-realm identity that accepted.
-- (accepted_by stays for invitations accepted before the split.)
ALTER TABLE tenant_invitations
ADD COLUMN accepted_issuer TEXT,
ADD COLUMN accepted_subject TEXT;

ALTER TABLE tenant_invitations
DROP CONSTRAINT tenant_invitations_check3;

ALTER TABLE tenant_invitations
ADD CONSTRAINT tenant_invitations_acceptance_check
CHECK (
    (
        status = 'accepted'
        AND accepted_at IS NOT NULL
        AND (
            accepted_by IS NOT NULL
            OR (accepted_issuer IS NOT NULL AND accepted_subject IS NOT NULL)
        )
    )
    OR
    (
        status <> 'accepted'
        AND accepted_by IS NULL
        AND accepted_at IS NULL
        AND accepted_issuer IS NULL
        AND accepted_subject IS NULL
    )
);

ALTER TABLE tenant_invitations
ADD CONSTRAINT tenant_invitations_accepted_identity_check
CHECK ((accepted_issuer IS NULL) = (accepted_subject IS NULL));

-- Memberships belong to the organization's database now.
DROP TABLE tenant_memberships;

-- Login on organization hostnames moved to the organization platform.
DROP TABLE auth_handoffs;

ALTER TABLE auth_sessions
DROP COLUMN bound_host;

ALTER TABLE auth_login_attempts
DROP COLUMN return_host;
