-- Secretary onboarding: recipient-side email verification, invitation
-- acceptance and memberships.

-- Where the browser returns after Keycloak login. A relative frontend
-- path only; the API validates it against an allowlist before storing.
ALTER TABLE auth_login_attempts
ADD COLUMN return_path TEXT
    CHECK (
        return_path IS NULL
        OR (
            return_path ~ '^/[A-Za-z0-9/_-]{0,200}$'
            AND return_path NOT LIKE '//%'
        )
    );


-- An identity's role in an organization. Created only by accepting an
-- invitation; email verification alone never creates one.
CREATE TABLE tenant_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL REFERENCES tenants(id),
    identity_id UUID NOT NULL REFERENCES identities(id),

    role TEXT NOT NULL
        CHECK (role IN ('secretary')),

    -- The invitation that granted this membership.
    invitation_id UUID NOT NULL UNIQUE
        REFERENCES tenant_invitations(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, identity_id)
);


-- Changing an invitation's email invalidates everything proven about the
-- previous address: its verification, the invitation link, and any
-- outstanding code. Enforced here so no code path can skip it.
CREATE FUNCTION tenant_invitations_reset_on_email_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email THEN
        IF OLD.status NOT IN ('pending_setup', 'pending') THEN
            RAISE EXCEPTION 'Only open invitations can change email'
                USING ERRCODE = 'check_violation';
        END IF;

        NEW.email_verified_at := NULL;
        NEW.verified_email := NULL;
        NEW.token_hash := NULL;
        NEW.expires_at := NULL;
        NEW.status := 'pending_setup';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER tenant_invitations_reset_on_email_change
BEFORE UPDATE OF email ON tenant_invitations
FOR EACH ROW
EXECUTE FUNCTION tenant_invitations_reset_on_email_change();

CREATE FUNCTION tenant_invitations_drop_challenge_on_email_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email THEN
        DELETE FROM secretary_email_verifications
        WHERE invitation_id = NEW.id;
    END IF;

    RETURN NULL;
END
$$;

CREATE TRIGGER tenant_invitations_drop_challenge_on_email_change
AFTER UPDATE OF email ON tenant_invitations
FOR EACH ROW
EXECUTE FUNCTION tenant_invitations_drop_challenge_on_email_change();
