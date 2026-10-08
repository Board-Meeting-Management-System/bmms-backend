CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    identity_id UUID NOT NULL
        REFERENCES identities(id) ON DELETE CASCADE,

    -- Store a hash of the random session token.
    -- The browser receives the original token in an HttpOnly cookie.
    session_token_hash TEXT NOT NULL UNIQUE,

    -- Encrypted token bundle, never plaintext tokens.
    tokens_encrypted TEXT NOT NULL,

    access_token_expires_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Absolute session deadline, enforced by the backend.
    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,

    CHECK (expires_at > created_at)
);

CREATE INDEX auth_sessions_identity_id_idx
    ON auth_sessions (identity_id);

CREATE INDEX auth_sessions_expires_at_idx
    ON auth_sessions (expires_at);