CREATE TABLE auth_login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Hash of a random secret held in the browser's HttpOnly cookie.
    browser_binding_hash TEXT NOT NULL,

    -- Random value checked when Keycloak redirects back.
    state TEXT NOT NULL UNIQUE,

    -- Secret used to exchange the authorization code.
    pkce_verifier TEXT NOT NULL,

    -- Random value checked against the returned ID token.
    nonce TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    expires_at TIMESTAMPTZ NOT NULL
        DEFAULT (now() + INTERVAL '5 minutes'),

    CHECK (expires_at > created_at)
);

CREATE INDEX auth_login_attempts_expires_at_idx
    ON auth_login_attempts (expires_at);