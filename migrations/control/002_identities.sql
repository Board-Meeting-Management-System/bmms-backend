CREATE TABLE identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    issuer text NOT NULL,
    subject text NOT NULL,

    email text,
    email_verified boolean NOT NULL DEFAULT false,

    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),

    is_platform_admin boolean NOT NULL DEFAULT false,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    UNIQUE(issuer, subject)
)