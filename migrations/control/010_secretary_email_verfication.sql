ALTER TABLE tenant_invitations
ADD COLUMN email_verified_at TIMESTAMPTZ,
ADD COLUMN verified_email TEXT;

ALTER TABLE tenant_invitations
ADD CONSTRAINT tenant_invitations_verified_email_check
CHECK (
    (
        email_verified_at IS NULL
        AND verified_email IS NULL
    )
    OR
    (
        email_verified_at IS NOT NULL
        AND verified_email IS NOT NULL
        AND verified_email = email
    )
);

CREATE TABLE secretary_email_verifications (
    invitation_id UUID PRIMARY KEY
        REFERENCES tenant_invitations(id),

    -- Replaced on resend to invalidate the previous challenge.
    challenge_id UUID NOT NULL UNIQUE
        DEFAULT gen_random_uuid(),

    -- Snapshot of the address receiving this code.
    email TEXT NOT NULL
        CHECK (
            email = lower(btrim(email))
            AND length(email) BETWEEN 3 AND 254
        ),

    -- HMAC-SHA-256; never store the plaintext OTP.
    otp_hash TEXT NOT NULL
        CHECK (otp_hash ~ '^[0-9a-f]{64}$'),

    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts BETWEEN 0 AND 5),

    expires_at TIMESTAMPTZ NOT NULL,

    -- Controls resend cooldown independently of delivery success.
    last_requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Fixed-window send limit, enforced by the repository.
    send_window_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    send_count INTEGER NOT NULL DEFAULT 1
        CHECK (send_count BETWEEN 1 AND 5),

    delivery_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_status IN ('pending', 'sent', 'failed')),

    consumed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (expires_at > last_requested_at)
);

CREATE INDEX secretary_email_verifications_expiry_idx
    ON secretary_email_verifications (expires_at);