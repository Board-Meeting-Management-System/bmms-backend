-- Foundation only: add identities, domains, invitations and resource references
-- in later migrations BEFORE implementing organization registration.
CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'provisioning'
    CHECK (status IN ('provisioning','active','failed','suspended')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE provisioning_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  idempotency_key text NOT NULL UNIQUE,
  request_hash text NOT NULL,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','running','failed','succeeded')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_run_at timestamptz NOT NULL DEFAULT now(),
  lease_owner text,
  lease_expires_at timestamptz,
  lease_version bigint NOT NULL DEFAULT 0,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX provisioning_jobs_due ON provisioning_jobs(status, next_run_at);
CREATE TABLE provisioning_steps (
  job_id uuid NOT NULL REFERENCES provisioning_jobs(id),
  step_name text NOT NULL,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','running','failed','succeeded')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  resource_ref text,
  last_error_code text,
  completed_at timestamptz,
  PRIMARY KEY (job_id, step_name)
);
