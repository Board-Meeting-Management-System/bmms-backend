# Organizations, domains and isolation

One shared application (one API, one worker, one frontend build) serves
every organization. Each organization gets:

| | Where | Created by |
|---|---|---|
| Its own PostgreSQL database and restricted runtime role | `bmms_t_<id>` / `bmms_app_<id>` | `create_database`, `configure_credentials`, `migrate_tenant` |
| Private file storage | `TENANT_STORAGE_ROOT/<id>/` (0700) | `configure_storage` |
| A data-encryption key, wrapped | `tenant_data_keys` | `configure_encryption` |
| A platform hostname `<slug>.<PLATFORM_BASE_DOMAIN>` | `tenant_domains` | registration; verified by `configure_domain` |

The control database (`bmms_control`) holds only platform metadata:
organizations, domains, jobs, invitations, memberships, sessions, encrypted
credentials and *references* to resources. No tenant business data.

## Provisioning

`POST /admin/tenants` creates the organization (`provisioning`), its domain
(`pending`), the secretary invitation (`pending_setup`) and a job with eight
steps, in one transaction, keyed by `Idempotency-Key` — repeated submissions
return the same organization.

The worker (`npm run dev:worker`, a separate process) runs:

1. `create_database` 2. `configure_credentials` 3. `migrate_tenant`
4. `configure_storage` 5. `configure_encryption` 6. `configure_domain`
7. `verify_resources` 8. `activate_tenant`

- Every step is idempotent and recorded; succeeded steps are skipped on
  later attempts, so a job resumes where it stopped.
- One worker at a time per job: leases with fencing versions; a crashed
  worker's lease expires and another worker resumes the job.
- Failures record a code and retry with backoff (30 s … 240 s, 5 attempts),
  then the job is `failed`. Nothing that succeeded is deleted.
- `POST /admin/provisioning-jobs/:id/retry` (admin) re-opens a failed job
  from the failed step; it never creates a second organization.
- `activate_tenant` marks the organization `active` only if every step
  succeeded, its storage exists and its domain is `active`, and in the same
  transaction **queues the secretary invitation** (`invitation_deliveries`).
- The worker sends queued invitations separately (5 attempts, backoff). A
  delivery failure never touches provisioning; an administrator can always
  send the invitation manually.

Infrastructure readiness, invitation delivery, email verification and
acceptance are separate states (see `GET /admin/tenants/:id/onboarding`).

## Domain providers (`DOMAIN_PROVIDER`)

Shared platform infrastructure is checked by `GET /admin/platform/domain-check`;
each organization's hostname by the `configure_domain` step and
`POST /admin/tenants/:id/domains/check`. Results (status, error code, last
check, attempts, next check) are stored on `tenant_domains`.

**local** (development; refused in production)

- Hostnames `<slug>.localhost` (base `PLATFORM_BASE_DOMAIN`, default
  `localhost`); URLs `http://<slug>.localhost:3000/`.
- Verification sends a request with `Host: <slug>.localhost` to the dev
  frontend (`LOCAL_ROUTING_CHECK_ORIGIN`, loopback only) and requires the
  answer at `/bmms-routing` to name this organization. It proves routing
  through the real frontend → API path. It never claims DNS or TLS.
- Browsers (Chrome, Firefox, Edge) resolve `*.localhost` to this machine
  without DNS. Command-line tools may not: use
  `curl -H "Host: org-a.localhost:3000" http://127.0.0.1:3000/`.
- Containers resolve `localhost` to themselves: run the frontend and API on
  the host, or point `LOCAL_ROUTING_CHECK_ORIGIN` at the frontend's loopback
  address from where the worker runs.
- If the frontend isn't running, the domain step stays pending
  (`LOCAL_APP_UNREACHABLE`) and retries; start it and use **Check again** or
  **Retry provisioning**.

**production**

Assumes infrastructure an operator configures once — nothing per organization:

- a wildcard DNS record `*.<PLATFORM_BASE_DOMAIN>` → the ingress,
- an ingress that sends every hostname to this app (preserving `Host`),
- a wildcard certificate for `*.<PLATFORM_BASE_DOMAIN>`.

Verification resolves the hostname (3 s timeout), requires every address to
be in `PLATFORM_INGRESS_ADDRESSES`, then connects **only to that address**
over HTTPS with certificate verification (5 s timeout, no redirects, 4 KB
limit) and checks `/bmms-routing` answers for this organization. Typical
codes: `DNS_NOT_FOUND`/`WILDCARD_DNS_MISSING` (pending), `DNS_NOT_INGRESS`,
`TLS_INVALID`, `ROUTING_WRONG_ORGANIZATION` (failed).

## Routing and tenant context

- The frontend's `proxy.ts` serves `PLATFORM_HOSTS` (default `localhost`) as
  the platform (`/master`, `/invitation`); every other hostname gets the
  organization app (`/org`, internal).
- The frontend server calls the API with `X-Forwarded-Host`; the API trusts it
  only from `TRUST_PROXY` addresses. The organization is resolved by exact
  hostname match against `tenant_domains` — unknown hosts are rejected
  (`TENANT_NOT_FOUND`); there's no default organization, and no request
  parameter can select one.
- Tenant database connections come from server-side records for that resolved
  organization (`tenantDatabase(tenantId)`), as its restricted role. Storage
  paths come from `storageProvider().objectPath(tenantId, key)`, which rejects
  keys that leave the organization's directory. There are no downloads,
  exports or caches yet; new ones must take the tenant from this context.
- Protected tenant routes require a session **bound to that hostname** and an
  active membership (`tenant_memberships`). Platform administrators have no
  implicit access to organizations. Host-bound sessions can't call platform
  routes, and platform sessions can't call tenant routes.

## Sign-in on an organization domain

Keycloak has one callback (the API's). For an organization hostname:

1. `/auth/login?returnHost=<host>` — accepted only for an active registered
   organization hostname.
2. After the Keycloak callback, the API issues a one-time, 60-second code
   bound to that host (only its hash is stored) and redirects to
   `<org origin>/auth/handoff?code=…`.
3. That host's server exchanges the code for a session bound to the host and
   sets its own HttpOnly cookie. Codes are consumed on first presentation,
   on any host.

No cookie is shared across subdomains. Sign-out revokes the host session and
ends the Keycloak session; Keycloak returns via `/auth/logged-out?state=<host>`
(re-validated) to the organization.

## Custom domains

Modelled separately (`domain_type = 'custom'`, never primary):

- `POST /admin/tenants/:id/custom-domains` `{ hostname }` → `pending`, with a
  TXT record to publish: `_bmms-challenge.<hostname>` = the returned value.
- `POST /admin/tenants/:id/custom-domains/:domainId/verify` checks ownership
  (TXT), routing (A/AAAA → ingress) and TLS. A database constraint refuses
  `active` without all three. Unverified custom hostnames aren't routed.
- The platform subdomain keeps working throughout.
- Not automated (no provider integration): creating DNS records and issuing
  per-domain certificates. Extension points: `ProductionDomainProvider`
  (`src/modules/domains/domain-provider.ts`) for DNS APIs, and your ingress
  (e.g. on-demand TLS) for certificates. The local provider refuses custom
  domains (`CUSTOM_DOMAINS_REQUIRE_PRODUCTION_PROVIDER`).

## Local setup: two organizations

In `bmms-backend/.env` (see `.env.example`):

```bash
TRUST_PROXY=127.0.0.1
DOMAIN_PROVIDER=local
PLATFORM_BASE_DOMAIN=localhost
STORAGE_PROVIDER=local
EMAIL_DELIVERY=file          # invitations land in bmms-backend/.mail/, nothing is sent
```

Then:

```bash
cd ~/Projects/board-meeting
./dev.sh                                           # DB, Keycloak, migrations, API, worker, frontend

# another terminal
cd ~/Projects/board-meeting/bmms-backend
npm run dev:create-organizations -- org-a org-b    # prints each URL and progress page
```

Within a few seconds both progress pages show every step complete. Open:

- http://org-a.localhost:3000
- http://org-b.localhost:3000

Each shows its own organization and a **Sign in** button. To sign in as a
member, accept the secretary invitation: the email is in
`bmms-backend/.mail/` (newest file for `secretary@org-a.example.com`). Open
its link, enter its code, then sign in with a Keycloak user whose email is
`secretary@org-a.example.com` and *Email verified* is on (create it in the
Keycloak console), accept, and **Open Org A**.

Check routing without a browser:

```bash
curl -s -H "Host: org-a.localhost:3000" http://127.0.0.1:3000/bmms-routing
curl -s -H "Host: nobody.localhost:3000" http://127.0.0.1:3000/bmms-routing   # 404 TENANT_NOT_FOUND
```

Organizations created before this change keep their old hostnames (e.g.
`*.bmms.test`); those don't resolve locally and their domains stay pending.

## Production prerequisites (not done by this code)

- Wildcard DNS, ingress and wildcard certificate as above; set
  `DOMAIN_PROVIDER=production`, `PLATFORM_BASE_DOMAIN`, `PLATFORM_INGRESS_ADDRESSES`,
  `TRUST_PROXY` (the ingress/frontend addresses).
- A production storage adapter (`STORAGE_PROVIDER=production` fails the step
  with `STORAGE_PROVIDER_UNSUPPORTED` until one exists).
- TLS for tenant database connections (remote tenant hosts are refused) and a
  real KMS / secrets manager in place of the local keys.
- The worker currently refuses to run outside `NODE_ENV=development`.
- Keycloak redirect URIs for the production API origin.
