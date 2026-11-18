# Local development (single machine)

Everything runs on one machine. `localhost` always means *the machine running
the browser or process*: the browser must run on this machine too (for other
computers, see [lan-testing.md](lan-testing.md)).

| Service | Address | Started by |
|---|---|---|
| PostgreSQL 17 | `127.0.0.1:5433` | `docker compose up -d --wait` (this repo) |
| Keycloak, realm `bmms` | `http://localhost:8080` | your existing Keycloak setup |
| API | `http://localhost:3001` | `npm run dev` (this repo) |
| Provisioning worker | — | `npm run dev:worker` (this repo; separate process) |
| Frontend (Next.js) | `http://localhost:3000` | `npm run dev` (bmms-frontend) |

Use `localhost` (not `127.0.0.1`) in the browser: the session cookie is set
for the hostname, and the frontend and API must share it.

## First-time setup

```bash
# bmms-backend
cp .env.example .env          # then fill in the placeholders
npm ci
docker compose up -d --wait
npm run db:migrate

# bmms-frontend
cp .env.example .env.local    # defaults work for local development
npm ci
```

Generate each key once with `openssl rand -base64 32`. Never regenerate a key
that's in use (`SESSION_ENCRYPTION_KEY`, `TENANT_SECRETS_KEY_V1`,
`EMAIL_OTP_HMAC_KEY`): existing sessions, tenant credentials or codes stop
working.

## Every day

Four terminals (or the `dev.sh` helper in the parent folder, if you have it):

```bash
cd bmms-backend  && docker compose up -d --wait && npm run db:migrate && npm run dev
cd bmms-backend  && npm run dev:worker
cd bmms-frontend && npm run dev
```

Then open http://localhost:3000/master.

## Checks and tests

```bash
# bmms-backend
npm run typecheck
npm run test:unit          # crypto, no database
npm run test:onboarding    # creates and drops its own database; sends no email
npm run test:tenancy       # provisions real organizations into throwaway databases, then drops them
npm run test:administration # audit log, suspend/delete, administrators, usage; throwaway databases

# bmms-frontend
npm run typecheck
npm run lint
npm test                   # polling logic
```

`test:onboarding` creates a throwaway database (`bmms_test_<random>`) on the
PostgreSQL server in `CONTROL_DATABASE_URL`, migrates it, and drops it at the
end. Email is captured in memory (`EMAIL_DELIVERY=capture`). It never touches
`bmms_control`.

`test:registration` runs against the **running API and development
database** (it cleans up after itself). Run it only when that's acceptable.

## Organizations and their domains

See [tenancy-and-domains.md](tenancy-and-domains.md) for the `.env` settings
(`TRUST_PROXY`, `DOMAIN_PROVIDER`, `PLATFORM_BASE_DOMAIN=localhost`,
`EMAIL_DELIVERY=file`) and the commands that create two organizations and
open them at `http://org-a.localhost:3000` and `http://org-b.localhost:3000`.

## Keycloak

The `bmms` realm's client (`OIDC_CLIENT_ID`) needs:

- Valid redirect URIs: `http://localhost:3001/auth/callback`
- Valid post logout redirect URIs: `http://localhost:3001/auth/logged-out`

**Platform administrator**: sign in once, then
`npm run admin:bootstrap -- <identity-uuid>` (the id from `GET /auth/me`).

**Secretary account** (to test acceptance): in the Keycloak admin console,
realm `bmms` → Users → Add user, with the invited email address, *Email
verified* on, and a password under Credentials. BMMS never sets *Email
verified* itself: acceptance requires Keycloak to vouch for the address.
(Alternatively enable user registration with email verification in the
realm, which needs SMTP configured in Keycloak.)

**More administrators**: Master administrators → *Grant access* with their
email. If they've signed in before (verified email, `bmms` realm) access is
immediate; otherwise it's pending and applies at their first sign-in. You
can't disable or remove yourself, or the last active administrator.

**Two-step verification for administrators** (`ADMIN_REQUIRE_MFA=true`):

1. Realm `bmms` → Authentication → the browser flow: set *OTP Form* (or
   *Conditional OTP*) to Required, so Keycloak asks each user to set up an
   authenticator app.
2. In that flow, open the OTP step's settings and set its *Authentication
   reference* (AMR value) to `otp`.
3. Clients → the BMMS client → Client scopes → its dedicated scope → Add
   mapper → By configuration → *Authentication Method Reference (AMR)*, with
   *Add to ID token* on.

Check: the mapper must appear under the client's *-dedicated* scope →
Mappers next to the audience mapper. With `ADMIN_REQUIRE_MFA=true` the API
asks Keycloak for a fresh login every time (`prompt=login`), because a
reused Keycloak session reports no second factor. A refusal is recorded with
the `amr`/`acr` Keycloak sent: no `amr` means the mapper is missing; `acr`
"0" means a reused session.

The API then refuses administrator sign-ins whose ID token has no
second-factor `amr` value, and records `administrator.sign_in_refused` in the
audit log. Turn it on only after your own account has OTP set up, or you'll
lock yourself out (set it back to `false` and restart to recover). The exact
Keycloak menu names vary slightly by version.

## Organization lifecycle and usage

- **Suspend** keeps all data but takes the organization offline: the
  internal API reports it as not ready and stops handing the organization
  platform its database and storage credentials. **Reactivate** reverses it.
- **Delete** is allowed only for suspended or failed organizations, needs the
  slug typed to confirm, and runs after `TENANT_DELETION_GRACE_HOURS`. Until
  then it can be cancelled. The worker then drops the database (`WITH
  (FORCE)`), its roles, the storage directory and the control records; the
  audit log keeps the history.
- The worker measures each active organization every
  `USAGE_INTERVAL_MINUTES` (database size, open connections, files and bytes
  in storage); *Measure now* on the organization page does it immediately.
  Sizes above `TENANT_DATABASE_WARN_MB` / `TENANT_STORAGE_WARN_MB` show as
  warnings and in the notifications bell.
- Every administrative action, sign-in and onboarding step is recorded in
  `audit_events`, which is append-only (a trigger refuses updates and
  deletes). See it under *Audit log*.

## Onboarding walkthrough

1. `/master` → sign in → Organizations → Create organization.
2. The progress page polls until all six provisioning steps finish.
3. **Send invitation** (enabled once provisioning succeeds) — this sends a
   real email when `EMAIL_DELIVERY=smtp`.
4. In the invited inbox, open the link and enter the code on the
   `/invitation` page.
5. On the same page, **Sign in to accept** with the secretary's Keycloak
   account, then **Accept invitation**.
6. Back on the progress page, **Refresh status**: email verified, secretary
   joined.

## Manual real-email smoke test

Automated tests never send email. To check Gmail delivery by hand:

1. Check the SMTP login (sends nothing):
   `node --env-file=.env --import tsx src/scripts/check-email.ts`
2. Create an organization whose secretary email is **an inbox you control**,
   wait for provisioning, then press **Send invitation** once.
3. Confirm: one email arrives (check spam), the link opens `/invitation`, the
   code verifies, the onboarding status shows *Verified*.
4. Request **Send a new code** on the page: a code-only email arrives and the
   earlier code is refused.

Gmail limits daily sends; each send counts.

## Never

- Don't drop or reset `bmms_control` or tenant databases, or remove the
  `bmms_pgdata` volume — tenant credentials and keys live there.
- Don't commit `.env`.
- Don't set `EMAIL_DELIVERY=capture` outside tests: invitations would
  silently go nowhere.
