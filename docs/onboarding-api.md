# Organization onboarding — API contract

Onboarding has four independent stages. Each has its own source of truth, and
none implies another:

| Stage | Done when | Source |
|---|---|---|
| Infrastructure provisioned | provisioning job `succeeded` (tenant `active`) | `provisioning_jobs`, `tenants` |
| Domain ready | primary domain `status = 'active'` | `tenant_domains` (not automated yet: stays `pending`) |
| Secretary email verified | `tenant_invitations.email_verified_at` set | the secretary entered the emailed code |
| Secretary joined | invitation `accepted`, membership row exists | `tenant_invitations`, `tenant_memberships` |

"Code sent" is not "verified", and "verified" is not "joined".

## Flow

1. **Register** — `POST /admin/tenants` (admin). Creates the tenant, its
   domain, a `pending_setup` secretary invitation and a provisioning job. 202.
2. **Provision** — the worker (`npm run dev:worker`, a separate process) runs
   the six steps; the frontend polls `GET /admin/provisioning-jobs/:id`.
3. **Invite** — once the tenant is `active`, `POST /admin/invitations/:id/email-verification`
   (admin) issues a new invitation link (256-bit token; only its SHA-256 is
   stored) and, while unverified, a new 6-digit code. Both go in one email:
   `<FRONTEND_ORIGIN>/invitation#token=<token>`. The invitation becomes
   `pending` and expires in 7 days. Sending again replaces the link and code.
4. **Verify** — the secretary opens the link; the page calls the public
   endpoints below with the token and enters the code themselves. The
   administrator never sees or handles the code.
5. **Accept** — the secretary signs in with Keycloak
   (`/auth/login?returnTo=/invitation`) and calls `POST /invitations/accept`.
   Requires: verified invitation email, a Keycloak account whose email is
   verified (`email_verified` claim) and equal to the invitation email. Creates
   a `tenant_memberships` row and marks the invitation `accepted`.

## Security properties

- Codes: `crypto.randomInt`, six digits as a string (leading zeros kept).
  Stored only as HMAC-SHA-256 over (invitation id, challenge id, normalized
  email, code) with `EMAIL_OTP_HMAC_KEY`. Never returned, logged or put in a URL.
- 10-minute expiry, 5 attempts per code, 60 s resend cooldown, 5 sends per
  hour per invitation. Only the latest challenge is accepted; it is consumed
  once. Wrong attempts are committed before the error is returned.
- Every verification and acceptance runs in one transaction holding a row
  lock on the invitation (lock order: identity → invitation/tenant →
  challenge), so concurrent requests can't double-verify or lose attempts.
- Changing an invitation's email (database trigger, migration 011) clears its
  verification, link and status, and deletes the outstanding challenge.
- SMTP failures and unrecorded outcomes return `503 EMAIL_DELIVERY_UNCONFIRMED`
  / `EMAIL_DELIVERY_STATUS_UNAVAILABLE`: delivery is uncertain, the cooldown
  still applies.
- Public endpoints: per-IP rate limits, generic `404 INVITATION_LINK_INVALID`
  for any unusable token (unknown, replaced, revoked), minimal responses
  (organization name, masked email).
- Verification never creates a membership and never changes Keycloak's
  `emailVerified`.

## Endpoints

Errors are `{ "error": "<CODE>", "message": "<human-readable>" }`.
Cookie-authenticated writes must send an allowed `Origin` (CSRF).

### Admin (session cookie, platform administrator)

`POST /admin/invitations/:invitationId/email-verification` → **202**
```json
{ "codeSent": true, "message": "Invitation email submitted. Earlier invitation links no longer work." }
```
Errors: 404 `INVITATION_NOT_FOUND`; 409 `TENANT_NOT_ACTIVE`,
`INVITATION_NOT_AVAILABLE`; 429 `OTP_RESEND_COOLDOWN`, `OTP_SEND_LIMIT`;
503 `EMAIL_DELIVERY_UNCONFIRMED`, `EMAIL_DELIVERY_STATUS_UNAVAILABLE`.
Rate limit 10/min.

`PATCH /admin/invitations/:invitationId` body `{ "email": "new@example.com" }` → **200** `{ "email": "..." }`.
Errors: 404 `INVITATION_NOT_FOUND`; 409 `INVITATION_NOT_AVAILABLE`, `EMAIL_ALREADY_INVITED`.

`GET /admin/tenants/:tenantId/onboarding` → **200**
```json
{
  "onboarding": {
    "tenant": { "id": "…", "name": "…", "slug": "…", "status": "active", "createdAt": "…" },
    "infrastructure": { "jobId": "…", "status": "succeeded" },
    "domain": { "hostname": "abc.bmms.test", "type": "platform", "status": "pending",
                "ownershipVerifiedAt": null, "tlsReadyAt": null },
    "secretary": {
      "invitationId": "…", "email": "…", "invitationStatus": "pending",
      "linkExpiresAt": "…", "linkExpired": false,
      "emailVerification": { "status": "code_sent", "lastSentAt": "…", "codeExpiresAt": "…", "verifiedAt": null },
      "membership": { "accepted": false, "acceptedAt": null }
    }
  }
}
```
`emailVerification.status`: `not_requested`, `delivery_unconfirmed`,
`delivery_failed`, `code_sent`, `code_expired`, `attempts_exhausted`,
`verified`. No secret references, hashes or credentials. 404 `TENANT_NOT_FOUND`.

`GET /admin/provisioning-jobs/:jobId` → **200** `{ "job": { id, tenantId, status, attempts,
lastErrorCode, createdAt, updatedAt, steps[], secretaryInvitation } }` (unchanged).
A job is terminal at `succeeded` or `failed` (after 5 attempts); a `failed`
step on a non-terminal job is being retried.

### Recipient (no session; JSON body with the link token)

`POST /public/invitations/lookup` `{ "token": "<43 chars>" }` → **200**
```json
{ "invitation": { "state": "open", "organizationName": "…", "maskedEmail": "se•••••@company.com",
  "emailVerified": false,
  "code": { "challengeId": "…", "expiresAt": "…", "attemptsRemaining": 5, "resendAvailableAt": "…" } } }
```
`state` is `open`, `expired` or `accepted` (the last two carry only
`organizationName`). `code` is null when there's no usable code. Rate limit 30/min.

`POST /public/invitations/email-verification/resend` `{ token }` → **202**
`{ "challengeId": "…", "message": "…" }`. Emails a code only (no link).
Errors as for the admin send, plus 409 `EMAIL_ALREADY_VERIFIED`, 410
`INVITATION_EXPIRED`. Rate limit 5/min.

`POST /public/invitations/email-verification/confirm` `{ token, code, challengeId? }` → **200**
`{ "verified": true, "verifiedAt": "…" }`. Pass the `challengeId` the page
knows, to detect a newer code. Errors: 400 `OTP_INVALID`; 404
`OTP_NOT_REQUESTED`; 409 `OTP_CHALLENGE_CHANGED`, `OTP_ALREADY_USED`,
`EMAIL_ALREADY_VERIFIED`; 410 `OTP_EXPIRED`, `INVITATION_EXPIRED`;
429 `OTP_ATTEMPTS_EXCEEDED`. Rate limit 10/min.

All three: 404 `INVITATION_LINK_INVALID` for any unusable link.

### Acceptance (organization platform, internal API)

The secretary accepts on the organization platform, signed in through the
organization realm. Its backend calls `POST /internal/v1/invitations/accept`
with the link token and the verified identity — see
`../org-platform-handoff/CONTRACT.md`. The control plane records the
accepting identity (`accepted_issuer`, `accepted_subject`); membership lives
in the organization's database.

### Login return

`GET /auth/login?returnTo=<path>` returns to `<FRONTEND_ORIGIN><path>` for
`/master…` paths only; anything else returns to `/master`.

## Removed

`POST /admin/invitations/:id/email-verification/confirm` (admin entering the
secretary's code) was removed: the secretary verifies their own address.
`POST /invitations/accept`, the `/tenant/*` routes and the login handoff moved
to the organization platform (migration 013 dropped their tables/columns).

## Added for organization domains

See [tenancy-and-domains.md](tenancy-and-domains.md) for the model.

| Endpoint | Who | Purpose |
|---|---|---|
| `GET /admin/tenants` | admin | organizations with onboarding facts and `url` (active domains only) |
| `POST /admin/provisioning-jobs/:id/retry` | admin | re-open a failed job (202); 409 `JOB_NOT_FAILED` otherwise |
| `GET /admin/platform/domain-check` | admin | shared DNS/ingress/TLS check |
| `POST /admin/tenants/:id/domains/check` | admin | re-check the platform hostname now |
| `GET/POST /admin/tenants/:id/custom-domains` | admin | list / register a custom hostname (pending) |
| `POST /admin/tenants/:id/custom-domains/:domainId/verify` | admin | verify ownership, routing, TLS |
| `GET /internal/v1/tenants/resolve?hostname=` | organization platform (service token) | hostname → organization, `ready` flag |
| `GET /internal/v1/tenants/:id/database` | organization platform | runtime-role connection (active only) |
| `GET /internal/v1/tenants/:id/storage` | organization platform | storage location (active only) |
| `POST /internal/v1/invitations/accept` | organization platform | accept for an organization-realm identity |
| `GET /admin/administrators` | admin | platform administrators |

The onboarding response now also includes `storage`,
domain check details (`url`, `provider`, `lastCheckedAt`, `lastErrorCode`,
`routingVerifiedAt`), `customDomains`, `readiness { canOpen, organizationUrl }`
and `secretary.delivery` (the automatic invitation's queue state).
Accepting an invitation returns `organizationUrl` once the domain is active.
