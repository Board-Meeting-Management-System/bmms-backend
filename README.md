# BMMS TypeScript backend

Fastify API and provisioning worker for BMMS: Keycloak browser login, platform
administration, organization registration and provisioning (one PostgreSQL
database per organization), and secretary onboarding (invitation email,
recipient email verification, invitation acceptance).

## Documentation
- [docs/local-development.md](docs/local-development.md) — startup commands, tests, Keycloak setup, manual email smoke test.
- [docs/onboarding-api.md](docs/onboarding-api.md) — onboarding flow and API contract.
- [docs/lan-testing.md](docs/lan-testing.md) — opt-in setup for testing from other computers.

## Requirements
Node.js 24+, npm, Docker Engine with the Compose plugin (or a local PostgreSQL 17 instance).
Run commands from this project directory. No cloud account or domain is needed yet.

## Start locally
```bash
cp .env.example .env
npm install
docker compose up -d --wait
npm run db:migrate
npm run dev
```
If a package-lock.json is included, use `npm ci` instead of `npm install`.
Open another terminal:
```bash
curl http://127.0.0.1:3001/health
curl http://127.0.0.1:3001/ready
```
Health returns status ok. Readiness returns status ready only if PostgreSQL is reachable.
Without Docker, create a development database and adjust CONTROL_DATABASE_URL.
Change FRONTEND_ORIGIN for your frontend (for example http://localhost:3000).
Use localhost consistently in the browser to match the configured origin.

## Checks and compiled run
```bash
npm run typecheck
npm run build
npm start
```
Stop the development server before npm start because they use the same port.
`docker compose stop` stops PostgreSQL while retaining its data.

## Files
- src/app.ts: application and health/readiness routes.
- src/server.ts: HTTP listener and graceful shutdown.
- src/config.ts: environment validation.
- src/db.ts: central PostgreSQL pool.
- src/migrate.ts: ordered, checksummed SQL migrations under an advisory lock.
- migrations/control/: central database migrations. Never edit an applied migration.
- src/worker.ts: provisioning worker (`npm run dev:worker`); runs separately from the API.
- src/modules/auth/: Keycloak login (PKCE), sessions, platform-admin checks.
- src/modules/organizations/: registration (`POST /admin/tenants`) and onboarding status.
- src/modules/provisioning/: job status endpoint and the six worker steps.
- src/modules/invitations/: invitation email, recipient OTP verification, acceptance.
- tests/: `test:unit` (no database), `test:onboarding` (disposable database).

The migration runner supports transactional control-database SQL only. CREATE DATABASE
belongs in the provisioning adapter, outside a transaction. updated_at must be set by
future write queries; no update trigger is installed.

## Not implemented yet
- Domain readiness (DNS ownership, TLS): domains stay `pending`.
- Real KMS and secrets-manager adapters.
- Listing organizations, and suspend/reactivate/retry operations.
- What a membership grants inside the organization's own application.

## Local credentials and production boundary
The Compose credentials are disposable local-development values, bound to loopback.
The local bootstrap database user is privileged: this starter does not demonstrate
production privilege isolation. Split migration, API and provisioner identities before
connecting real organizations. Never use these credentials or expose this Compose database
in production. .env is ignored; do not commit it. No secrets should appear in logs.

Reference: https://fastify.dev/docs/latest/Reference/TypeScript/
