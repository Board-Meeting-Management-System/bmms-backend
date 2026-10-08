# BMMS TypeScript backend — local foundation

This starter establishes the API and central database. It does NOT yet implement
organization registration, authentication, tenant provisioning, KMS, or invitations.
The worker entry point reports that it is unimplemented and exits without modifying jobs.

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
- src/worker.ts: reserved entry point for the provisioning process.

The migration runner supports transactional control-database SQL only. CREATE DATABASE
belongs in the provisioning adapter, outside a transaction. updated_at must be set by
future write queries; no update trigger is installed.

## Next implementation order
1. Add identities, domain mapping, invitation metadata and tenant resource-reference migrations.
2. Add administrator authentication and authorization; do not expose an unprotected create endpoint.
3. Implement POST /admin/tenants. In one transaction insert tenant, domain, pending
   invitation metadata, job and steps. Enforce idempotency and request-hash matching.
4. Add authorized job-status and organization-detail endpoints for the frontend.
5. Implement a separate worker: atomic claims, expiring leases with fencing,
   bounded retries and resource reconciliation before every retry.
6. Implement tenant database creation, restricted runtime roles and tenant migrations.
7. Add secrets manager and real KMS adapters, then domain readiness and activation.
8. Add invitation delivery and acceptance; prove two-tenant isolation.

Keep tenants unavailable until actual required checks pass. Do not simulate successful
KMS setup and activate tenants. Document keys are generated when documents are saved.

## Local credentials and production boundary
The Compose credentials are disposable local-development values, bound to loopback.
The local bootstrap database user is privileged: this starter does not demonstrate
production privilege isolation. Split migration, API and provisioner identities before
connecting real organizations. Never use these credentials or expose this Compose database
in production. .env is ignored; do not commit it. No secrets should appear in logs.

Reference: https://fastify.dev/docs/latest/Reference/TypeScript/
