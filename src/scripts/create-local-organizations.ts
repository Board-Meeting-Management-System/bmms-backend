// Development only: registers organizations as the platform administrator,
// exactly as POST /admin/tenants does (same validation, idempotency and
// provisioning job). The worker then provisions them.
//
//   npm run dev:create-organizations -- org-a org-b
//
// Each slug becomes <slug>.<PLATFORM_BASE_DOMAIN> and a secretary invitation
// for secretary@<slug>.example.com (use EMAIL_DELIVERY=file locally).

import { createHash } from "node:crypto";

import { pool } from "../db.js";
import { domainProvider } from "../modules/domains/domain-provider.js";
import { createOrganization } from "../modules/organizations/organization.service.js";

if (process.env.NODE_ENV !== "development") {
  throw new Error("This script only runs with NODE_ENV=development.");
}

const slugs = process.argv.slice(2);
if (slugs.length === 0) {
  console.error("Usage: npm run dev:create-organizations -- <slug> [<slug> ...]");
  process.exit(2);
}

try {
  const admins = await pool.query<{ id: string; email: string | null }>(
    `SELECT id, email FROM identities WHERE is_platform_admin AND status = 'active' ORDER BY created_at LIMIT 1`,
  );
  const admin = admins.rows[0];
  if (!admin) throw new Error("No platform administrator yet: sign in once, then run npm run admin:bootstrap.");

  for (const slug of slugs) {
    // Deterministic key: re-running the script doesn't register twice.
    const digest = createHash("sha256").update(`dev-create:${slug}`).digest("hex");
    const key = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;

    try {
      const result = await createOrganization(
        { name: slug.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), slug, secretaryEmail: `secretary@${slug}.example.com` },
        key,
        { id: admin.id, email: admin.email, emailVerified: true, status: "active", isPlatformAdmin: true },
      );
      const url = domainProvider().tenantUrl(domainProvider().platformHostname(slug));
      console.log(`${slug}: registered (job ${result.jobId}) → ${url}`);
      console.log(`  progress: http://localhost:3000/master/organizations/jobs/${result.jobId}`);
    } catch (error) {
      console.error(`${slug}: ${(error as { code?: string }).code ?? "FAILED"} ${(error as Error).message}`);
      process.exitCode = 1;
    }
  }
} finally {
  await pool.end();
}
