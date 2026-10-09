import { createHash, randomBytes } from "node:crypto";

// The invitation link token: 256 random bits, sent only in the invitation
// email. The database stores its SHA-256 hash (tenant_invitations.token_hash),
// so a database leak doesn't reveal working links.

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function generateInvitationToken(): string {
  return randomBytes(32).toString("base64url");
}

export function isInvitationToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export function hashInvitationToken(token: string): string {
  if (!isInvitationToken(token)) {
    throw new Error("Invalid invitation token.");
  }

  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * The page the secretary opens. The token goes in the fragment, which
 * browsers never send to servers or in Referer headers.
 */
export function invitationUrl(frontendOrigin: string, token: string): string {
  const url = new URL("/invitation", frontendOrigin);
  url.hash = `token=${token}`;
  return url.href;
}
