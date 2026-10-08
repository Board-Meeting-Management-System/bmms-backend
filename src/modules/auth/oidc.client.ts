import * as oidc from "openid-client";
import { authConfig } from "./auth.config.js";

let cachedConfiguration:
  | Promise<oidc.Configuration>
  | undefined;

export function getOidcClient(): Promise<oidc.Configuration> {
  if (!cachedConfiguration) {
    cachedConfiguration = discoverConfiguration().catch((error) => {
      // Allow another attempt if discovery fails.
      cachedConfiguration = undefined;
      throw error;
    });
  }

  return cachedConfiguration;
}

async function discoverConfiguration(): Promise<oidc.Configuration> {
  const issuer = new URL(authConfig.issuer);

  const allowLocalHttp =
    process.env.NODE_ENV === "development" &&
    issuer.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname);

  return oidc.discovery(
    issuer,
    authConfig.client_id,
    authConfig.clientSecret,
    oidc.ClientSecretPost(authConfig.clientSecret),
    {
      ...(allowLocalHttp
        ? { execute: [oidc.allowInsecureRequests] }
        : {}),
    },
  );
}