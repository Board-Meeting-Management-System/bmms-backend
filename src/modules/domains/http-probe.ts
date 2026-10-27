import http from "node:http";
import https from "node:https";

// A bounded GET used by domain checks. It connects to an address the caller
// has already approved (never to whatever DNS says at connect time), sends
// the tenant hostname as Host (and as TLS SNI), follows no redirects, and
// reads at most a few kilobytes.

export interface ProbeTarget {
  protocol: "http:" | "https:";
  /** The approved IP or loopback address to connect to. */
  address: string;
  port: number;
  /** Host header value and, for HTTPS, the certificate name checked. */
  hostname: string;
  path: string;
  timeoutMs: number;
  /** Test hook: extra trusted CAs. Verification is never disabled. */
  ca?: string | Buffer;
}

export type ProbeResult =
  | { ok: true; status: number; body: unknown }
  | { ok: false; errorCode: "UNREACHABLE" | "TIMEOUT" | "TLS_INVALID" | "BAD_RESPONSE" };

const MAX_BODY_BYTES = 4096;

const TLS_ERROR = /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|HOSTNAME|ALTNAME/i;

export function probe(target: ProbeTarget): Promise<ProbeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result: ProbeResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const options = {
      host: target.address,
      port: target.port,
      path: target.path,
      method: "GET",
      headers: { Host: target.port === (target.protocol === "https:" ? 443 : 80) ? target.hostname : `${target.hostname}:${target.port}`, Accept: "application/json" },
      timeout: target.timeoutMs,
      ...(target.protocol === "https:"
        ? { servername: target.hostname, rejectUnauthorized: true, ...(target.ca ? { ca: target.ca } : {}) }
        : {}),
    };

    const request = (target.protocol === "https:" ? https : http).request(options, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          request.destroy();
          done({ ok: false, errorCode: "BAD_RESPONSE" });
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        try {
          done({ ok: true, status: response.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch {
          done({ ok: false, errorCode: "BAD_RESPONSE" });
        }
      });
      response.on("error", () => done({ ok: false, errorCode: "UNREACHABLE" }));
    });

    request.on("timeout", () => {
      request.destroy();
      done({ ok: false, errorCode: "TIMEOUT" });
    });
    request.on("error", (error: NodeJS.ErrnoException) => {
      done({ ok: false, errorCode: TLS_ERROR.test(error.code ?? "") || TLS_ERROR.test(error.message) ? "TLS_INVALID" : "UNREACHABLE" });
    });
    request.end();
  });
}

/** The tenant identity our app reports at /bmms-routing for a hostname. */
export function readRoutingIdentity(body: unknown): { hostname: string; organizationId: string } | null {
  if (!body || typeof body !== "object") return null;
  const { hostname, organizationId } = body as Record<string, unknown>;
  return typeof hostname === "string" && typeof organizationId === "string" ? { hostname, organizationId } : null;
}

/** True when the response is our app saying it knows no organization here. */
export function isUnknownTenantResponse(result: ProbeResult): boolean {
  return (
    result.ok &&
    result.status === 404 &&
    !!result.body &&
    typeof result.body === "object" &&
    (result.body as Record<string, unknown>).error === "TENANT_NOT_FOUND"
  );
}
