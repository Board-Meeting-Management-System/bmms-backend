import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";

// Private file storage per organization.
//
//   STORAGE_PROVIDER=local  a 0700 directory per organization under
//                           TENANT_STORAGE_ROOT (default ./.storage/tenants)
//
// No production adapter exists yet: STORAGE_PROVIDER=production fails the
// storage step with STORAGE_PROVIDER_UNSUPPORTED rather than pretending.
// Extension point: implement StorageProvider for the object store you choose
// (one bucket prefix or bucket per organization, server-side credentials).

export interface StorageProvider {
  readonly kind: string;
  /** Creates (or confirms) the organization's private storage; returns its reference. */
  ensureTenantStorage(tenantId: string): Promise<string>;
  /** Confirms the referenced storage exists and belongs to this organization. */
  verifyTenantStorage(tenantId: string, ref: string): Promise<boolean>;
  /**
   * The location of an object inside the organization's storage. The tenant
   * comes from server-side context, never from the request; keys can't escape it.
   */
  objectPath(tenantId: string, key: string): string;
  /** The organization's root on this machine, for providers that have one. */
  rootPath(tenantId: string): string | null;
  /** Total size and file count of the organization's storage. */
  measure(tenantId: string): Promise<{ bytes: number; files: number }>;
  /** Permanently removes the organization's storage (deletion). Idempotent. */
  deleteTenantStorage(tenantId: string): Promise<void>;
}

export class StorageUnavailableError extends Error {
  constructor(public readonly code: string) {
    super(`Tenant storage unavailable: ${code}`);
    this.name = "StorageUnavailableError";
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MARKER = ".bmms-tenant";

function assertTenantId(tenantId: string) {
  if (!UUID.test(tenantId)) throw new Error("Invalid tenant ID.");
}

export class LocalStorageProvider implements StorageProvider {
  readonly kind = "local";

  constructor(private readonly root: string) {
    if (!path.isAbsolute(root)) throw new Error("TENANT_STORAGE_ROOT must be absolute.");
  }

  private tenantDir(tenantId: string) {
    assertTenantId(tenantId);
    return path.join(this.root, tenantId);
  }

  async ensureTenantStorage(tenantId: string): Promise<string> {
    const dir = this.tenantDir(tenantId);
    // Idempotent: repeated runs reuse the directory after checking its owner.
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await chmod(dir, 0o700);
    const marker = path.join(dir, MARKER);
    try {
      const existing = (await readFile(marker, "utf8")).trim();
      if (existing !== tenantId) throw new StorageUnavailableError("STORAGE_OWNERSHIP_MISMATCH");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await writeFile(marker, `${tenantId}\n`, { mode: 0o600, flag: "wx" }).catch((e: NodeJS.ErrnoException) => {
        if (e.code !== "EEXIST") throw e;
      });
    }
    return `local-fs:${tenantId}`;
  }

  async verifyTenantStorage(tenantId: string, ref: string): Promise<boolean> {
    if (ref !== `local-fs:${tenantId}`) return false;
    const dir = this.tenantDir(tenantId);
    try {
      const info = await stat(dir);
      const marker = (await readFile(path.join(dir, MARKER), "utf8")).trim();
      return info.isDirectory() && (info.mode & 0o077) === 0 && marker === tenantId;
    } catch {
      return false;
    }
  }

  rootPath(tenantId: string): string {
    return this.tenantDir(tenantId);
  }

  async measure(tenantId: string): Promise<{ bytes: number; files: number }> {
    let bytes = 0;
    let files = 0;
    const walk = async (dir: string) => {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
        throw error;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full);
        else if (entry.isFile() && entry.name !== MARKER) {
          bytes += (await stat(full)).size;
          files += 1;
        }
      }
    };
    await walk(this.tenantDir(tenantId));
    return { bytes, files };
  }

  async deleteTenantStorage(tenantId: string): Promise<void> {
    const dir = this.tenantDir(tenantId);
    // tenantDir only builds paths directly under the root from a UUID.
    if (path.dirname(dir) !== this.root) throw new Error("Refusing to delete outside the storage root.");
    await rm(dir, { recursive: true, force: true });
  }

  objectPath(tenantId: string, key: string): string {
    const segments = key.split("/");
    if (segments.length === 0 || segments.length > 16 || !segments.every((s) => KEY_SEGMENT.test(s) && s !== MARKER)) {
      throw new Error("Invalid storage key.");
    }
    const dir = this.tenantDir(tenantId);
    const resolved = path.resolve(dir, ...segments);
    if (!resolved.startsWith(dir + path.sep)) throw new Error("Invalid storage key.");
    return resolved;
  }
}

class UnsupportedStorageProvider implements StorageProvider {
  readonly kind = "production";
  async ensureTenantStorage(): Promise<string> {
    throw new StorageUnavailableError("STORAGE_PROVIDER_UNSUPPORTED");
  }
  async verifyTenantStorage(): Promise<boolean> {
    return false;
  }
  objectPath(): string {
    throw new StorageUnavailableError("STORAGE_PROVIDER_UNSUPPORTED");
  }
  rootPath(): null {
    return null;
  }
  async measure(): Promise<{ bytes: number; files: number }> {
    throw new StorageUnavailableError("STORAGE_PROVIDER_UNSUPPORTED");
  }
  async deleteTenantStorage(): Promise<void> {
    throw new StorageUnavailableError("STORAGE_PROVIDER_UNSUPPORTED");
  }
}

export function createStorageProviderFromEnv(env: NodeJS.ProcessEnv = process.env): StorageProvider {
  const production = env.NODE_ENV === "production";
  const kind = env.STORAGE_PROVIDER?.trim() || (production ? "" : "local");

  if (kind === "local") {
    if (production) throw new Error("STORAGE_PROVIDER=local is not allowed in production.");
    return new LocalStorageProvider(path.resolve(env.TENANT_STORAGE_ROOT?.trim() || ".storage/tenants"));
  }
  if (kind === "production") return new UnsupportedStorageProvider();
  throw new Error("STORAGE_PROVIDER must be local or production.");
}

let provider: StorageProvider | undefined;

export function storageProvider(): StorageProvider {
  provider ??= createStorageProviderFromEnv();
  return provider;
}
