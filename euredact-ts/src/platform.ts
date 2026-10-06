/**
 * The two things the SDK needs from a crypto library: a SHA-256 digest for the
 * result-cache key and a uniform random index for token suffixes.
 *
 * This is the Node implementation, on `node:crypto`. A browser bundle gets
 * `platform.browser.ts` instead, through the `browser` field in package.json,
 * because `node:crypto` does not exist there and importing it from `cache.ts`
 * and `sdk.ts` made the package unbundleable for a page (rules-engine#56).
 * Every other module imports these two functions from here and nothing from
 * `node:`; a test holds the source tree to that.
 */
import { createHash, randomInt } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { gzipSync } from "node:zlib";

/** Hex SHA-256 of the UTF-8 encoding of `parts`, joined with nothing between. */
export function sha256Hex(parts: string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

/** A uniformly random integer in `[0, n)`. */
export function randomIndex(n: number): number {
  return randomInt(n);
}

/** Where a local batch file lives (rules-engine#84). Mirrors `BatchStore` in
 *  cloud/batches.ts; declared here so this module imports nothing from there. */
export interface PlatformBatchStore {
  read(batchId: string): Promise<Uint8Array | null>;
  write(batchId: string, data: Uint8Array): Promise<void>;
  delete(batchId: string): Promise<void>;
  list(): Promise<string[]>;
}

/**
 * `<dir>/<batchId>.json`, directory `0700`, files `0600`, the default local
 * batch store. Writes go to a temporary file in the same directory, created
 * `0600` before any byte is written, then renamed over the old one.
 */
export function defaultBatchStore(directory?: string): PlatformBatchStore | null {
  const dir = directory ?? path.join(os.homedir(), ".euredact", "batches");
  const fileFor = (batchId: string): string => {
    if (!batchId || /[/\\]/.test(batchId) || batchId === "." || batchId === "..") {
      throw new Error(`not a batch id: ${JSON.stringify(batchId)}`);
    }
    return path.join(dir, `${batchId}.json`);
  };
  return {
    async read(batchId) {
      try {
        return new Uint8Array(fs.readFileSync(fileFor(batchId)));
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
    },
    async write(batchId, data) {
      const target = fileFor(batchId);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      try { fs.chmodSync(dir, 0o700); } catch { /* not ours to change */ }
      const tmp = path.join(dir, `.${batchId}.${process.pid}.${Date.now()}.tmp`);
      const fd = fs.openSync(tmp, "wx", 0o600);
      try {
        fs.writeSync(fd, data);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      try {
        fs.renameSync(tmp, target);
      } catch (err) {
        try { fs.unlinkSync(tmp); } catch { /* already gone */ }
        throw err;
      }
    },
    async delete(batchId) {
      try { fs.unlinkSync(fileFor(batchId)); } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    },
    async list() {
      if (!fs.existsSync(dir)) return [];
      return fs.readdirSync(dir)
        .filter(name => name.endsWith(".json") && !name.startsWith("."))
        .map(name => name.slice(0, -".json".length))
        .sort();
    },
  };
}

/** Gzip, for the batch upload. */
export function gzip(data: Uint8Array): Uint8Array | null {
  return new Uint8Array(gzipSync(data));
}
