import zlib from "node:zlib";

const MAX_UNPACKED_BYTES = 512 * 1024 * 1024;

/**
 * Reads one file out of a .tmxplug (a gzipped tar) without unpacking it to
 * disk. Returns null when the archive has no such file.
 *
 * Rejects archives that use PAX extended headers (typeflag `x`/`g`) or GNU
 * long-name entries (`L`/`K`), because this reader has no way to apply those
 * path overrides. If it did, a crafted archive could show one benign
 * manifest.json to the consent/preview step and have node-tar extract a
 * different, elevated manifest later. Only regular files and directories are
 * accepted. A duplicate manifest entry is also refused.
 */
export function readArtifactFile(
  buffer: Buffer,
  wanted: string,
): Buffer | null {
  const tar = zlib.gunzipSync(buffer, { maxOutputLength: MAX_UNPACKED_BYTES });
  let offset = 0;
  let found: Buffer | null = null;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const field = (start: number, length: number) =>
      header
        .subarray(start, start + length)
        .toString("utf8")
        .replace(/\0.*$/s, "");
    const prefix = field(345, 155);
    const name = (
      prefix ? `${prefix}/${field(0, 100)}` : field(0, 100)
    ).replace(/^\.\//, "");
    const size = Number.parseInt(field(124, 12).trim() || "0", 8);
    if (!Number.isFinite(size) || size < 0) break;
    const typeflag = String.fromCharCode(header[156] || 0);
    // Allow NUL (old-style regular file), '0' (regular file), '5' (dir).
    // Everything else (hard/symlink, PAX x/g, GNU L/K, char/block device,
    // vendor extensions) is treated as "we don't understand this archive".
    if (
      header[156] !== 0 &&
      typeflag !== "0" &&
      typeflag !== "5"
    ) {
      throw new Error(
        `the archive uses an unsupported tar entry type (${typeflag || "\\0"})`,
      );
    }
    const start = offset + 512;
    if (name === wanted) {
      if (found !== null) {
        throw new Error(`the archive has more than one ${wanted} entry`);
      }
      found = tar.subarray(start, start + size);
    }
    offset = start + Math.ceil(size / 512) * 512;
  }
  return found;
}

/** The manifest.json packed in a .tmxplug, parsed but not validated. */
export function readArtifactManifest(buffer: Buffer): Record<string, unknown> {
  let raw: Buffer | null;
  try {
    raw = readArtifactFile(buffer, "manifest.json");
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    // Preserve the duplicate / unsupported-entry diagnostics the reader
    // emits for crafted archives; everything else collapses to the generic
    // "not a valid .tmxplug archive" to avoid leaking parser state.
    if (
      message.startsWith("the archive has more than one") ||
      message.startsWith("the archive uses an unsupported tar entry type")
    ) {
      throw err;
    }
    throw new Error("the file is not a valid .tmxplug archive");
  }
  if (!raw) throw new Error("the archive has no manifest.json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("manifest.json is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("manifest.json is not an object");
  }
  return parsed as Record<string, unknown>;
}

/** Whether two capability lists name the same set, order ignored. */
export function sameCapabilities(
  a: readonly string[],
  b: readonly string[],
): boolean {
  const left = new Set(a);
  const right = new Set(b);
  if (left.size !== right.size) return false;
  for (const capability of left) if (!right.has(capability)) return false;
  return true;
}
