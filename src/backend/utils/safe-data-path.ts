import fs from "node:fs";
import path from "node:path";

/**
 * Confines a caller-supplied path to a base directory.
 *
 * The database backup/restore endpoint takes `backupPath` and `targetPath`
 * straight from the request body and hands them to `fs` as read and write
 * targets. It is admin-only, but "only an admin can reach it" is not the same
 * as "it cannot escape the data directory": an admin session is exactly what an
 * attacker who lands one wants to turn into arbitrary file read/write on the
 * host. Backups only ever live under DATA_DIR, so nothing legitimate needs to
 * point outside it.
 *
 * Returns the resolved absolute path when it stays within `baseDir`, or null
 * when it escapes -- including via `..`, an absolute path, or a symlink that
 * points out of the directory. The function also follows symlinks on every
 * existing ancestor of the resolved path, so a link planted inside the data
 * directory that points elsewhere cannot be used to escape. Comparison is
 * done on resolved paths with a trailing separator so that `/data-evil`
 * cannot pass as being inside `/data`.
 */
export function resolveWithinDir(
  baseDir: string,
  candidate: unknown,
): string | null {
  if (typeof candidate !== "string" || candidate.length === 0) return null;
  if (candidate.includes("\0")) return null;

  const base = path.resolve(baseDir);
  const resolved = path.resolve(base, candidate);

  const baseWithSep = base.endsWith(path.sep) ? base : base + path.sep;
  if (resolved !== base && !resolved.startsWith(baseWithSep)) return null;

  // Resolve symlinks on the nearest existing ancestor. If any component
  // along the chain is a symlink pointing outside the base, reject.
  let realAncestor: string | null = null;
  let cursor = resolved;
  while (cursor !== path.dirname(cursor)) {
    try {
      realAncestor = fs.realpathSync(cursor);
      break;
    } catch {
      cursor = path.dirname(cursor);
    }
  }
  if (realAncestor !== null) {
    const remainder = path.relative(cursor, resolved);
    const realResolved = path.resolve(realAncestor, remainder);
    const realBase = (() => {
      try {
        return fs.realpathSync(base);
      } catch {
        return base;
      }
    })();
    const realBaseWithSep = realBase.endsWith(path.sep)
      ? realBase
      : realBase + path.sep;
    if (
      realResolved !== realBase &&
      !realResolved.startsWith(realBaseWithSep)
    ) {
      return null;
    }
  }

  return resolved;
}

/**
 * Turns a caller-supplied name (an upload's original file name, a username
 * from a sign-up form or an identity provider) into a single file-name
 * segment: no directory part, no separators, no leading dots, a bounded
 * length. Used wherever such a name becomes part of a path on disk.
 */
export function safeFileSegment(name: unknown, fallback = "file"): string {
  if (typeof name !== "string") return fallback;
  const base = name.split(/[/\\]/).pop() ?? "";
  const cleaned = base
    .replace(/\0/g, "")
    .replace(/[^A-Za-z0-9._-]/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 100);
  return cleaned.length > 0 ? cleaned : fallback;
}
