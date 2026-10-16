import { describe, expect, it } from "vitest";
import path from "node:path";
import {
  resolveWithinDir,
  safeFileSegment,
} from "../../utils/safe-data-path.js";

/**
 * The database restore endpoint takes its read and write paths from the request
 * body. It is admin-only, but an admin session is exactly what an attacker who
 * lands one wants to turn into arbitrary file access, so the paths are confined
 * to DATA_DIR. These are the escapes that confinement has to refuse.
 */
describe("resolveWithinDir", () => {
  const base = "/app/data";

  it("accepts a plain relative path inside the base", () => {
    expect(resolveWithinDir(base, "backups/db.sqlite.encrypted")).toBe(
      path.resolve("/app/data/backups/db.sqlite.encrypted"),
    );
  });

  it("accepts the base directory itself", () => {
    expect(resolveWithinDir(base, ".")).toBe(path.resolve(base));
  });

  it("refuses a traversal escape", () => {
    expect(resolveWithinDir(base, "../etc/shadow")).toBeNull();
    expect(resolveWithinDir(base, "backups/../../etc/passwd")).toBeNull();
  });

  it("refuses an absolute path outside the base", () => {
    expect(resolveWithinDir(base, "/etc/shadow")).toBeNull();
    expect(resolveWithinDir(base, "/app/data-evil/db")).toBeNull();
  });

  it("does not treat a sibling with a shared prefix as inside", () => {
    // /app/dataX must not pass as being under /app/data.
    expect(resolveWithinDir("/app/data", "/app/dataX/db")).toBeNull();
  });

  it("refuses empty, non-string and null-byte input", () => {
    expect(resolveWithinDir(base, "")).toBeNull();
    expect(resolveWithinDir(base, undefined)).toBeNull();
    expect(resolveWithinDir(base, null)).toBeNull();
    expect(resolveWithinDir(base, 42)).toBeNull();
    expect(resolveWithinDir(base, "backups/db\0.encrypted")).toBeNull();
  });
});

describe("safeFileSegment", () => {
  it("keeps an ordinary file name", () => {
    expect(safeFileSegment("termix-backup.sqlite")).toBe(
      "termix-backup.sqlite",
    );
  });

  it("drops every directory part, Unix and Windows style", () => {
    expect(safeFileSegment("../../data/termix.sqlite")).toBe("termix.sqlite");
    expect(safeFileSegment("..\\..\\x.sqlite")).toBe("x.sqlite");
    expect(safeFileSegment("/etc/x.sqlite")).toBe("x.sqlite");
  });

  it("never yields a path separator, a leading dot or a traversal", () => {
    for (const name of ["../../../evil", "..", ".", "a/../b", ".hidden"]) {
      const out = safeFileSegment(name, "user");
      expect(out).not.toMatch(/[/\\]/);
      expect(out.startsWith(".")).toBe(false);
      expect(out).not.toBe("..");
    }
  });

  it("replaces unusual characters and bounds the length", () => {
    expect(safeFileSegment("al ice@corp")).toBe("al_ice_corp");
    expect(safeFileSegment("x".repeat(300))).toHaveLength(100);
  });

  it("falls back for empty or non-string input", () => {
    expect(safeFileSegment("", "user")).toBe("user");
    expect(safeFileSegment(undefined, "user")).toBe("user");
    expect(safeFileSegment("../", "user")).toBe("user");
  });
});
