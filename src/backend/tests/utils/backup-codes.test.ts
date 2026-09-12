import { describe, expect, it } from "vitest";
import {
  BACKUP_CODE_COUNT,
  BACKUP_CODE_LENGTH,
  findMatchingBackupCode,
  generateBackupCode,
  generateBackupCodes,
  hashBackupCode,
  hashBackupCodes,
} from "../../utils/backup-codes.js";

describe("generateBackupCode", () => {
  it("always produces a full-length code", () => {
    // Math.random().toString(36) drops trailing zeroes, so the old codes were
    // sometimes shorter than advertised.
    for (let i = 0; i < 200; i += 1) {
      expect(generateBackupCode()).toHaveLength(BACKUP_CODE_LENGTH);
    }
  });

  it("stays within the uppercase alphanumeric alphabet", () => {
    for (let i = 0; i < 200; i += 1) {
      expect(generateBackupCode()).toMatch(/^[0-9A-Z]+$/);
    }
  });

  it("uses the whole alphabet", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i += 1) {
      for (const char of generateBackupCode()) seen.add(char);
    }
    expect(seen.size).toBe(36);
  });
});

describe("generateBackupCodes", () => {
  it("returns the expected number of distinct codes", () => {
    const codes = generateBackupCodes();
    expect(codes).toHaveLength(BACKUP_CODE_COUNT);
    expect(new Set(codes).size).toBe(BACKUP_CODE_COUNT);
  });
});

describe("hashBackupCode", () => {
  it("produces a recognisable bcrypt digest", () => {
    const hash = hashBackupCode("ABCD1234");
    expect(hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
  });

  it("produces a different digest for the same input each call (salted)", () => {
    expect(hashBackupCode("AAAA1111")).not.toBe(hashBackupCode("AAAA1111"));
  });
});

describe("findMatchingBackupCode", () => {
  it("finds a hashed code and returns its index", () => {
    const plain = generateBackupCodes(3);
    const hashed = hashBackupCodes(plain);
    expect(findMatchingBackupCode(hashed, plain[0])).toBe(0);
    expect(findMatchingBackupCode(hashed, plain[2])).toBe(2);
  });

  it("returns -1 when nothing matches", () => {
    const hashed = hashBackupCodes(generateBackupCodes(2));
    expect(findMatchingBackupCode(hashed, "NOMATCH1")).toBe(-1);
    expect(findMatchingBackupCode(hashed, "")).toBe(-1);
  });

  it("still matches legacy plaintext entries so pre-migration codes work", () => {
    const codes = ["OLD11111", "OLD22222"];
    expect(findMatchingBackupCode(codes, "OLD11111")).toBe(0);
    expect(findMatchingBackupCode(codes, "OLD22222")).toBe(1);
    expect(findMatchingBackupCode(codes, "MISSING1")).toBe(-1);
  });

  it("handles a mixed list of hashed and legacy plaintext entries", () => {
    const legacyCode = "OLD11111";
    const hashedCode = "NEW22222";
    const stored = [legacyCode, hashBackupCode(hashedCode)];
    expect(findMatchingBackupCode(stored, legacyCode)).toBe(0);
    expect(findMatchingBackupCode(stored, hashedCode)).toBe(1);
  });

  it("returns -1 for non-array or non-string input", () => {
    expect(findMatchingBackupCode(null, "x")).toBe(-1);
    expect(findMatchingBackupCode(undefined, "x")).toBe(-1);
    expect(findMatchingBackupCode("not an array", "x")).toBe(-1);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(findMatchingBackupCode(["abc"], 123 as any)).toBe(-1);
  });
});
