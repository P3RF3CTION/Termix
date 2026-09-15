import { describe, it, expect } from "vitest";
import { safeUrl, isSafeUrl } from "../../lib/safe-url";

describe("safeUrl", () => {
  it("passes http and https URLs through", () => {
    expect(safeUrl("https://example.com/path?q=1")).toBe(
      "https://example.com/path?q=1",
    );
    expect(safeUrl("http://example.com")).toBe("http://example.com");
  });

  it("passes mailto and tel URLs", () => {
    expect(safeUrl("mailto:user@example.com")).toBe("mailto:user@example.com");
    expect(safeUrl("tel:+491234")).toBe("tel:+491234");
  });

  it("rejects javascript: URLs in every casing and whitespace form", () => {
    expect(safeUrl("javascript:alert(1)")).toBe("");
    expect(safeUrl("JavaScript:alert(1)")).toBe("");
    expect(safeUrl("  javascript:alert(1)  ")).toBe("");
    // A tab or newline between "java" and "script" is stripped by the URL
    // parser, so the resulting scheme becomes "javascript:" and stays
    // blocked.
    expect(safeUrl("java\tscript:alert(1)")).toBe("");
    expect(safeUrl("java\nscript:alert(1)")).toBe("");
  });

  it("rejects data: URLs (svg script payload vector)", () => {
    expect(safeUrl("data:text/html,<script>alert(1)</script>")).toBe("");
    expect(safeUrl("data:image/svg+xml,<svg/onload=alert(1)>")).toBe("");
  });

  it("rejects vbscript and file schemes", () => {
    expect(safeUrl("vbscript:msgbox(1)")).toBe("");
    expect(safeUrl("file:///etc/passwd")).toBe("");
  });

  it("passes relative URLs unchanged", () => {
    expect(safeUrl("/dashboard/hosts")).toBe("/dashboard/hosts");
    expect(safeUrl("./nested")).toBe("./nested");
    expect(safeUrl("#section")).toBe("#section");
    expect(safeUrl("?tab=1")).toBe("?tab=1");
  });

  it("returns empty string for null/undefined/non-string input", () => {
    expect(safeUrl(null)).toBe("");
    expect(safeUrl(undefined)).toBe("");
    expect(safeUrl("")).toBe("");
    expect(safeUrl("   ")).toBe("");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(safeUrl(123 as any)).toBe("");
  });

  it("isSafeUrl matches safeUrl", () => {
    expect(isSafeUrl("https://x")).toBe(true);
    expect(isSafeUrl("javascript:x")).toBe(false);
  });
});
