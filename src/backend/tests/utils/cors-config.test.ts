import { afterEach, describe, expect, it } from "vitest";
import type { Request } from "express";
import {
  createCorsMiddleware,
  isAllowedOrigin,
} from "../../utils/cors-config.js";

const originalAllowed = process.env.CORS_ALLOWED_ORIGINS;

afterEach(() => {
  if (originalAllowed === undefined) {
    delete process.env.CORS_ALLOWED_ORIGINS;
  } else {
    process.env.CORS_ALLOWED_ORIGINS = originalAllowed;
  }
});

/** A request as it reaches the backend through the bundled nginx. */
function proxiedRequest(headers: Record<string, string>) {
  return {
    headers,
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as Request;
}

const behindProxy = proxiedRequest({
  host: "termix.example.com",
  "x-forwarded-proto": "https",
  "x-forwarded-host": "termix.example.com",
});

describe("isAllowedOrigin", () => {
  it("requires an explicit allowlist entry (no Host-based fallback)", () => {
    // Without CORS_ALLOWED_ORIGINS, a public origin is refused even when its
    // value matches the request's Host header. The Host header is attacker-
    // controlled through any proxy that does not strictly pin the host, so
    // reflecting it enabled a cross-origin credentialed-fetch attack.
    expect(isAllowedOrigin("https://termix.example.com", behindProxy)).toBe(
      false,
    );
  });

  it("allows the origin once it is explicitly on the configured allowlist", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://termix.example.com";
    expect(isAllowedOrigin("https://termix.example.com", behindProxy)).toBe(
      true,
    );
  });

  it("rejects a foreign origin even though the TCP peer is loopback", () => {
    // Every request arrives from 127.0.0.1 in a containerized deployment,
    // so a peer-address check would reflect this origin with credentials.
    expect(isAllowedOrigin("https://evil.example", behindProxy)).toBe(false);
  });

  it("rejects an origin that merely looks like the real host", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://termix.example.com";
    expect(
      isAllowedOrigin("https://termix.example.com.evil.example", behindProxy),
    ).toBe(false);
    expect(isAllowedOrigin("http://termix.example.com", behindProxy)).toBe(
      false,
    );
  });

  it("allows the desktop app and local dev clients", () => {
    expect(isAllowedOrigin("file://", behindProxy)).toBe(true);
    expect(isAllowedOrigin("http://localhost:5173", behindProxy)).toBe(true);
    expect(isAllowedOrigin("http://127.0.0.1:30001", behindProxy)).toBe(true);
    expect(isAllowedOrigin("http://[::1]:8080", behindProxy)).toBe(true);
  });

  it("honours the configured allowlist", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://dash.example.com";
    expect(isAllowedOrigin("https://dash.example.com", behindProxy)).toBe(true);
    expect(isAllowedOrigin("https://other.example.com", behindProxy)).toBe(
      false,
    );
  });

  it("refuses a wildcard, which cannot be combined with credentials", () => {
    // This middleware sets credentials: true, and reflecting an arbitrary
    // origin alongside credentials hands every website the visitor's session.
    process.env.CORS_ALLOWED_ORIGINS = "*";
    expect(isAllowedOrigin("https://evil.example", behindProxy)).toBe(false);
  });

  it("honours the named origins in a list that also contains a wildcard", () => {
    process.env.CORS_ALLOWED_ORIGINS = "*,https://dash.example.com";
    expect(isAllowedOrigin("https://dash.example.com", behindProxy)).toBe(true);
    expect(isAllowedOrigin("https://evil.example", behindProxy)).toBe(false);
  });
});

describe("createCorsMiddleware", () => {
  function run(origin: string | undefined, method = "GET") {
    const headers: Record<string, string> = {};
    if (origin) headers.origin = origin;
    const req = {
      headers,
      method,
      path: "/users/me",
      socket: { remoteAddress: "127.0.0.1" },
    } as unknown as Request;
    let status: number | undefined;
    let body: unknown;
    const resHeaders: Record<string, string> = {};
    const res = {
      statusCode: 200,
      status(code: number) {
        status = code;
        this.statusCode = code;
        return this;
      },
      json(payload: unknown) {
        body = payload;
        return this;
      },
      setHeader(name: string, value: string) {
        resHeaders[name.toLowerCase()] = String(value);
      },
      getHeader(name: string) {
        return resHeaders[name.toLowerCase()];
      },
      end() {},
    };
    let nextCalled = false;
    let nextError: unknown;
    createCorsMiddleware()(req, res as never, (err?: unknown) => {
      nextCalled = true;
      nextError = err;
    });
    return { status, body, nextCalled, nextError, resHeaders };
  }

  it("answers a disallowed origin with 403 instead of an error (HTTP 500)", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://termix.example.com";
    const r = run("https://evil.example", "POST");
    expect(r.status).toBe(403);
    expect(r.body).toEqual({ error: "Origin not allowed" });
    expect(r.nextCalled).toBe(false);
  });

  it("passes an allowed origin through with CORS headers", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://termix.example.com";
    const r = run("https://termix.example.com");
    expect(r.status).toBeUndefined();
    expect(r.nextCalled).toBe(true);
    expect(r.nextError).toBeUndefined();
    expect(r.resHeaders["access-control-allow-origin"]).toBe(
      "https://termix.example.com",
    );
  });

  it("passes requests without an Origin header (same-origin GET, curl, native app)", () => {
    const r = run(undefined);
    expect(r.status).toBeUndefined();
    expect(r.nextCalled).toBe(true);
  });
});
