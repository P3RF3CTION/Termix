import { afterEach, describe, expect, it } from "vitest";
import type { Request } from "express";
import {
  createCorsMiddleware,
  isCorsOriginAllowed,
  isDesktopAppOrigin,
} from "../../utils/cors-config.js";

function request(headers: Record<string, string> = {}): Request {
  // Default to a loopback peer so X-Forwarded-* in headers reflects a
  // request that came through the trusted reverse proxy.
  return {
    headers,
    protocol: "http",
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as Request;
}

afterEach(() => {
  delete process.env.CORS_ALLOWED_ORIGINS;
  delete process.env.ELECTRON_EMBEDDED;
});

describe("isCorsOriginAllowed", () => {
  it("allows requests without an Origin header", () => {
    expect(isCorsOriginAllowed(request(), undefined)).toBe(true);
  });

  it("allows the externally forwarded same origin", () => {
    const req = request({
      "x-forwarded-proto": "https",
      "x-forwarded-host": "termix.example",
    });
    expect(isCorsOriginAllowed(req, "https://termix.example")).toBe(true);
  });

  it("rejects an unknown origin even without an allowlist (fail-closed default)", () => {
    // The previous fallback echoed any origin together with
    // Access-Control-Allow-Credentials, letting any site a victim visits
    // read responses from this backend. The default now matches the
    // configured path's final fallback: only the request's own origin.
    const req = request({ host: "termix.example" });
    expect(isCorsOriginAllowed(req, "https://anything.example")).toBe(false);
  });

  it("still allows a request from the server's own origin without an allowlist", () => {
    const req = request({ host: "termix.example" });
    expect(isCorsOriginAllowed(req, "http://termix.example")).toBe(true);
  });

  it("allows an explicitly configured origin", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://portal.example";
    expect(isCorsOriginAllowed(request(), "https://portal.example")).toBe(true);
  });

  it("rejects an unlisted origin once an allowlist is configured", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://portal.example";
    const req = request({ host: "termix.example" });
    expect(isCorsOriginAllowed(req, "https://attacker.example")).toBe(false);
  });

  describe("embedded desktop backend", () => {
    it("rejects other websites even with no allowlist", () => {
      process.env.ELECTRON_EMBEDDED = "true";
      const req = request({ host: "127.0.0.1:30001" });
      expect(isCorsOriginAllowed(req, "https://evil.example")).toBe(false);
    });

    it("still allows the desktop app and the dev server", () => {
      process.env.ELECTRON_EMBEDDED = "true";
      const req = request({ host: "127.0.0.1:30001" });
      expect(isCorsOriginAllowed(req, "file://")).toBe(true);
      expect(isCorsOriginAllowed(req, "http://localhost:5173")).toBe(true);
      expect(isCorsOriginAllowed(req, undefined)).toBe(true);
    });

    it("allows an explicitly configured origin", () => {
      process.env.ELECTRON_EMBEDDED = "true";
      process.env.CORS_ALLOWED_ORIGINS = "https://portal.example";
      expect(isCorsOriginAllowed(request(), "https://portal.example")).toBe(
        true,
      );
    });
  });
});

describe("isDesktopAppOrigin", () => {
  it("accepts no origin, file:// and the dev server", () => {
    expect(isDesktopAppOrigin(undefined)).toBe(true);
    expect(isDesktopAppOrigin("file://")).toBe(true);
    expect(isDesktopAppOrigin("http://127.0.0.1:5173")).toBe(true);
  });

  it("rejects websites", () => {
    expect(isDesktopAppOrigin("https://evil.example")).toBe(false);
    expect(isDesktopAppOrigin("null")).toBe(false);
  });
});

describe("createCorsMiddleware", () => {
  function run(origin: string | undefined) {
    const headers: Record<string, string> = { host: "termix.example" };
    if (origin) headers.origin = origin;
    const req = {
      headers,
      method: "POST",
      protocol: "https",
      socket: { remoteAddress: "127.0.0.1" },
    } as never;
    let status: number | undefined;
    let body: unknown;
    const resHeaders: Record<string, string> = {};
    const res = {
      statusCode: 200,
      status(code: number) {
        status = code;
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
    let nextErr: unknown = "not called";
    createCorsMiddleware()(req, res as never, (err?: unknown) => {
      nextErr = err;
    });
    return { status, body, nextErr, resHeaders };
  }

  it("answers a disallowed origin with 403 instead of an error (HTTP 500)", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://portal.example";
    const r = run("https://evil.example");
    expect(r.status).toBe(403);
    expect(r.body).toEqual({ error: "Origin not allowed" });
    expect(r.nextErr).toBe("not called");
  });

  it("passes an allowed origin through with CORS headers", () => {
    process.env.CORS_ALLOWED_ORIGINS = "https://portal.example";
    const r = run("https://portal.example");
    expect(r.status).toBeUndefined();
    expect(r.nextErr).toBeUndefined();
    expect(r.resHeaders["access-control-allow-origin"]).toBe(
      "https://portal.example",
    );
  });

  it("passes requests without an Origin header", () => {
    const r = run(undefined);
    expect(r.status).toBeUndefined();
    expect(r.nextErr).toBeUndefined();
  });
});
