import type { Request } from "express";
import type { IncomingMessage } from "http";
import { isTrustedProxy, resolveRequestClientIp } from "./trusted-proxies.js";

function firstHeaderValue(value: string | string[] | undefined): string {
  if (!value) return "";
  const raw = Array.isArray(value) ? value[0] : value;
  return raw.split(",")[0].trim();
}

function normalizePort(value: string | string[] | undefined): string {
  const raw = firstHeaderValue(value);
  if (!/^\d+$/.test(raw)) return "";

  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return "";

  return String(port);
}

function splitHostHeader(value: string | string[] | undefined): {
  host: string;
  port: string;
} {
  const raw = firstHeaderValue(value) || "localhost";

  if (raw.startsWith("[")) {
    const match = raw.match(/^(\[[^\]]+\])(?::(.+))?$/);
    return {
      host: match?.[1] || raw,
      port: normalizePort(match?.[2]),
    };
  }

  const parts = raw.split(":");
  if (parts.length === 2) {
    return {
      host: parts[0] || "localhost",
      port: normalizePort(parts[1]),
    };
  }

  return {
    host: raw,
    port: "",
  };
}

export function normalizeBasePath(value: unknown): string {
  if (typeof value !== "string") return "";
  let basePath = value.split(",")[0].trim();
  if (!basePath) return "";

  try {
    if (/^https?:\/\//i.test(basePath)) {
      basePath = new URL(basePath).pathname;
    }
  } catch {
    return "";
  }

  basePath = basePath.split("?")[0].split("#")[0].trim();
  if (!basePath || basePath === "/") return "";
  if (!basePath.startsWith("/")) basePath = `/${basePath}`;
  return basePath.replace(/\/+$/, "");
}

/**
 * Real client IP behind a reverse proxy.
 *
 * `X-Forwarded-For`'s *leftmost* entry is whatever the first hop was told, and
 * every hop only appends - so a client that sends `X-Forwarded-For: 1.2.3.4`
 * puts that value in front of its own address and the leftmost entry becomes
 * attacker-controlled. Rate-limit buckets and audit records keyed on it are
 * therefore forgeable. `resolveClientIp` instead walks the chain from the
 * socket peer leftwards and stops at the first hop that is not a configured
 * trusted proxy (see `TRUSTED_PROXIES`).
 */
export function getClientIp(req: Request | IncomingMessage): string {
  // Express has already applied the same `trust proxy` setting to produce
  // req.ip, so prefer it where it exists; the manual walk is for the
  // WebSocket upgrade path, which never passes through Express.
  if ("ip" in req && req.ip) return req.ip;

  return resolveRequestClientIp(req as IncomingMessage);
}

/**
 * Whether the immediate peer that opened this connection is on the operator's
 * trusted-proxy list. When it isn't, X-Forwarded-* headers were written by
 * an untrusted client and must not steer origin, port, or protocol -- they
 * become inputs to the OIDC callback URL and the CORS same-origin fallback,
 * so trusting client-supplied values there is a redirect-hijack primitive.
 */
function peerIsTrustedProxy(req: Request | IncomingMessage): boolean {
  const socket = (req as { socket?: { remoteAddress?: string } }).socket;
  return isTrustedProxy(socket?.remoteAddress);
}

export function getRequestOrigin(req: Request | IncomingMessage): string {
  const trustForwarded = peerIsTrustedProxy(req);

  let protocol: string;
  const protoHeader = trustForwarded
    ? req.headers["x-forwarded-proto"]
    : undefined;

  if (protoHeader) {
    const raw =
      typeof protoHeader === "string"
        ? protoHeader.split(",")[0].trim()
        : protoHeader[0];
    // Normalize WebSocket protocols to their HTTP equivalents
    protocol = raw === "wss" ? "https" : raw === "ws" ? "http" : raw;
  } else if ("protocol" in req && req.protocol) {
    protocol = req.protocol;
  } else {
    protocol = (req.socket as unknown as { encrypted?: boolean }).encrypted
      ? "https"
      : "http";
  }

  let port = trustForwarded
    ? normalizePort(req.headers["x-forwarded-port"])
    : "";
  const { host, port: hostPort } = splitHostHeader(
    (trustForwarded && req.headers["x-forwarded-host"]) || req.headers.host,
  );
  port ||= hostPort;

  if (port) {
    const isDefaultPort =
      (protocol === "http" && port === "80") ||
      (protocol === "https" && port === "443");

    return isDefaultPort
      ? `${protocol}://${host}`
      : `${protocol}://${host}:${port}`;
  }

  return `${protocol}://${host}`;
}

export function getRequestOriginWithForceHTTPS(
  req: Request | IncomingMessage,
): string {
  if (process.env.OIDC_FORCE_HTTPS === "true") {
    const origin = getRequestOrigin(req);
    return origin.replace(/^http:/, "https:");
  }
  return getRequestOrigin(req);
}

export function getRequestBasePath(req: Request | IncomingMessage): string {
  const envBasePath = normalizeBasePath(
    process.env.BASE_PATH || process.env.VITE_BASE_PATH,
  );
  if (envBasePath) return envBasePath;

  // Same rule as X-Forwarded-Host: don't let a peer that isn't a configured
  // reverse proxy dictate the effective base path -- it lands in redirect
  // targets and OIDC callback URLs, so a client-supplied prefix here is a
  // rewrite of where the browser is sent next.
  if (!peerIsTrustedProxy(req)) return "";

  return (
    normalizeBasePath(firstHeaderValue(req.headers["x-forwarded-prefix"])) ||
    normalizeBasePath(firstHeaderValue(req.headers["x-script-name"])) ||
    normalizeBasePath(firstHeaderValue(req.headers["x-original-prefix"]))
  );
}

export function getRequestBaseUrl(req: Request | IncomingMessage): string {
  return `${getRequestOrigin(req)}${getRequestBasePath(req)}`;
}

export function getRequestBaseUrlWithForceHTTPS(
  req: Request | IncomingMessage,
): string {
  return `${getRequestOriginWithForceHTTPS(req)}${getRequestBasePath(req)}`;
}
