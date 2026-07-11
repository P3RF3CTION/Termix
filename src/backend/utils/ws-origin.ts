import type { IncomingMessage } from "http";

const DEV_ORIGINS = new Set([
  "http://localhost:5173",
  "http://127.0.0.1:5173",
]);
const ELECTRON_FILE_ORIGIN = "file://";

function getConfiguredOrigins(): string[] {
  const envOrigins = process.env.CORS_ALLOWED_ORIGINS;
  if (!envOrigins) return [];
  return envOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

function isSocketLocal(req: IncomingMessage): boolean {
  const remoteAddr = req.socket?.remoteAddress || "";
  return (
    remoteAddr === "127.0.0.1" ||
    remoteAddr === "::1" ||
    remoteAddr === "::ffff:127.0.0.1"
  );
}

function normalizeOrigin(origin: string): string {
  try {
    const url = new URL(origin);
    const port =
      (url.protocol === "http:" && url.port === "80") ||
      (url.protocol === "https:" && url.port === "443") ||
      (url.protocol === "ws:" && url.port === "80") ||
      (url.protocol === "wss:" && url.port === "443")
        ? ""
        : url.port;
    const proto =
      url.protocol === "ws:"
        ? "http:"
        : url.protocol === "wss:"
          ? "https:"
          : url.protocol;
    return `${proto}//${url.hostname}${port ? ":" + port : ""}`;
  } catch {
    return origin;
  }
}

/**
 * Reject a WebSocket upgrade when the request's Origin header does not match a
 * trusted origin. Prevents Cross-Site WebSocket Hijacking: a malicious page in
 * a victim's browser cannot open a WS to this backend because the browser
 * always sets the Origin header, and only known origins are accepted.
 *
 * Trusted origins:
 *   - Same-origin (Origin === Host) for browser requests through a reverse
 *     proxy (Host is set by the proxy, and must not be spoofable client-side)
 *   - Loopback socket connections without an Origin header (internal, nginx)
 *   - Local development origins (localhost:5173)
 *   - Electron file:// origin
 *   - Explicitly configured origins via CORS_ALLOWED_ORIGINS
 */
export function isAllowedWebSocketOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin;

  if (!origin) {
    // No Origin header - allow only if the socket is local (proxy, internal),
    // never for a remote socket, which would allow non-browser clients from
    // untrusted networks.
    return isSocketLocal(req);
  }

  const normalized = normalizeOrigin(origin);

  if (DEV_ORIGINS.has(normalized) || DEV_ORIGINS.has(origin)) {
    return true;
  }

  if (origin.startsWith(ELECTRON_FILE_ORIGIN)) {
    return true;
  }

  const configured = getConfiguredOrigins();
  if (configured.length > 0) {
    if (configured.includes("*")) {
      // We deliberately do not accept "*" for WS because the JWT is sent from
      // the browser via cookies (credentialed connection). Fail closed.
      return false;
    }
    if (
      configured.includes(origin) ||
      configured.some((o) => normalizeOrigin(o) === normalized)
    ) {
      return true;
    }
  }

  // Fallback: allow same-origin requests, computed strictly from the socket's
  // own Host header. We do NOT trust X-Forwarded-Host here because a request
  // that reaches this handler already succeeded HTTP upgrade routing; if a
  // reverse proxy is in place, configure CORS_ALLOWED_ORIGINS instead.
  const host = req.headers.host;
  if (host) {
    const sameOriginHttp = `http://${host}`;
    const sameOriginHttps = `https://${host}`;
    if (
      normalized === normalizeOrigin(sameOriginHttp) ||
      normalized === normalizeOrigin(sameOriginHttps)
    ) {
      return true;
    }
  }

  return false;
}

/**
 * verifyClient handler for `ws` WebSocketServer, rejecting requests whose
 * Origin is not permitted. Use when constructing a WebSocketServer.
 */
export function wsVerifyClient(info: {
  req: IncomingMessage;
  origin: string;
  secure: boolean;
}): boolean {
  return isAllowedWebSocketOrigin(info.req);
}
