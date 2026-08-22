import cors from "cors";
import type { Request, Response, NextFunction } from "express";
import { getRequestOrigin } from "./request-origin.js";

const DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];
const ELECTRON_FILE_ORIGIN = "file://";

function getAllowedOrigins(): string[] {
  const envOrigins = process.env.CORS_ALLOWED_ORIGINS;
  if (!envOrigins) return [];
  return envOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

// True only if the *direct* TCP peer is loopback and there is no forwarded-for
// chain — a request coming through a reverse proxy still terminates on
// loopback, so `req.socket.remoteAddress` alone is not proof of trust.
function isDirectLoopbackRequest(req: Request): boolean {
  const remoteAddr = req.socket?.remoteAddress || "";
  const isLoopback =
    remoteAddr === "127.0.0.1" ||
    remoteAddr === "::1" ||
    remoteAddr === "::ffff:127.0.0.1";
  if (!isLoopback) return false;
  const forwarded =
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    req.headers["forwarded"];
  return !forwarded;
}

function isElectronAppRequest(req: Request): boolean {
  const header = req.headers["x-electron-app"];
  if (Array.isArray(header)) {
    return header.some((v) => typeof v === "string" && v.toLowerCase() === "true");
  }
  return typeof header === "string" && header.toLowerCase() === "true";
}

export function createCorsMiddleware(
  methods: string[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  extraHeaders: string[] = [],
) {
  const allowedHeaders = [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
    "User-Agent",
    "X-Electron-App",
    "X-Termix-Device-ID",
    "Cache-Control",
    "x-admin-target-user",
    ...extraHeaders,
  ];

  return (req: Request, res: Response, next: NextFunction) => {
    const handler = cors({
      origin: (origin, callback) => {
        // No origin = same-origin or non-browser request (curl, internal service calls)
        if (!origin) return callback(null, true);

        // Requests from a direct-loopback client with no forwarded-for chain
        // (nginx sidecar bug, internal service calls). Not merely
        // "req.socket is loopback" — the reverse proxy always looks loopback.
        if (isDirectLoopbackRequest(req)) return callback(null, true);

        if (DEV_ORIGINS.includes(origin)) return callback(null, true);

        // Electron renderer loads via file://. Only accept file:// when the
        // request carries the bundled app's X-Electron-App marker; otherwise
        // any other local file-scheme app could piggyback with credentials.
        if (
          origin.startsWith(ELECTRON_FILE_ORIGIN) &&
          isElectronAppRequest(req)
        ) {
          return callback(null, true);
        }

        const configured = getAllowedOrigins();
        // A wildcard entry may only be honoured when credentials are OFF,
        // which we cannot signal per-request via the `cors` module while
        // credentials:true is set globally. Refuse `*` here so no browser
        // ever receives Access-Control-Allow-Origin:* with credentials.
        if (configured.includes(origin)) return callback(null, true);

        const sameOrigin = getRequestOrigin(req);
        if (origin === sameOrigin) return callback(null, true);

        callback(new Error("Not allowed by CORS"));
      },
      credentials: true,
      methods,
      allowedHeaders,
    });
    handler(req, res, next);
  };
}
