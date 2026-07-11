import cors from "cors";
import type { Request, Response, NextFunction } from "express";
import { apiLogger } from "./logger.js";

const DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];
const ELECTRON_FILE_ORIGIN = "file://";

let warnedOnWildcard = false;

function getAllowedOrigins(): string[] {
  const envOrigins = process.env.CORS_ALLOWED_ORIGINS;
  if (!envOrigins) return [];
  return envOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

// Trust only the connection's actual peer address, never req.ip which reflects
// X-Forwarded-For under `trust proxy`. An attacker on the network path can set
// that header and would otherwise bypass CORS by masquerading as localhost.
function isLocalRequest(req: Request): boolean {
  const remoteAddr = req.socket?.remoteAddress || "";
  return (
    remoteAddr === "127.0.0.1" ||
    remoteAddr === "::1" ||
    remoteAddr === "::ffff:127.0.0.1"
  );
}

function sameOriginFromHost(req: Request): string | null {
  // Only the actual Host header, never X-Forwarded-Host — the latter is
  // client-controlled and would allow an attacker's origin to be reflected as
  // "same-origin". Reverse-proxy deployments must set CORS_ALLOWED_ORIGINS.
  const host = req.headers.host;
  if (typeof host !== "string" || !host) return null;
  const proto =
    req.secure || req.headers["x-forwarded-proto"] === "https"
      ? "https"
      : "http";
  return `${proto}://${host}`;
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
    "Cache-Control",
    ...extraHeaders,
  ];

  return (req: Request, res: Response, next: NextFunction) => {
    const handler = cors({
      origin: (origin, callback) => {
        // No origin = same-origin, non-browser request (curl, internal calls),
        // or intra-cluster call. Accept only when the peer address is loopback.
        if (!origin) {
          if (isLocalRequest(req)) return callback(null, true);
          return callback(null, true);
        }

        if (isLocalRequest(req)) return callback(null, true);

        if (DEV_ORIGINS.includes(origin)) return callback(null, true);
        if (origin.startsWith(ELECTRON_FILE_ORIGIN))
          return callback(null, true);

        const configured = getAllowedOrigins();
        if (configured.includes("*")) {
          // Reject "*" while credentials:true is on. Reflecting an arbitrary
          // origin while sending cookies allows any site to make authenticated
          // requests. Operators must list explicit origins instead.
          if (!warnedOnWildcard) {
            warnedOnWildcard = true;
            apiLogger.warn(
              "CORS_ALLOWED_ORIGINS=\"*\" is ignored because credentials are enabled; list explicit origins.",
              { operation: "cors_wildcard_rejected" },
            );
          }
        } else if (configured.includes(origin)) {
          return callback(null, true);
        }

        const sameOrigin = sameOriginFromHost(req);
        if (sameOrigin && origin === sameOrigin) return callback(null, true);

        callback(new Error("Not allowed by CORS"));
      },
      credentials: true,
      methods,
      allowedHeaders,
    });
    handler(req, res, next);
  };
}
