import cors from "cors";
import type { Request, Response, NextFunction } from "express";
import { getRequestOrigin } from "./request-origin.js";
import { systemLogger } from "./logger.js";

const DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];
const ELECTRON_FILE_ORIGIN = "file://";

let wildcardCorsWarned = false;

function getAllowedOrigins(): string[] {
  const envOrigins = process.env.CORS_ALLOWED_ORIGINS;
  if (!envOrigins) return [];
  return envOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

function isLocalRequest(req: Request): boolean {
  const remoteAddr = req.socket?.remoteAddress || req.ip || "";
  const isLocalIP =
    remoteAddr === "127.0.0.1" ||
    remoteAddr === "::1" ||
    remoteAddr === "::ffff:127.0.0.1";

  if (!isLocalIP) return false;

  // If there's an Origin header, require it to also look local.
  // This prevents browsers running at a public origin from being treated as
  // trusted just because the request transits a local proxy that resolves to
  // 127.0.0.1.
  const origin = req.headers.origin;
  if (origin) {
    return (
      origin === "null" ||
      origin.startsWith("http://localhost") ||
      origin.startsWith("http://127.0.0.1") ||
      origin.startsWith("http://[::1]") ||
      origin.startsWith("https://localhost") ||
      origin.startsWith("https://127.0.0.1") ||
      origin.startsWith(ELECTRON_FILE_ORIGIN)
    );
  }

  return true;
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
        // No origin = same-origin or non-browser request (curl, internal service calls)
        if (!origin) return callback(null, true);

        // Requests coming from localhost (nginx proxy, internal service calls)
        if (isLocalRequest(req)) return callback(null, true);

        if (DEV_ORIGINS.includes(origin)) return callback(null, true);
        if (origin.startsWith(ELECTRON_FILE_ORIGIN))
          return callback(null, true);

        const configured = getAllowedOrigins();

        // Wildcard CORS is incompatible with credentials: true. Refuse to
        // honor a configured wildcard rather than silently leaking
        // credentials to arbitrary origins.
        if (configured.includes("*")) {
          if (!wildcardCorsWarned) {
            wildcardCorsWarned = true;
            systemLogger.error(
              "CORS_ALLOWED_ORIGINS contains '*' but credentials are enabled. Wildcard origins are ignored. Configure explicit origins instead.",
              {
                operation: "cors_wildcard_rejected",
              },
            );
          }
        }

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
