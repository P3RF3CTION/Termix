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
        // No origin = server-to-server or non-browser (curl, internal service calls).
        // Do NOT enable `credentials` for these — the CORS lib will still allow the
        // request without echoing Access-Control-Allow-Credentials, which is what
        // we want (browsers with `credentials:'include'` always send an Origin).
        if (!origin) return callback(null, true);

        if (DEV_ORIGINS.includes(origin)) return callback(null, true);
        if (origin.startsWith(ELECTRON_FILE_ORIGIN))
          return callback(null, true);

        const configured = getAllowedOrigins();
        // Never allow a wildcard with credentials — that would let any web origin
        // read authenticated responses. Treat "*" as "any origin present in list is fine",
        // but require the explicit-origin path for credentialed CORS.
        if (configured.includes(origin)) return callback(null, true);

        // Same-origin fallback: derive from a trusted PUBLIC_URL env var only.
        // Do NOT trust X-Forwarded-Host for security decisions (an attacker
        // controls it when the reverse proxy allows it through).
        const publicUrl = process.env.PUBLIC_URL;
        if (publicUrl && origin === publicUrl.replace(/\/+$/, "")) {
          return callback(null, true);
        }

        // Only fall back to the request-derived origin when no PUBLIC_URL is set
        // (dev deployments without a documented public URL). This still trusts
        // X-Forwarded-Host, so operators are strongly encouraged to set PUBLIC_URL.
        if (!publicUrl) {
          const sameOrigin = getRequestOrigin(req);
          if (origin === sameOrigin) return callback(null, true);
        }

        callback(new Error("Not allowed by CORS"));
      },
      credentials: true,
      methods,
      allowedHeaders,
    });
    handler(req, res, next);
  };
}
