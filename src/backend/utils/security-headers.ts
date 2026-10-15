import type { Request, Response, NextFunction } from "express";

/**
 * `frame-ancestors` is the only CSP directive that cannot be delivered through
 * a meta tag, and it is the one that matters most here: a framed Termix means
 * a framed live SSH terminal.
 *
 * The default is `'self'` because a framed live terminal is a clickjackable
 * surface and the JWT cookie's `SameSite=Lax` still ships on same-tab frame
 * navigations that follow a top-level click. Operators who deliberately embed
 * Termix elsewhere (a dashboard tile, the desktop app's remote-login iframe)
 * widen it through `FRAME_ANCESTORS` -- "'self'" for the common case, or
 * "'self' https://dash.example.com" for an embed on that host.
 *
 * `ELECTRON_EMBEDDED=true` disables the default so the desktop app can render
 * a remote Termix inside a `file://` iframe without a rebuild.
 */
function frameAncestors(): string {
  const configured = process.env.FRAME_ANCESTORS?.trim();
  if (configured) return configured;
  if (process.env.ELECTRON_EMBEDDED === "true") return "*";
  return "'self'";
}

export function createSecurityHeadersMiddleware() {
  return (_req: Request, res: Response, next: NextFunction) => {
    // nginx sets this for the static document, but every proxied API response
    // arrives without it because a location-level add_header replaces the
    // server-level one.
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

    const ancestors = frameAncestors();
    // Kept separately from frame-ancestors: X-Frame-Options is the fallback
    // for older UAs that don't parse CSP, and it only understands DENY /
    // SAMEORIGIN. Skip it when the operator has explicitly widened
    // frame-ancestors, since the two would contradict.
    if (ancestors === "'self'") {
      res.setHeader("X-Frame-Options", "SAMEORIGIN");
    }
    if (ancestors !== "*") {
      // `form-action` cannot be delivered via a meta tag either, and it stops
      // a form-based XSS from POSTing credentials off-site. `base-uri 'none'`
      // shuts down base-tag-hijacking DOM-XSS variants.
      res.setHeader(
        "Content-Security-Policy",
        `frame-ancestors ${ancestors}; base-uri 'none'; form-action 'self'`,
      );
    }

    next();
  };
}
