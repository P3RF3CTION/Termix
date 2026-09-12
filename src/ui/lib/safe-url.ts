/**
 * `href={untrusted}` and `src={untrusted}` are the two direct-to-code sinks
 * React does not protect. `noopener/noreferrer` does not close the hole:
 * clicking a `javascript:` URL runs the script in the parent origin,
 * with full access to `localStorage.jwt` and the session cookie's fetch
 * privileges. Widget links, dashboards, and RSS items are all remotely
 * or cross-user-controllable, so every `href={link.url}` must funnel
 * through this helper first.
 */

const SAFE_PROTOCOLS = new Set(["http:", "https:", "mailto:", "tel:"]);

/**
 * Returns the URL if its protocol is on a small allowlist; otherwise "".
 * A returned "" should be used to skip rendering the anchor -- do NOT fall
 * back to `#`, because `<a href="#">` still steals the current page's origin
 * on click.
 */
export function safeUrl(url: string | undefined | null): string {
  if (typeof url !== "string") return "";
  const trimmed = url.trim();
  if (!trimmed) return "";

  // Relative URLs (start with `/`, `./`, `../`, `#`, `?`) never carry a scheme,
  // so they cannot become javascript: URLs and are safe to pass through.
  if (
    trimmed.startsWith("/") ||
    trimmed.startsWith("./") ||
    trimmed.startsWith("../") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("?")
  ) {
    return trimmed;
  }

  try {
    const parsed = new URL(trimmed, "https://placeholder.invalid/");
    // If the URL constructor filled in the placeholder base, the caller
    // passed a relative URL that our prefix test missed. Return the
    // original relative form so navigation still works.
    if (parsed.origin === "https://placeholder.invalid") {
      return trimmed;
    }
    if (SAFE_PROTOCOLS.has(parsed.protocol)) {
      return trimmed;
    }
  } catch {
    // fall through
  }
  return "";
}

export function isSafeUrl(url: string | undefined | null): boolean {
  return safeUrl(url) !== "";
}
