import type { Request, Response } from "express";
import express from "express";
import { homepageLogger } from "../../utils/logger.js";
import { safeOutboundFetch } from "../../utils/safe-outbound-fetch.js";

export const homepageRssRouter = express.Router();

const rssCache = new Map<string, { data: RssItem[]; expires: number }>();
const CACHE_TTL_MS = 1000 * 60 * 15; // 15 minutes
const CACHE_SIZE = 50;
const FETCH_TIMEOUT_MS = 8000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB — RSS/Atom feeds don't need more

interface RssItem {
  title: string;
  link: string;
  pubDate: string | null;
  description: string | null;
}

async function fetchXml(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await safeOutboundFetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: { Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*" },
    });
    if (!res.ok) {
      throw new Error(`Upstream returned ${res.status}`);
    }
    const contentLength = Number(res.headers.get("content-length") || 0);
    if (contentLength > MAX_RESPONSE_BYTES) {
      throw new Error("Response too large");
    }
    const reader = res.body?.getReader();
    if (!reader) {
      return await res.text();
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw new Error("Response too large");
        }
        chunks.push(value);
      }
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf-8");
  } finally {
    clearTimeout(timer);
  }
}

function parseRss(xml: string): RssItem[] {
  const items: RssItem[] = [];
  const itemRegex = /<item[\s>]([\s\S]*?)<\/item>/gi;
  let match: RegExpExecArray | null;

  const getText = (tag: string, src: string): string | null => {
    const m = new RegExp(
      `<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`,
      "i",
    ).exec(src);
    if (!m) return null;
    return (m[1] ?? m[2]).trim();
  };

  const getLink = (src: string): string => {
    // Self-closing <link rel="alternate" href="..." /> (BBC style)
    const selfClose = /<link[^>]+href="([^"]+)"[^>]*\/?>/i.exec(src);
    if (selfClose) return sanitizeLink(selfClose[1]);
    // Plain text <link>url</link>
    return sanitizeLink(getText("link", src) ?? "");
  };

  // Only allow http(s) hrefs so a hostile feed can't inject javascript:/data: URLs
  // that would execute in the widget origin when clicked.
  const sanitizeLink = (raw: string): string => {
    const trimmed = raw.trim();
    if (!trimmed) return "";
    try {
      const url = new URL(trimmed);
      if (url.protocol === "http:" || url.protocol === "https:") {
        return url.toString();
      }
      return "";
    } catch {
      return "";
    }
  };

  while ((match = itemRegex.exec(xml)) !== null) {
    const src = match[1];
    items.push({
      title: getText("title", src) ?? "(no title)",
      link: getLink(src),
      pubDate: getText("pubDate", src) ?? getText("updated", src),
      description: getText("description", src) ?? getText("summary", src),
    });
    if (items.length >= 50) break;
  }

  // Atom feed fallback
  if (items.length === 0) {
    const entryRegex = /<entry[\s>]([\s\S]*?)<\/entry>/gi;
    while ((match = entryRegex.exec(xml)) !== null) {
      const src = match[1];
      const linkMatch = /<link[^>]+href="([^"]+)"/.exec(src);
      items.push({
        title: getText("title", src) ?? "(no title)",
        link: sanitizeLink(linkMatch?.[1] ?? ""),
        pubDate: getText("published", src) ?? getText("updated", src),
        description: getText("summary", src) ?? getText("content", src),
      });
      if (items.length >= 50) break;
    }
  }

  return items;
}

/**
 * @openapi
 * /homepage/rss:
 *   get:
 *     summary: Proxy and parse an RSS/Atom feed
 *     tags:
 *       - Homepage
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: max
 *         schema:
 *           type: integer
 *           default: 10
 *     responses:
 *       200:
 *         description: Array of feed items.
 *       400:
 *         description: Invalid or missing URL.
 *       500:
 *         description: Failed to fetch or parse the feed.
 */
homepageRssRouter.get("/", async (req: Request, res: Response) => {
  const feedUrl = req.query.url as string;
  const max = Math.min(50, Math.max(1, Number(req.query.max) || 10));

  if (!feedUrl) return res.status(400).json({ error: "url is required" });

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(feedUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return res.status(400).json({ error: "Only http(s) URLs are allowed" });
  }

  const cached = rssCache.get(feedUrl);
  if (cached && cached.expires > Date.now()) {
    return res.json(cached.data.slice(0, max));
  }

  try {
    const xml = await fetchXml(feedUrl);
    const items = parseRss(xml);

    if (rssCache.size >= CACHE_SIZE) {
      const oldest = rssCache.keys().next().value;
      if (oldest) rssCache.delete(oldest);
    }
    rssCache.set(feedUrl, { data: items, expires: Date.now() + CACHE_TTL_MS });

    res.json(items.slice(0, max));
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    homepageLogger.warn("Failed to fetch RSS feed", { feedUrl, msg });
    res.status(500).json({ error: "Failed to fetch feed" });
  }
});
