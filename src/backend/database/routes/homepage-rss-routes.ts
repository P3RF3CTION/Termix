import express, { type Request, type Response } from "express";
import { homepageLogger } from "../../utils/logger.js";
import { safeOutboundFetch } from "../../utils/safe-outbound-fetch.js";

export const homepageRssRouter = express.Router();

const rssCache = new Map<string, { data: RssItem[]; expires: number }>();
const CACHE_TTL_MS = 1000 * 60 * 15; // 15 minutes
const CACHE_SIZE = 50;
const FETCH_TIMEOUT_MS = 8000;
// Response size cap. The timeout only bounds elapsed time, not throughput, so
// a hostile feed can stream multi-MB and then feed the regex engine (which is
// quadratic in the input length on this parser). 2 MiB is already far more
// than any legitimate RSS/Atom feed.
const MAX_FEED_BYTES = 2 * 1024 * 1024;

interface RssItem {
  title: string;
  link: string;
  pubDate: string | null;
  description: string | null;
}

function fetchXml(url: string): Promise<string> {
  return safeOutboundFetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  }).then(async (res) => {
    if (!res.ok) throw new Error(`RSS fetch failed: ${res.status}`);
    return readCappedResponseText(res, MAX_FEED_BYTES);
  });
}

async function readCappedResponseText(
  response: globalThis.Response,
  maxBytes: number,
): Promise<string> {
  const body = response.body;
  if (!body) {
    try {
      return await response.text();
    } catch {
      return "";
    }
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    while (received < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const remaining = maxBytes - received;
      if (value.byteLength > remaining) {
        chunks.push(value.subarray(0, remaining));
        received += remaining;
        break;
      }
      chunks.push(value);
      received += value.byteLength;
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* */
    }
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
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
    if (selfClose) return selfClose[1];
    // Plain text <link>url</link>
    return getText("link", src) ?? "";
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
        link: linkMatch?.[1] ?? "",
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

  try {
    new URL(feedUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
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
    homepageLogger.warn("Failed to fetch RSS feed", { feedUrl });
    res.status(500).json({ error: "Failed to fetch feed" });
  }
});
