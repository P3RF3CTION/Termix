import type { Request, Response } from "express";
import express from "express";
import { homepageLogger } from "../../utils/logger.js";
import { safeOutboundFetch } from "../../utils/safe-outbound-fetch.js";

export const homepagePingRouter = express.Router();

interface PingCacheEntry {
  ok: boolean;
  statusCode: number | null;
  latencyMs: number;
  expires: number;
}

const pingCache = new Map<string, PingCacheEntry>();
const CACHE_SIZE = 200;
const FETCH_TIMEOUT_MS = 5000;

async function pingUrl(
  url: string,
): Promise<{ ok: boolean; statusCode: number | null; latencyMs: number }> {
  const start = performance.now();

  const attempt = async (
    method: "HEAD" | "GET",
  ): Promise<{ statusCode: number | null; failed: boolean }> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await safeOutboundFetch(url, {
        method,
        signal: controller.signal,
      });
      // Discard body so the connection releases even on GET fallbacks
      try {
        await res.arrayBuffer();
      } catch {
        // ignore body-read errors — the status code is what we care about
      }
      return { statusCode: res.status, failed: false };
    } catch {
      return { statusCode: null, failed: true };
    } finally {
      clearTimeout(timer);
    }
  };

  const headResult = await attempt("HEAD");
  const finalResult =
    headResult.statusCode === 405 ? await attempt("GET") : headResult;

  const latencyMs = Math.round(performance.now() - start);
  const code = finalResult.statusCode;
  return {
    ok: code !== null && code < 400,
    statusCode: code,
    latencyMs,
  };
}

/**
 * @openapi
 * /homepage/ping:
 *   get:
 *     summary: Check the HTTP reachability and latency of a URL
 *     tags:
 *       - Homepage
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: ttl
 *         schema:
 *           type: integer
 *           description: Cache TTL in seconds (min 10)
 *     responses:
 *       200:
 *         description: Ping result with ok, statusCode and latencyMs.
 *       400:
 *         description: Invalid or missing URL.
 */
homepagePingRouter.get("/", async (req: Request, res: Response) => {
  let targetUrl = req.query.url as string;
  const ttl = Math.max(10, Number(req.query.ttl) || 30) * 1000;

  if (!targetUrl) return res.status(400).json({ error: "url is required" });
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = `https://${targetUrl}`;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return res.status(400).json({ error: "Only http(s) URLs are allowed" });
  }

  const cached = pingCache.get(targetUrl);
  if (cached && cached.expires > Date.now()) {
    return res.json({
      ok: cached.ok,
      statusCode: cached.statusCode,
      latencyMs: cached.latencyMs,
    });
  }

  try {
    const result = await pingUrl(targetUrl);
    if (pingCache.size >= CACHE_SIZE) {
      const oldest = pingCache.keys().next().value;
      if (oldest) pingCache.delete(oldest);
    }
    pingCache.set(targetUrl, { ...result, expires: Date.now() + ttl });
    res.json(result);
  } catch (err) {
    homepageLogger.warn("Ping failed", { targetUrl });
    res.status(500).json({ error: "Ping failed" });
  }
});
