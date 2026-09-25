import type { RemoteDesktopLogger } from "./log.js";

/**
 * Server-side keepalive for Guacamole tunnels.
 *
 * guacamole-lite closes a tunnel when the browser has not sent anything for
 * `maxInactivityTime` (10 s by default), and guacd drops a user after 15 s
 * without input ("User is not responding."). Both rely on the client's
 * timer-driven pings, which browsers throttle heavily in background tabs
 * (Chrome: down to once per minute after 5 minutes hidden). Idle remote
 * desktop sessions in a background tab were therefore disconnected.
 *
 * Instead of trusting browser timers, liveness is checked with WebSocket
 * protocol-level ping/pong frames, which browsers answer natively and without
 * throttling. While the peer answers, guacamole-lite's activity timestamp is
 * refreshed and guacd receives a `nop`, so neither side times out. A peer that
 * misses a pong is terminated within two intervals.
 */

export const GUAC_KEEPALIVE_INTERVAL_MS = 5000;

const WS_OPEN = 1;
const NOP_INSTRUCTION = "3.nop;";

export interface KeepaliveWebSocket {
  readyState: number;
  ping(): void;
  terminate(): void;
  on(event: "pong" | "close", listener: () => void): unknown;
}

export interface KeepaliveClientConnection {
  webSocket?: KeepaliveWebSocket;
  lastActivity?: number;
  guacdClient?: { send(data: string, afterOpened?: boolean): void } | null;
}

/**
 * Attaches the keepalive to an opened guacamole-lite client connection.
 * Returns a function that stops the keepalive (also called automatically when
 * the WebSocket closes).
 */
export function attachGuacKeepalive(
  clientConnection: KeepaliveClientConnection,
  log?: Pick<RemoteDesktopLogger, "warn">,
  intervalMs: number = GUAC_KEEPALIVE_INTERVAL_MS,
): () => void {
  const ws = clientConnection.webSocket;
  if (!ws) return () => {};

  let alive = true;
  let timer: ReturnType<typeof setInterval> | null = null;

  const stop = () => {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };

  ws.on("pong", () => {
    alive = true;
    clientConnection.lastActivity = Date.now();
  });
  ws.on("close", stop);

  timer = setInterval(() => {
    if (ws.readyState !== WS_OPEN) {
      stop();
      return;
    }

    if (!alive) {
      stop();
      log?.warn("Guacamole client missed keepalive pong, terminating", {
        operation: "guac_keepalive_timeout",
      });
      ws.terminate();
      return;
    }

    alive = false;
    try {
      ws.ping();
    } catch {
      // socket is closing; the close handler stops the keepalive
    }
    try {
      clientConnection.guacdClient?.send(NOP_INSTRUCTION, true);
    } catch {
      // guacd connection is closing; guacamole-lite handles the teardown
    }
  }, intervalMs);

  // Do not keep the process alive just for the keepalive timer.
  (timer as { unref?: () => void }).unref?.();

  return stop;
}
