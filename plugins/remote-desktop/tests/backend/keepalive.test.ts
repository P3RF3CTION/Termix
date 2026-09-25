import { EventEmitter } from "events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { attachGuacKeepalive } from "../../src/backend/keepalive.js";

class FakeWebSocket extends EventEmitter {
  readyState = 1;
  ping = vi.fn();
  terminate = vi.fn(() => {
    this.readyState = 3;
    this.emit("close");
  });
}

function setup() {
  const ws = new FakeWebSocket();
  const send = vi.fn();
  const conn = {
    webSocket: ws,
    lastActivity: 0,
    guacdClient: { send },
  };
  return { ws, send, conn };
}

describe("attachGuacKeepalive", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("pings the browser and sends nop to guacd every interval", () => {
    const { ws, send, conn } = setup();
    attachGuacKeepalive(conn, undefined, 5000);

    vi.advanceTimersByTime(5000);
    expect(ws.ping).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith("3.nop;", true);
  });

  it("refreshes guacamole-lite activity on pong and keeps the tunnel open", () => {
    const { ws, conn } = setup();
    attachGuacKeepalive(conn, undefined, 5000);

    for (let i = 0; i < 20; i++) {
      vi.advanceTimersByTime(5000);
      vi.setSystemTime(Date.now());
      ws.emit("pong");
      expect(conn.lastActivity).toBe(Date.now());
    }
    expect(ws.terminate).not.toHaveBeenCalled();
  });

  it("terminates a client that misses a pong", () => {
    const { ws, conn } = setup();
    const log = { warn: vi.fn() };
    attachGuacKeepalive(conn, log, 5000);

    vi.advanceTimersByTime(5000);
    expect(ws.terminate).not.toHaveBeenCalled();
    vi.advanceTimersByTime(5000);
    expect(ws.terminate).toHaveBeenCalledTimes(1);
    expect(log.warn).toHaveBeenCalledWith(
      "Guacamole client missed keepalive pong, terminating",
      { operation: "guac_keepalive_timeout" },
    );
  });

  it("stops after the socket closes", () => {
    const { ws, send, conn } = setup();
    attachGuacKeepalive(conn, undefined, 5000);

    ws.readyState = 3;
    ws.emit("close");
    vi.advanceTimersByTime(20000);
    expect(ws.ping).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("is a no-op without a WebSocket", () => {
    expect(() => attachGuacKeepalive({}, undefined, 5000)()).not.toThrow();
  });
});
