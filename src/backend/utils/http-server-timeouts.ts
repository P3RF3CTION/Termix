import type { Server as HttpServer } from "http";
import type { Server as HttpsServer } from "https";

/**
 * Node's HTTP server ships with `requestTimeout = 0` and a five-minute
 * `headersTimeout` by default, which lets a Slowloris-style client hold a
 * socket open indefinitely by trickling bytes. Combined with the body
 * parsers that run before authentication, that is enough to pin memory and
 * file descriptors without ever authenticating.
 *
 * These values are picked to be generous for real clients (a long chunked
 * upload still completes, terminal WebSocket upgrades still succeed) while
 * cutting off requests that never advance.
 */
export function applyServerTimeouts(server: HttpServer | HttpsServer): void {
  // The whole request (headers + body) must arrive within this window. 0 =
  // no cap. Uploads that need longer talk to a dedicated streaming route
  // that clears this on its own socket.
  server.requestTimeout = 5 * 60 * 1000;

  // Headers alone must arrive within this. A well-behaved client sends its
  // request line and headers in one TCP window; anything slower is a stall.
  server.headersTimeout = 30 * 1000;

  // Idle keep-alive sockets held open beyond this are recycled.
  server.keepAliveTimeout = 30 * 1000;
}
