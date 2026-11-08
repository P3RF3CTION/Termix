/**
 * A relay to a host's SSH port, for another Termix server that manages this
 * one. It opens a WebSocket at /plugin-ws/core/ssh-relay with an API key
 * ticket, names a host, and the bytes of an SSH connection run through it.
 * This server reaches the host the way it always does, jump hosts, proxy and
 * port knocking included, so the other server never needs a route to it. The
 * SSH session itself stays between that server and the host.
 *
 * The caller needs connect access to the host, the same as for a session.
 */

import net from "node:net";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { promisify } from "node:util";
import { isIP, BlockList } from "node:net";
import type { Duplex } from "node:stream";
import { createWebSocketStream, type WebSocket } from "ws";
import type { PluginWebSocketConnection } from "@termix-ssh/plugin-sdk/backend";
import { resolveHostById, resolveHostBySyncId } from "./host-resolver.js";
import { openSshTransport } from "./connect/transport.js";
import type { MutableConnectConfig, SshConnectHost } from "./connect/types.js";
import { sshLogger } from "../utils/logger.js";
import { registerCoreWsRoute } from "../plugins/ws.js";

const MAX_RELAYS_PER_USER = 100;
const open = new Map<string, number>();

const dnsLookupAsync = promisify(dnsLookup);

// The relay is a raw-bytes tunnel; without checks a user who can add a host
// gets to speak arbitrary protocols to anything the Termix process can reach.
// Blocking loopback and the cloud-metadata address closes the most-dangerous
// cases (Termix's own admin endpoints and IMDS) without breaking legitimate
// RFC-1918 fleets that the user actually meant to manage. Operators who need
// loopback (e.g. a dev-mode nested Termix) can opt in via the env flag.
const relayBlockList = new BlockList();
relayBlockList.addSubnet("127.0.0.0", 8, "ipv4");
relayBlockList.addSubnet("::1", 128, "ipv6");
relayBlockList.addSubnet("::ffff:127.0.0.0", 104, "ipv6");
relayBlockList.addAddress("169.254.169.254", "ipv4");
relayBlockList.addAddress("::ffff:169.254.169.254", "ipv6");
// GCE metadata.
relayBlockList.addAddress("169.254.169.253", "ipv4");

async function isRelayDestinationAllowed(host: string): Promise<boolean> {
  if (process.env.TERMIX_ALLOW_SSH_RELAY_LOOPBACK === "true") return true;
  const literal = isIP(host);
  const addresses: LookupAddress[] = literal
    ? [{ address: host, family: literal }]
    : await dnsLookupAsync(host, { all: true, verbatim: true }).catch(
        () => [] as LookupAddress[],
      );
  if (addresses.length === 0) return false;
  for (const { address, family } of addresses) {
    if (relayBlockList.check(address, family === 6 ? "ipv6" : "ipv4")) {
      return false;
    }
  }
  return true;
}

function close(ws: WebSocket, code: number, reason: string): void {
  try {
    ws.close(code, reason);
  } catch {
    // Already closed.
  }
}

async function handleRelay(
  connection: PluginWebSocketConnection,
): Promise<void> {
  const ws = connection.socket as WebSocket;
  const url = String((connection.request as { url?: string }).url ?? "");
  const params = new URL(url, "http://relay").searchParams;
  const hostId = Number(params.get("hostId"));
  // A linked desktop knows its hosts by sync id, not by this server's id.
  const syncId = params.get("syncId");
  const userId = connection.userId;

  if (!userId || (!syncId && (!Number.isSafeInteger(hostId) || hostId <= 0))) {
    close(ws, 1008, "A host is required");
    return;
  }
  if ((open.get(userId) ?? 0) >= MAX_RELAYS_PER_USER) {
    close(ws, 1013, "Too many connections");
    return;
  }

  const host = syncId
    ? await resolveHostBySyncId(syncId, userId)
    : await resolveHostById(hostId, userId);
  if (!host) {
    close(ws, 1008, "Host not found or access denied");
    return;
  }

  open.set(userId, (open.get(userId) ?? 0) + 1);
  let stream: Duplex | null = null;
  let jumpEnd: (() => void) | null = null;
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    open.set(userId, Math.max(0, (open.get(userId) ?? 1) - 1));
    stream?.destroy();
    jumpEnd?.();
    close(ws, 1000, "Closed");
  };
  ws.once("close", finish);

  try {
    const sshHost = host as unknown as SshConnectHost;
    const config = {
      host: sshHost.ip,
      port: sshHost.port || 22,
    } as MutableConnectConfig;
    // Refuse before dialing a jump chain if the ultimate target resolves to
    // loopback or metadata; otherwise an authenticated user turns the relay
    // into an SSRF primitive against the Termix host itself.
    if (!(await isRelayDestinationAllowed(String(config.host)))) {
      sshLogger.warn("Relay refused: destination is restricted", {
        operation: "ssh_relay_blocked",
        host: String(config.host),
        hostId: syncId ? undefined : hostId,
        syncId,
        userId,
      });
      close(ws, 1008, "Destination not allowed");
      finish();
      return;
    }
    const { jumpClient } = await openSshTransport(sshHost, config);
    jumpEnd = () => jumpClient?.end();
    stream = (config.sock as Duplex | undefined) ?? null;
    if (!stream) {
      // Re-check after jump-host rewrites config.host; the chain could have
      // rewritten the final address to something private.
      if (!(await isRelayDestinationAllowed(String(config.host)))) {
        sshLogger.warn(
          "Relay refused after jump-host resolution: destination is restricted",
          {
            operation: "ssh_relay_blocked_post_jump",
            host: String(config.host),
            hostId: syncId ? undefined : hostId,
            syncId,
            userId,
          },
        );
        close(ws, 1008, "Destination not allowed");
        finish();
        return;
      }
      stream = net.connect({
        host: String(config.host),
        port: Number(config.port),
      });
    }
    const pipe = createWebSocketStream(ws);
    stream.once("error", finish);
    stream.once("close", finish);
    pipe.once("error", finish);
    stream.pipe(pipe);
    pipe.pipe(stream);
  } catch (error) {
    sshLogger.warn("A relay could not reach its host", {
      operation: "ssh_relay_open",
      hostId: syncId ? undefined : hostId,
      syncId,
      error: error instanceof Error ? error.message : String(error),
    });
    finish();
  }
}

let registered = false;

/** Mounts the relay once, for servers that other Termix servers manage. */
export function registerSshRelay(): void {
  if (registered) return;
  registered = true;
  registerCoreWsRoute("/ssh-relay", handleRelay);
}
