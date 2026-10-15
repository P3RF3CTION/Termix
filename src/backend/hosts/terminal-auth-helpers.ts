import dgram from "dgram";
import net from "net";
import ssh2Pkg, {
  type BaseAgent as BaseAgentType,
  type GetStreamCallback,
  type IdentityCallback,
  type KnownPublicKeys,
  type ParsedKey,
  type SignCallback,
  type SigningRequestOptions,
} from "ssh2";

type KnownPublicKey = KnownPublicKeys[number];

const { AgentProtocol, BaseAgent } = ssh2Pkg;
const DEFAULT_PORT_KNOCK_TIMEOUT_MS = 1000;

type Sleep = (ms: number) => Promise<void>;

type PortKnockingOptions = {
  tcpTimeoutMs?: number;
  udpTimeoutMs?: number;
  createTcpSocket?: () => net.Socket;
  createUdpSocket?: () => dgram.Socket;
  wait?: Sleep;
};

const sleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class MemoryAgent extends BaseAgent {
  private key: ParsedKey;

  constructor(key: ParsedKey) {
    super();
    this.key = key;
  }

  getIdentities(cb: IdentityCallback<ParsedKey>): void {
    cb(null, [this.key]);
  }

  getStream(cb: GetStreamCallback): void {
    const protocol = new AgentProtocol(false);

    protocol.on("identities", (request) => {
      protocol.getIdentitiesReply(request, [this.key]);
    });

    protocol.on("sign", (request, publicKey, data, options) => {
      this.sign(publicKey, data, options, (error, signature) => {
        if (error || !signature) return protocol.failureReply(request);
        protocol.signReply(request, signature);
      });
    });

    cb(null, protocol);
  }

  sign(
    _pubKey: ParsedKey | Buffer | string,
    data: Buffer,
    optionsOrCb: SigningRequestOptions | SignCallback,
    cb?: SignCallback,
  ): void {
    const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb!;
    const options = typeof optionsOrCb === "function" ? {} : optionsOrCb;
    try {
      const algo =
        options.hash === "sha256"
          ? "rsa-sha2-256"
          : options.hash === "sha512"
            ? "rsa-sha2-512"
            : undefined;
      const signature = this.key.sign(data, algo);
      callback(null, signature);
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
    }
  }
}

/**
 * Decide whether a user-supplied agentSocketPath is safe to open as an SSH
 * agent.
 *
 * ssh2 speaks the SSH-agent wire protocol over any UNIX socket we hand it,
 * so letting an authenticated Termix user name `/var/run/docker.sock`,
 * `/run/user/0/bus`, or any other unix socket on the backend host would let
 * them probe and send request bytes to those sockets as whichever user
 * Termix runs as. On Windows the equivalent concern is arbitrary named
 * pipes.
 *
 * The allowlist mirrors what a user can legitimately point to: a socket in
 * their home SSH directory, the standard per-user runtime socket, a
 * Windows SSH-agent named pipe, or an environment-provided path. Anything
 * else is refused regardless of whether it looks like a valid file.
 */
function isAllowedAgentSocket(resolved: string): boolean {
  if (process.platform === "win32") {
    // Only the standard Windows OpenSSH agent pipe or an operator-provided one.
    const envPipe = process.env.SSH_AUTH_SOCK;
    const normalized = resolved.replace(/\//g, "\\");
    if (envPipe && normalized === envPipe) return true;
    return (
      /^\\\\\.\\pipe\\openssh-ssh-agent$/i.test(normalized) ||
      /^\\\\\.\\pipe\\ssh-agent(?:-\d+)?$/i.test(normalized)
    );
  }

  const envSock = process.env.SSH_AUTH_SOCK;
  if (envSock && resolved === envSock) return true;

  // Must be an absolute path with no traversal.
  if (!resolved.startsWith("/")) return false;
  if (resolved.includes("\0")) return false;
  if (resolved.split("/").some((segment) => segment === "..")) {
    return false;
  }

  const prefixes = [
    "/tmp/ssh-",
    "/private/tmp/ssh-",
    "/run/user/",
    "/var/run/ssh-",
  ];
  if (prefixes.some((p) => resolved.startsWith(p))) return true;

  // Any ssh-agent socket inside a user's ~/.ssh directory. Only HOME is
  // trusted here; letting the caller name an arbitrary /home/<user>/.ssh
  // path would open any other local account's agent.
  const home = process.env.HOME;
  if (home) {
    const dotSsh = `${home.replace(/\/+$/, "")}/.ssh/`;
    if (resolved.startsWith(dotSsh)) return true;
  }

  return false;
}

export async function resolveAgentSocket(
  terminalConfig: Record<string, unknown> | undefined,
): Promise<{ socketPath: string } | { error: string }> {
  const explicit = (
    terminalConfig?.agentSocketPath as string | undefined
  )?.trim();
  const resolved = explicit || process.env.SSH_AUTH_SOCK;

  if (!resolved) {
    return {
      error: "SSH_AUTH_SOCK is not set and no socket path was provided.",
    };
  }

  if (explicit && !isAllowedAgentSocket(explicit)) {
    return {
      error:
        "Agent socket path is not allowed. Use the server's SSH_AUTH_SOCK, a socket under /run/user/<uid>/, /tmp/ssh-*/, or inside the Termix user's ~/.ssh/.",
    };
  }

  if (process.platform !== "win32") {
    const { access } = await import("fs/promises");
    try {
      await access(resolved);
    } catch {
      return {
        error: `SSH agent socket not found at ${resolved}. Make sure your agent is running.`,
      };
    }
  }

  return { socketPath: resolved };
}

/**
 * Wraps an agent so only identities matching a specific public key are
 * offered to the server, mirroring ssh_config's IdentityFile + IdentitiesOnly
 * for agent auth. Prevents exhausting the server's MaxAuthTries when the
 * agent holds many keys.
 */
export class FilteredAgent extends BaseAgent {
  private inner: BaseAgentType;
  private publicKeyBlob: Buffer;

  constructor(inner: BaseAgentType, publicKeyBlob: Buffer) {
    super();
    this.inner = inner;
    this.publicKeyBlob = publicKeyBlob;
  }

  private matches(key: KnownPublicKey): boolean {
    try {
      const blob =
        typeof key === "string"
          ? Buffer.from(key)
          : Buffer.isBuffer(key)
            ? key
            : "getPublicSSH" in key
              ? key.getPublicSSH()
              : null;
      return (
        Buffer.isBuffer(blob) && Buffer.compare(blob, this.publicKeyBlob) === 0
      );
    } catch {
      return false;
    }
  }

  getIdentities(cb: IdentityCallback): void {
    this.inner.getIdentities((err, keys) => {
      if (err || !keys) return cb(err, keys);
      cb(
        null,
        keys.filter((key) => this.matches(key)),
      );
    });
  }

  getStream(cb: GetStreamCallback): void {
    if (typeof this.inner.getStream !== "function") {
      return cb(new Error("Agent does not support forwarding."));
    }
    this.inner.getStream(cb);
  }

  sign(
    pubKey: ParsedKey | Buffer | string,
    data: Buffer,
    optionsOrCb: SigningRequestOptions | SignCallback,
    cb?: SignCallback,
  ): void {
    this.inner.sign(
      pubKey,
      data,
      optionsOrCb as SigningRequestOptions,
      cb as SignCallback,
    );
  }
}

function parseAgentIdentityBlob(agentIdentity: string): Buffer | null {
  const { utils } = ssh2Pkg;
  const parsed = utils.parseKey(agentIdentity.trim());
  if (parsed instanceof Error || !parsed) return null;
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  try {
    return key.getPublicSSH();
  } catch {
    return null;
  }
}

export async function applyAgentAuth(
  connectConfig: Record<string, unknown>,
  terminalConfig: Record<string, unknown> | undefined,
): Promise<{ socketPath: string } | { error: string }> {
  const result = await resolveAgentSocket(terminalConfig);
  if ("error" in result) return result;

  const { createAgent } = ssh2Pkg;
  const agent = createAgent(result.socketPath);

  const agentIdentity = (
    terminalConfig?.agentIdentity as string | undefined
  )?.trim();
  if (agentIdentity) {
    const publicKeyBlob = parseAgentIdentityBlob(agentIdentity);
    if (!publicKeyBlob) {
      return { error: "Invalid public key provided for agent identity." };
    }
    connectConfig.agent = new FilteredAgent(agent, publicKeyBlob);
  } else {
    connectConfig.agent = agent;
  }

  return result;
}

export async function performPortKnocking(
  host: string,
  sequence: Array<{ port: number; protocol?: string; delay?: number }>,
  options: PortKnockingOptions = {},
): Promise<void> {
  const createTcpSocket = options.createTcpSocket ?? (() => new net.Socket());
  const createUdpSocket =
    options.createUdpSocket ?? (() => dgram.createSocket("udp4"));
  const wait = options.wait ?? sleep;
  const tcpTimeoutMs = options.tcpTimeoutMs ?? DEFAULT_PORT_KNOCK_TIMEOUT_MS;
  const udpTimeoutMs = options.udpTimeoutMs ?? DEFAULT_PORT_KNOCK_TIMEOUT_MS;

  for (const knock of sequence) {
    const port = Number(knock.port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) continue;

    const protocol = (knock.protocol || "tcp").toLowerCase();
    const delay = Number(knock.delay ?? 100);

    await new Promise<void>((resolve) => {
      if (protocol === "udp") {
        const client = createUdpSocket();
        let settled = false;
        const timeout = setTimeout(() => finish(), udpTimeoutMs);
        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          client.close();
          resolve();
        };
        client.once("error", finish);
        client.send(Buffer.alloc(0), port, host, () => {
          finish();
        });
      } else {
        const socket = createTcpSocket();
        let settled = false;
        const timeout = setTimeout(() => finish(), tcpTimeoutMs);
        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          socket.removeAllListeners("connect");
          socket.removeAllListeners("error");
          socket.destroy();
          resolve();
        };
        socket.once("connect", finish);
        socket.once("error", finish);
        socket.connect(port, host);
      }
    });

    if (delay > 0) {
      await wait(delay);
    }
  }
}
