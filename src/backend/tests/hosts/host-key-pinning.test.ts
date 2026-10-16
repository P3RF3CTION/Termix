import { EventEmitter } from "node:events";
import type { WebSocket } from "ws";
import { beforeEach, describe, expect, it, vi } from "vitest";

const repo = vi.hoisted(() => ({
  storeHostKey: vi.fn(async () => undefined),
  updateHostKey: vi.fn(async () => undefined),
  touchHostKeyLastVerified: vi.fn(async () => undefined),
  findHostKeyVerificationData: vi.fn(),
}));

vi.mock("../../database/repositories/factory.js", () => ({
  createCurrentHostResolutionRepository: () => repo,
}));
vi.mock("../../utils/logger.js", () => ({
  sshLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("../../plugins/events.js", () => ({
  pluginEvents: { emit: vi.fn() },
  TOPICS: { hostKeyUpdated: "host-key-updated" },
}));

import { SSHHostKeyVerifier } from "../../hosts/host-key-verifier.js";

type Preloaded = Awaited<ReturnType<typeof SSHHostKeyVerifier.preloadHostData>>;

function hostRow(fingerprint: string | null): Preloaded {
  return {
    hostKeyFingerprint: fingerprint,
    hostKeyType: fingerprint ? "ssh-ed25519" : null,
    hostKeyChangedCount: 0,
    name: "web-01",
  } as unknown as Preloaded;
}

function socketAnswering(action: "accept" | "reject") {
  const sent: string[] = [];
  const socket = new EventEmitter() as EventEmitter & {
    send: (data: string) => void;
  };
  socket.send = (data) => {
    sent.push(data);
    socket.emit(
      "message",
      Buffer.from(
        JSON.stringify({
          type: "host_key_verification_response",
          data: { action },
        }),
      ),
    );
  };
  return { socket: socket as unknown as WebSocket, sent };
}

async function verify(opts: {
  key: string;
  stored: string | null;
  ws?: WebSocket | null;
  jump?: boolean;
}) {
  const verifier = await SSHHostKeyVerifier.createHostVerifier(
    7,
    "10.0.0.7",
    22,
    opts.ws ?? null,
    "user-1",
    opts.jump ?? false,
    hostRow(opts.stored),
  );
  return new Promise<boolean>((resolve) =>
    verifier(Buffer.from(opts.key), resolve),
  );
}

const hex = (s: string) => Buffer.from(s).toString("hex");

beforeEach(() => {
  repo.storeHostKey.mockClear();
  repo.updateHostKey.mockClear();
});

describe("first contact without a socket (background connections)", () => {
  it("pins the key instead of accepting it unstored", async () => {
    expect(await verify({ key: "key-a", stored: null })).toBe(true);
    expect(repo.storeHostKey).toHaveBeenCalledTimes(1);
    expect(repo.storeHostKey.mock.calls[0][0]).toBe(7);
    expect(repo.storeHostKey.mock.calls[0][1]).toBe(hex("key-a"));
  });

  it("refuses a different key once the first one is pinned", async () => {
    expect(await verify({ key: "key-b", stored: hex("key-a") })).toBe(false);
    expect(repo.updateHostKey).not.toHaveBeenCalled();
  });
});

describe("jump hosts", () => {
  it("refuses a changed jump-host key when nobody can confirm it", async () => {
    expect(
      await verify({ key: "jump-new", stored: hex("jump-old"), jump: true }),
    ).toBe(false);
    expect(repo.updateHostKey).not.toHaveBeenCalled();
  });

  it("asks about a changed jump-host key and keeps the user's answer", async () => {
    const no = socketAnswering("reject");
    expect(
      await verify({
        key: "jump-new",
        stored: hex("jump-old"),
        jump: true,
        ws: no.socket,
      }),
    ).toBe(false);
    expect(no.sent[0]).toContain("host_key_changed");
    expect(repo.updateHostKey).not.toHaveBeenCalled();

    const yes = socketAnswering("accept");
    expect(
      await verify({
        key: "jump-new",
        stored: hex("jump-old"),
        jump: true,
        ws: yes.socket,
      }),
    ).toBe(true);
    expect(repo.updateHostKey).toHaveBeenCalledTimes(1);
  });

  it("still pins an unseen jump-host key on first contact", async () => {
    expect(await verify({ key: "jump-a", stored: null, jump: true })).toBe(
      true,
    );
    expect(repo.storeHostKey).toHaveBeenCalledTimes(1);
  });
});

describe("unchanged behaviour", () => {
  it("accepts the pinned key", async () => {
    expect(await verify({ key: "key-a", stored: hex("key-a") })).toBe(true);
  });
});
