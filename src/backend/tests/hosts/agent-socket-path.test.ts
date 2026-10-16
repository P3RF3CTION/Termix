import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const fsState = vi.hoisted(() => ({
  existing: new Set<string>(),
  links: new Map<string, string>(),
}));

vi.mock("fs/promises", () => ({
  access: async (p: string) => {
    if (!fsState.existing.has(p)) throw new Error("ENOENT");
  },
  realpath: async (p: string) => fsState.links.get(p) ?? p,
}));

import {
  isAllowedAgentSocketPath,
  resolveAgentSocket,
} from "../../hosts/terminal-auth-helpers.js";

const env = { ...process.env };

beforeEach(() => {
  fsState.existing.clear();
  fsState.links.clear();
  process.env.HOME = "/home/termix";
  delete process.env.SSH_AUTH_SOCK;
  delete process.env.TERMIX_AGENT_SOCKET_ALLOWLIST;
});

afterEach(() => {
  process.env = { ...env };
});

const withSocket = (agentSocketPath: string) =>
  resolveAgentSocket({ agentSocketPath } as never);

describe.skipIf(process.platform === "win32")("agent socket path", () => {
  it("refuses docker.sock and other non-agent sockets", async () => {
    fsState.existing.add("/var/run/docker.sock");
    expect(isAllowedAgentSocketPath("/var/run/docker.sock")).toBe(false);
    expect(await withSocket("/var/run/docker.sock")).toHaveProperty("error");
  });

  it("allows the usual agent locations and the Termix user's ~/.ssh", async () => {
    for (const p of [
      "/tmp/ssh-abc/agent.123",
      "/run/user/1000/ssh-agent.socket",
      "/home/termix/.ssh/agent.sock",
    ]) {
      fsState.existing.add(p);
      expect(await withSocket(p)).toEqual({ socketPath: p });
    }
  });

  it("refuses traversal and relative paths", () => {
    expect(
      isAllowedAgentSocketPath("/tmp/ssh-x/../../var/run/docker.sock"),
    ).toBe(false);
    expect(isAllowedAgentSocketPath("tmp/ssh-x/agent")).toBe(false);
    expect(isAllowedAgentSocketPath("/home/other/.ssh/agent")).toBe(false);
  });

  it("follows symlinks before deciding", async () => {
    fsState.existing.add("/tmp/ssh-evil/agent");
    fsState.links.set("/tmp/ssh-evil/agent", "/var/run/docker.sock");
    expect(await withSocket("/tmp/ssh-evil/agent")).toHaveProperty("error");
  });

  it("accepts the server's own SSH_AUTH_SOCK wherever it lives", async () => {
    process.env.SSH_AUTH_SOCK = "/opt/1password/agent.sock";
    fsState.existing.add("/opt/1password/agent.sock");
    expect(await withSocket("/opt/1password/agent.sock")).toEqual({
      socketPath: "/opt/1password/agent.sock",
    });
  });

  it("accepts prefixes the operator lists", async () => {
    process.env.TERMIX_AGENT_SOCKET_ALLOWLIST = "/srv/agents/";
    fsState.existing.add("/srv/agents/a.sock");
    expect(await withSocket("/srv/agents/a.sock")).toEqual({
      socketPath: "/srv/agents/a.sock",
    });
  });
});
