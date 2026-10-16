import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthManager } from "../../../utils/auth-manager.js";

const state = vi.hoisted(() => ({
  settings: new Map<string, string>(),
  users: new Map<
    string,
    { id: string; username: string; isExternal: boolean }
  >(),
  logged: [] as string[],
}));

vi.mock("../../../database/repositories/factory.js", () => ({
  createCurrentSettingsRepository: () => ({
    get: async (key: string) => state.settings.get(key) ?? null,
    set: async (key: string, value: string) => {
      state.settings.set(key, value);
    },
    delete: async (key: string) => {
      state.settings.delete(key);
    },
    getBoolean: async (_key: string, fallback: boolean) => fallback,
  }),
  createCurrentUserRepository: () => ({
    findByUsername: async (username: string) =>
      state.users.get(username) ?? null,
    update: async () => ({}),
  }),
}));

vi.mock("../../../utils/logger.js", () => {
  const log = (msg: unknown) => {
    state.logged.push(String(msg));
  };
  return {
    authLogger: { info: log, warn: log, error: log, success: log },
  };
});

vi.mock("../../../plugins/events.js", () => ({
  pluginEvents: { emit: vi.fn() },
  TOPICS: { userDataWiped: "user.data_wiped" },
}));

vi.mock("../../../auth/second-factor-admin.js", () => ({
  resetUserSecondFactors: async () => [],
}));

// The client IP decides one of the two limits; take it from the header the
// test sets instead of the loopback address every supertest request has.
vi.mock("../../../utils/request-origin.js", () => ({
  getClientIp: (req: { headers: Record<string, string | undefined> }) =>
    req.headers["x-forwarded-for"] ?? "local",
}));

import { registerUserPasswordResetRoutes } from "../../../database/routes/user-password-reset-routes.js";

function app() {
  const a = express();
  a.use(express.json());
  const router = express.Router();
  registerUserPasswordResetRoutes(router, {
    authManager: {
      isUserUnlocked: () => true,
      logoutUser: vi.fn(async () => {}),
    } as unknown as AuthManager,
  });
  a.use("/users", router);
  return a;
}

/** The code is only ever shown in the log, so the tests read it from there. */
function loggedCode(): string {
  const line = state.logged.find((l) =>
    l.startsWith("Password reset code generated"),
  );
  const match = line?.match(/: (\d{6}) /);
  if (!match) throw new Error("no code logged");
  return match[1];
}

let ipCounter = 0;
function fromNewIp(req: request.Test): request.Test {
  ipCounter += 1;
  return req.set("X-Forwarded-For", `198.51.100.${ipCounter % 250}`);
}

beforeEach(() => {
  state.settings.clear();
  state.users.clear();
  state.logged = [];
  state.users.set("alice", { id: "u1", username: "alice", isExternal: false });
  state.users.set("carol", { id: "u3", username: "carol", isExternal: false });
});

describe("password reset flow", () => {
  it("answers the same for existing and unknown accounts", async () => {
    const known = await fromNewIp(
      request(app()).post("/users/initiate-reset"),
    ).send({ username: "alice" });
    const unknown = await fromNewIp(
      request(app()).post("/users/initiate-reset"),
    ).send({ username: "nobody-here" });
    expect(known.status).toBe(200);
    expect(unknown.status).toBe(200);
    expect(known.body).toEqual(unknown.body);
    expect(state.logged.join("\n")).not.toContain("nobody-here");
  });

  it("stores only a digest of the code, never the code itself", async () => {
    await fromNewIp(request(app()).post("/users/initiate-reset")).send({
      username: "alice",
    });
    const stored = state.settings.get("reset_code_alice") ?? "";
    expect(stored).not.toContain(loggedCode());
    expect(JSON.parse(stored)).toHaveProperty("codeHash");
    expect(JSON.parse(stored)).not.toHaveProperty("code");
  });

  it("redeems a code once and the temporary token once", async () => {
    const a = app();
    await fromNewIp(request(a).post("/users/initiate-reset")).send({
      username: "alice",
    });
    const code = loggedCode();

    const first = await request(a)
      .post("/users/verify-reset-code")
      .send({ username: "alice", resetCode: code });
    expect(first.status).toBe(200);
    expect(typeof first.body.tempToken).toBe("string");
    expect(state.settings.get("temp_reset_token_alice")).not.toContain(
      first.body.tempToken,
    );

    const again = await request(a)
      .post("/users/verify-reset-code")
      .send({ username: "alice", resetCode: code });
    expect(again.status).toBe(400);

    const wrongToken = await request(a).post("/users/complete-reset").send({
      username: "alice",
      tempToken: "not-the-token",
      newPassword: "a-new-password",
    });
    expect(wrongToken.status).toBe(400);

    const done = await request(a).post("/users/complete-reset").send({
      username: "alice",
      tempToken: first.body.tempToken,
      newPassword: "a-new-password",
    });
    expect(done.status).toBe(200);
    expect(state.settings.has("temp_reset_token_alice")).toBe(false);
  });

  it("limits repeated reset requests for one account", async () => {
    const a = app();
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      const res = await fromNewIp(
        request(a).post("/users/initiate-reset"),
      ).send({ username: "carol" });
      statuses.push(res.status);
    }
    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(statuses.at(-1)).toBe(429);
  });
});
