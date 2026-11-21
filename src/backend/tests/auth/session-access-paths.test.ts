/**
 * Express matches routes without regard to case and with an optional
 * trailing slash, so the session path rules must see the same form or
 * `/users/API-KEYS/` would walk past the plugin-session block list.
 */

import { describe, expect, it, vi } from "vitest";

vi.mock("../../auth/registry.js", () => ({
  listSecondFactors: () => [{ pluginId: "keys" }],
}));

const { sessionAccessRefusal } = await import("../../auth/session-access.js");
const { canonicalRoutePath } = await import("../../utils/route-path.js");

const pluginSession = { pluginSession: true };

describe("session access path rules", () => {
  it.each([
    "/users/api-keys",
    "/users/API-KEYS",
    "/users/api-keys/",
    "/users/Api-Keys/mine",
    "/users/Change-Password",
    "/users/change-password/",
    "/users/admin/u1/SECOND-FACTORS",
    "/plugins/keys/passkey-steps/c1/options",
    "/plugins/keys/Passkey-Steps/c1/finish",
    "/plugin-api/KEYS/enroll",
  ])("refuses a plugin-minted session on %s", (path) => {
    expect(sessionAccessRefusal(pluginSession, path, "POST")).toMatchObject({
      code: "PLUGIN_SESSION_NOT_ALLOWED",
    });
  });

  it("still lets a plugin-minted session reach ordinary routes", () => {
    expect(sessionAccessRefusal(pluginSession, "/hosts/db/ssh", "GET")).toBe(
      null,
    );
  });

  it("canonicalises like Express matches", () => {
    expect(canonicalRoutePath("/Users/Login/")).toBe("/users/login");
    expect(canonicalRoutePath("/users/login?x=1")).toBe("/users/login");
    expect(canonicalRoutePath("/")).toBe("/");
    expect(canonicalRoutePath("")).toBe("/");
  });
});
