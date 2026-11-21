/**
 * A delegated user manager may only change accounts that hold nothing the
 * manager lacks, or a password reset on a more privileged user is a way up.
 */

import { describe, expect, it, vi } from "vitest";

const perms = vi.hoisted(
  () =>
    ({
      admin: ["*"],
      helpdesk: ["admin.users.manage", "admin.sessions.manage"],
      plain: ["hosts.view"],
      pluginAdmin: ["admin.plugins.manage"],
      peer: ["admin.users.manage"],
    }) as Record<string, string[]>,
);

vi.mock("../../utils/permission-manager.js", () => ({
  PermissionManager: {
    getInstance: () => ({
      isAdmin: async (id: string) => id === "admin",
      getUserPermissions: async (id: string) => perms[id] ?? [],
      hasPermission: async (id: string, permission: string) =>
        (perms[id] ?? []).includes("*") ||
        (perms[id] ?? []).includes(permission),
    }),
  },
}));

const { canManageAccount, SESSIONS_MANAGE } =
  await import("../../auth/user-admin-access.js");

describe("canManageAccount", () => {
  it("lets admins change anyone and nobody else change an admin", async () => {
    expect(await canManageAccount("admin", { id: "peer", isAdmin: true })).toBe(
      true,
    );
    expect(
      await canManageAccount("helpdesk", { id: "admin", isAdmin: true }),
    ).toBe(false);
  });

  it("lets a user manager change an account with fewer permissions", async () => {
    expect(
      await canManageAccount("helpdesk", { id: "plain", isAdmin: false }),
    ).toBe(true);
    expect(
      await canManageAccount("helpdesk", { id: "peer", isAdmin: false }),
    ).toBe(true);
  });

  it("refuses an account holding a permission the manager lacks", async () => {
    expect(
      await canManageAccount("helpdesk", { id: "pluginAdmin", isAdmin: false }),
    ).toBe(false);
    expect(await canManageAccount("helpdesk", { isAdmin: false })).toBe(false);
  });

  it("keeps session management to the permission alone", async () => {
    expect(
      await canManageAccount(
        "helpdesk",
        { id: "pluginAdmin", isAdmin: false },
        SESSIONS_MANAGE,
      ),
    ).toBe(true);
    expect(
      await canManageAccount("plain", { id: "plain", isAdmin: false }),
    ).toBe(false);
  });
});
