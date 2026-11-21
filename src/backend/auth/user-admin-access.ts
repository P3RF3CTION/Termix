import { PermissionManager } from "../utils/permission-manager.js";

export const USERS_VIEW = "admin.users.view";
export const USERS_MANAGE = "admin.users.manage";
export const SESSIONS_MANAGE = "admin.sessions.manage";
export const AUDIT_VIEW = "admin.audit.view";

/** Whether the caller may see account details in the admin user list. */
export function canViewUsers(actorId: string | undefined): Promise<boolean> {
  if (!actorId) return Promise.resolve(false);
  return PermissionManager.getInstance().hasPermission(actorId, USERS_VIEW);
}

/** Whether the caller holds a permission (admins hold every one). */
export function actorHas(
  actorId: string | undefined,
  permission: string,
): Promise<boolean> {
  if (!actorId) return Promise.resolve(false);
  return PermissionManager.getInstance().hasPermission(actorId, permission);
}

/**
 * Whether the caller may change this account. Admins may change anyone.
 * Someone holding only a delegated permission never touches an admin, so a
 * helpdesk role can't reset an admin's password and take over. For account
 * changes (USERS_MANAGE: password and second-factor resets, profile edits,
 * disabling) the target also may not hold an admin permission the caller
 * lacks, the same rule role grants follow, or resetting a more privileged
 * user's password would be a way up.
 */
export async function canManageAccount(
  actorId: string | undefined,
  target: { isAdmin: boolean; id?: string },
  permission: string = USERS_MANAGE,
): Promise<boolean> {
  if (!actorId) return false;
  const permissions = PermissionManager.getInstance();
  if (await permissions.isAdmin(actorId)) return true;
  if (target.isAdmin) return false;
  if (!(await permissions.hasPermission(actorId, permission))) return false;
  if (permission !== USERS_MANAGE) return true;
  if (!target.id) return false;
  for (const held of await permissions.getUserPermissions(target.id)) {
    if (held !== "*" && !held.startsWith("admin.")) continue;
    if (!(await permissions.hasPermission(actorId, held))) return false;
  }
  return true;
}
