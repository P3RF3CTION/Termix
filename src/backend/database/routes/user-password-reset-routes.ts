import type { Router } from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { nanoid } from "nanoid";
import { recentActivity } from "../../plugins/activity-provider.js";
import { AuthManager } from "../../utils/auth-manager.js";
import { authLogger } from "../../utils/logger.js";
import { loginRateLimiter } from "../../utils/login-rate-limiter.js";
import {
  createCurrentCredentialRepository,
  createCurrentHostRepository,
  createCurrentSettingsRepository,
  createCurrentSshCredentialUsageRepository,
  createCurrentUserRepository,
} from "../repositories/factory.js";
import { pluginEvents, TOPICS } from "../../plugins/events.js";

interface UserPasswordResetRoutesDeps {
  authManager: AuthManager;
}

function isNonEmptyString(val: unknown): val is string {
  return typeof val === "string" && val.trim().length > 0;
}

export type PasswordResetOutcome =
  | { status: "reset"; dataWiped: false }
  | { status: "reset"; dataWiped: true }
  | { status: "wipe_confirmation_required" };

// Resets a user's password. The DEK is wrapped by the system key, so for any
// user migrated to the v3 wrap this is just a hash update and their data
// survives. Users who never logged in after the encryption upgrade still have
// a password-wrapped DEK that a reset cannot recover; their encrypted data
// must be wiped, which callers have to confirm explicitly.
export async function resetUserPassword(
  authManager: AuthManager,
  options: {
    userId: string;
    username: string;
    newPassword: string;
    confirmDataWipe: boolean;
  },
): Promise<PasswordResetOutcome> {
  const { userId, username, newPassword, confirmDataWipe } = options;
  const passwordHash = await bcrypt.hash(newPassword, 10);
  const userRepository = createCurrentUserRepository();

  if (authManager.isUserUnlocked(userId)) {
    await userRepository.update(userId, { passwordHash });
    await authManager.logoutUser(userId);

    authLogger.success(
      `Password reset (data preserved) for user: ${username}`,
      {
        operation: "password_reset_preserved",
        userId,
        username,
      },
    );
    return { status: "reset", dataWiped: false };
  }

  if (!confirmDataWipe) {
    return { status: "wipe_confirmation_required" };
  }

  await userRepository.update(userId, { passwordHash });

  await createCurrentSshCredentialUsageRepository().deleteByUserId(userId);
  await recentActivity.deleteByUserId(userId);
  await createCurrentHostRepository().deleteByUserId(userId);
  await createCurrentCredentialRepository().deleteByUserId(userId);
  // A plugin holding this user's data (anything keyed by
  // refUser()) wipes it on this topic, since the user row itself survives.
  pluginEvents.emit(TOPICS.userDataWiped, { userId });

  const { UserKeyManager } = await import("../../utils/user-keys.js");
  await UserKeyManager.getInstance().rotateUserDEK(userId);
  const { deleteLegacyWraps } =
    await import("../../utils/crypto-migration/dek-migration.js");
  await deleteLegacyWraps(userId);
  await authManager.logoutUser(userId);

  // Same as 2.8, where the wipe took the TOTP secret with it: the user sets
  // up their second factors again after this.
  const { resetUserSecondFactors } =
    await import("../../auth/second-factor-admin.js");
  await resetUserSecondFactors(userId);

  authLogger.warn(
    `Password reset completed for user: ${username}. All encrypted data has been deleted because the old key was unrecoverable.`,
    {
      operation: "password_reset_data_deleted",
      userId,
      username,
    },
  );
  return { status: "reset", dataWiped: true };
}

export function registerUserPasswordResetRoutes(
  router: Router,
  { authManager }: UserPasswordResetRoutesDeps,
): void {
  /**
   * @openapi
   * /users/initiate-reset:
   *   post:
   *     summary: Initiate password reset
   *     description: Initiates the password reset process for a user.
   *     tags:
   *       - Users
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               username:
   *                 type: string
   *     responses:
   *       200:
   *         description: Password reset code has been generated.
   *       400:
   *         description: Username is required.
   *       403:
   *         description: Password reset not available for external authentication users.
   *       404:
   *         description: User not found.
   *       500:
   *         description: Failed to initiate password reset.
   */
  router.post("/initiate-reset", async (req, res) => {
    try {
      const envVal = process.env.ALLOW_PASSWORD_RESET;
      const allowed =
        envVal !== undefined
          ? envVal.trim().toLowerCase() === "true"
          : await createCurrentSettingsRepository().getBoolean(
              "allow_password_reset",
              true,
            );
      if (!allowed) {
        return res
          .status(403)
          .json({ error: "Password reset is currently disabled" });
      }
    } catch (e) {
      authLogger.warn("Failed to check password reset status", {
        operation: "password_reset_check",
        error: e,
      });
    }

    const { username } = req.body;

    if (!isNonEmptyString(username)) {
      return res.status(400).json({ error: "Username is required" });
    }

    // Rate limit per-username and per-IP so an attacker can't flood the
    // reset log channel or continuously roll a victim's stored code.
    const clientIp =
      (req.headers["x-forwarded-for"] as string | undefined)
        ?.split(",")[0]
        ?.trim() ||
      req.socket?.remoteAddress ||
      "unknown";
    const nameLock = loginRateLimiter.isResetCodeLocked(username);
    if (nameLock.locked) {
      return res.status(429).json({
        error: `Rate limited: too many reset requests. Please wait ${nameLock.remainingTime} seconds before trying again.`,
        remainingTime: nameLock.remainingTime,
        code: "RESET_CODE_RATE_LIMITED",
      });
    }
    const ipLock = loginRateLimiter.isLocked(clientIp);
    if (ipLock.locked) {
      return res.status(429).json({
        error: `Rate limited: too many login/reset attempts from this address. Please wait ${ipLock.remainingTime} seconds before trying again.`,
        remainingTime: ipLock.remainingTime,
      });
    }
    loginRateLimiter.recordResetCodeAttempt(username);

    try {
      const user = await createCurrentUserRepository().findByUsername(username);

      // Same 200 response for existing/missing/external users so the endpoint
      // can't be used for user enumeration.
      const genericResponse = {
        message:
          "If the user exists, a password reset code has been generated. The code is written to the server's authentication log; a server operator can look it up for you.",
      };

      if (!user) {
        authLogger.warn(
          `Password reset attempted for non-existent user: ${username}`,
        );
        return res.json(genericResponse);
      }

      if (user.isExternal) {
        return res.json(genericResponse);
      }

      // Don't overwrite a still-valid code within the first minute: a user
      // who refreshes shouldn't invalidate their own just-received code,
      // and an attacker who sprays this endpoint shouldn't be able to keep
      // a victim's code rolling.
      const existing = await createCurrentSettingsRepository().get(
        `reset_code_${username}`,
      );
      if (existing) {
        try {
          const existingData = JSON.parse(existing);
          const existingExpiresAt = new Date(existingData.expiresAt);
          const existingIssuedAt = existingExpiresAt.getTime() - 15 * 60 * 1000;
          if (
            existingExpiresAt.getTime() > Date.now() &&
            Date.now() - existingIssuedAt < 60 * 1000
          ) {
            return res.json(genericResponse);
          }
        } catch {
          // Malformed stored value — ignore and overwrite.
        }
      }

      const resetCode = crypto.randomInt(100000, 1000000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

      await createCurrentSettingsRepository().set(
        `reset_code_${username}`,
        JSON.stringify({
          code: resetCode,
          expiresAt: expiresAt.toISOString(),
        }),
      );

      // The code is a password-equivalent secret with a 15-minute lifetime.
      // Operators who forward logs off-box should ensure the auth logger's
      // output is restricted to least-privilege reviewers.
      authLogger.warn(
        `SENSITIVE: password reset code for ${username}: ${resetCode} (expires at ${expiresAt.toLocaleString()})`,
        {
          operation: "password_reset_code_issued",
          username,
          expiresAt: expiresAt.toISOString(),
        },
      );

      res.json({
        message:
          "A password reset code has been generated. The code is written to the server's authentication log; a server operator can look it up for you.",
      });
    } catch (err) {
      authLogger.error("Failed to initiate password reset", err);
      res.status(500).json({ error: "Failed to initiate password reset" });
    }
  });

  /**
   * @openapi
   * /users/verify-reset-code:
   *   post:
   *     summary: Verify reset code
   *     description: Verifies the password reset code.
   *     tags:
   *       - Users
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               username:
   *                 type: string
   *               resetCode:
   *                 type: string
   *     responses:
   *       200:
   *         description: Reset code verified.
   *       400:
   *         description: Invalid or expired reset code.
   *       500:
   *         description: Failed to verify reset code.
   */
  router.post("/verify-reset-code", async (req, res) => {
    const { username, resetCode } = req.body;

    if (!isNonEmptyString(username) || !isNonEmptyString(resetCode)) {
      return res
        .status(400)
        .json({ error: "Username and reset code are required" });
    }

    try {
      const lockStatus = loginRateLimiter.isResetCodeLocked(username);
      if (lockStatus.locked) {
        authLogger.warn(
          "Reset code verification blocked due to rate limiting",
          {
            operation: "reset_code_verify_blocked",
            username,
            remainingTime: lockStatus.remainingTime,
          },
        );
        return res.status(429).json({
          error: `Rate limited: Too many verification attempts. Please wait ${lockStatus.remainingTime} seconds before trying again.`,
          remainingTime: lockStatus.remainingTime,
          code: "RESET_CODE_RATE_LIMITED",
        });
      }

      loginRateLimiter.recordResetCodeAttempt(username);

      const resetDataValue = await createCurrentSettingsRepository().get(
        `reset_code_${username}`,
      );
      if (!resetDataValue) {
        authLogger.warn("Reset code verification failed - no code found", {
          operation: "reset_code_verify_failed",
          username,
          remainingAttempts:
            loginRateLimiter.getRemainingResetCodeAttempts(username),
        });
        return res.status(400).json({
          error: "No reset code found for this user",
          remainingAttempts:
            loginRateLimiter.getRemainingResetCodeAttempts(username),
        });
      }

      const resetData = JSON.parse(resetDataValue);
      const now = new Date();
      const expiresAt = new Date(resetData.expiresAt);

      if (now > expiresAt) {
        await createCurrentSettingsRepository().delete(
          `reset_code_${username}`,
        );
        authLogger.warn("Reset code verification failed - code expired", {
          operation: "reset_code_verify_failed",
          username,
          remainingAttempts:
            loginRateLimiter.getRemainingResetCodeAttempts(username),
        });
        return res.status(400).json({
          error: "Reset code has expired",
          remainingAttempts:
            loginRateLimiter.getRemainingResetCodeAttempts(username),
        });
      }

      // Timing-safe compare so the 6-digit code can't be byte-walked on
      // deployments where this endpoint isn't rate limited in front of us.
      const storedCode = String(resetData.code ?? "");
      const providedCode = String(resetCode);
      const codeMatches =
        storedCode.length === providedCode.length &&
        crypto.timingSafeEqual(
          Buffer.from(storedCode),
          Buffer.from(providedCode),
        );
      if (!codeMatches) {
        authLogger.warn("Reset code verification failed - invalid code", {
          operation: "reset_code_verify_failed",
          username,
          remainingAttempts:
            loginRateLimiter.getRemainingResetCodeAttempts(username),
        });
        return res.status(400).json({
          error: "Invalid reset code",
          remainingAttempts:
            loginRateLimiter.getRemainingResetCodeAttempts(username),
        });
      }

      loginRateLimiter.resetResetCodeAttempts(username);

      const tempToken = nanoid();
      const tempTokenExpiry = new Date(Date.now() + 10 * 60 * 1000);

      // Consume the one-time reset code: it has done its job, and leaving
      // it callable would widen the window if the temp token leaked.
      await createCurrentSettingsRepository().delete(
        `reset_code_${username}`,
      );
      await createCurrentSettingsRepository().set(
        `temp_reset_token_${username}`,
        JSON.stringify({
          token: tempToken,
          expiresAt: tempTokenExpiry.toISOString(),
        }),
      );

      res.json({ message: "Reset code verified", tempToken });
    } catch (err) {
      authLogger.error("Failed to verify reset code", err);
      res.status(500).json({ error: "Failed to verify reset code" });
    }
  });

  /**
   * @openapi
   * /users/complete-reset:
   *   post:
   *     summary: Complete password reset
   *     description: Completes the password reset process with a new password.
   *     tags:
   *       - Users
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               username:
   *                 type: string
   *               tempToken:
   *                 type: string
   *               newPassword:
   *                 type: string
   *     responses:
   *       200:
   *         description: Password has been successfully reset.
   *       400:
   *         description: Invalid or expired temporary token.
   *       404:
   *         description: User not found.
   *       500:
   *         description: Failed to complete password reset.
   */
  router.post("/complete-reset", async (req, res) => {
    const { username, tempToken, newPassword } = req.body;

    if (
      !isNonEmptyString(username) ||
      !isNonEmptyString(tempToken) ||
      !isNonEmptyString(newPassword)
    ) {
      return res.status(400).json({
        error: "Username, temporary token, and new password are required",
      });
    }

    // Minimum password policy: too weak a password bypasses every other
    // defence this endpoint has. Keep the policy conservative (no character
    // class rules that trip up good passwords) but refuse trivially short
    // ones.
    if (newPassword.length < 10) {
      return res.status(400).json({
        error: "New password must be at least 10 characters long",
      });
    }

    // Rate limit the temp-token guess the same way verify-reset-code is
    // limited: both consume a reset code and lead to the same account.
    const nameLock = loginRateLimiter.isResetCodeLocked(username);
    if (nameLock.locked) {
      return res.status(429).json({
        error: `Rate limited: too many reset attempts. Please wait ${nameLock.remainingTime} seconds before trying again.`,
        remainingTime: nameLock.remainingTime,
        code: "RESET_CODE_RATE_LIMITED",
      });
    }
    loginRateLimiter.recordResetCodeAttempt(username);

    try {
      const tempTokenValue = await createCurrentSettingsRepository().get(
        `temp_reset_token_${username}`,
      );
      if (!tempTokenValue) {
        return res.status(400).json({ error: "No temporary token found" });
      }

      const tempTokenData = JSON.parse(tempTokenValue);
      const now = new Date();
      const expiresAt = new Date(tempTokenData.expiresAt);

      if (now > expiresAt) {
        await createCurrentSettingsRepository().delete(
          `temp_reset_token_${username}`,
        );
        return res.status(400).json({ error: "Temporary token has expired" });
      }

      const storedToken = String(tempTokenData.token ?? "");
      const providedToken = String(tempToken);
      const tokenMatches =
        storedToken.length === providedToken.length &&
        crypto.timingSafeEqual(
          Buffer.from(storedToken),
          Buffer.from(providedToken),
        );
      if (!tokenMatches) {
        // Burn the stored token on a mismatch so a brute-forcer can't keep
        // guessing against the same reservation. The user restarts the
        // flow with initiate-reset.
        await createCurrentSettingsRepository().delete(
          `temp_reset_token_${username}`,
        );
        return res.status(400).json({ error: "Invalid temporary token" });
      }

      const user = await createCurrentUserRepository().findByUsername(username);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const userId = user.id;

      const outcome = await resetUserPassword(authManager, {
        userId,
        username,
        newPassword,
        confirmDataWipe: req.body?.confirmDataWipe === true,
      });

      if (outcome.status === "wipe_confirmation_required") {
        return res.status(409).json({
          error:
            "This account has not logged in since the encryption upgrade, so its stored data cannot be recovered without the old password. Resetting will permanently delete its hosts, credentials and other saved data.",
          code: "DATA_WIPE_REQUIRED",
        });
      }

      authLogger.success(`Password successfully reset for user: ${username}`);

      const settingsRepository = createCurrentSettingsRepository();
      await settingsRepository.delete(`reset_code_${username}`);
      await settingsRepository.delete(`temp_reset_token_${username}`);

      res.json({
        message: "Password has been successfully reset",
        dataWiped: outcome.dataWiped,
      });
    } catch (err) {
      authLogger.error("Failed to complete password reset", err);
      res.status(500).json({ error: "Failed to complete password reset" });
    }
  });
}
