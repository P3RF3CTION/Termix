import type { AuthenticatedRequest } from "../../../types/index.js";
import type { RequestHandler, Router } from "express";
import bcrypt from "bcryptjs";
import { AuthManager } from "../../utils/auth-manager.js";
import { authLogger } from "../../utils/logger.js";
import { createCurrentUserRepository } from "../repositories/factory.js";

interface UserDataAccessRoutesDeps {
  authenticateJWT: RequestHandler;
  authManager: AuthManager;
}

export function registerUserDataAccessRoutes(
  router: Router,
  { authenticateJWT, authManager }: UserDataAccessRoutesDeps,
): void {
  /**
   * @openapi
   * /users/unlock-data:
   *   post:
   *     summary: Unlock user data
   *     description: Re-authenticates user with password to unlock encrypted data.
   *     tags:
   *       - Users
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               password:
   *                 type: string
   *     responses:
   *       200:
   *         description: Data unlocked successfully.
   *       400:
   *         description: Password is required.
   *       401:
   *         description: Invalid password.
   *       500:
   *         description: Failed to unlock data.
   */
  router.post("/unlock-data", authenticateJWT, async (req, res) => {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.userId;
    const { password } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    if (!password) {
      return res.status(400).json({ error: "Password is required" });
    }

    try {
      // authManager.authenticateUser is a no-op for users already migrated to
      // the v3 wrap: it returns true whenever the DEK can be loaded, without
      // re-checking the password. That is fine for the login flow (which
      // verifies the password against bcrypt above the call) but here it means
      // any string sent by an already-authenticated client would "unlock"
      // data. Re-check the password here so this route lives up to its name.
      const userRepository = createCurrentUserRepository();
      const userRecord = await userRepository.findById(userId);
      if (!userRecord || !userRecord.passwordHash) {
        return res.status(401).json({ error: "Invalid password" });
      }
      const passwordMatches = await bcrypt.compare(
        password,
        userRecord.passwordHash,
      );
      if (!passwordMatches) {
        authLogger.warn("Failed to unlock user data - invalid password", {
          operation: "user_data_unlock_failed",
          userId,
        });
        return res.status(401).json({ error: "Invalid password" });
      }

      const unlocked = await authManager.authenticateUser(userId, password);
      if (unlocked) {
        const refreshedSession =
          userId && authReq.sessionId
            ? await authManager.refreshSessionToken(userId, authReq.sessionId)
            : null;

        if (refreshedSession) {
          res.cookie(
            "jwt",
            refreshedSession.token,
            authManager.getSecureCookieOptions(req, refreshedSession.maxAge),
          );
        }

        res.json({
          success: true,
          message: "Data unlocked successfully",
        });
      } else {
        authLogger.warn("Failed to unlock user data - invalid password", {
          operation: "user_data_unlock_failed",
          userId,
        });
        res.status(401).json({ error: "Invalid password" });
      }
    } catch (err) {
      authLogger.error("Data unlock failed", err, {
        operation: "user_data_unlock_error",
        userId,
      });
      res.status(500).json({ error: "Failed to unlock data" });
    }
  });

  /**
   * @openapi
   * /users/data-status:
   *   get:
   *     summary: Check user data unlock status
   *     description: Checks if user data is currently unlocked.
   *     tags:
   *       - Users
   *     responses:
   *       200:
   *         description: Data status returned.
   *       500:
   *         description: Failed to check data status.
   */
  router.get("/data-status", authenticateJWT, async (req, res) => {
    const userId = (req as AuthenticatedRequest).userId;

    try {
      const unlocked = authManager.isUserUnlocked(userId);
      res.json({
        unlocked,
        message: unlocked ? "Data is unlocked" : "Data is locked",
      });
    } catch (err) {
      authLogger.error("Failed to check data status", err, {
        operation: "data_status_check_failed",
        userId,
      });
      res.status(500).json({ error: "Failed to check data status" });
    }
  });
}
