import type { AuthenticatedRequest } from "../../../types/index.js";
import type { Request, RequestHandler, Router } from "express";
import bcrypt from "bcryptjs";
import {
  findMatchingBackupCode,
  generateBackupCodes,
  hashBackupCodes,
} from "../../utils/backup-codes.js";
import QRCode from "qrcode";
import speakeasy from "speakeasy";
import { AuthManager } from "../../utils/auth-manager.js";
import { DatabaseSaveTrigger } from "../../utils/database-save-trigger.js";
import { FieldCrypto } from "../../utils/field-crypto.js";
import { LazyFieldEncryption } from "../../utils/lazy-field-encryption.js";
import { authLogger } from "../../utils/logger.js";
import { loginRateLimiter } from "../../utils/login-rate-limiter.js";
import { isTrustedProxyAuthEnabled } from "../../utils/trusted-proxy-auth.js";
import {
  generateDeviceFingerprint,
  getDeviceId,
  parseUserAgent,
} from "../../utils/user-agent-parser.js";
import {
  createCurrentSessionRepository,
  createCurrentSettingsRepository,
  createCurrentTrustedDeviceRepository,
  createCurrentUserRepository,
} from "../repositories/factory.js";
import type { UserRecord } from "../repositories/user-repository.js";
import crypto from "crypto";

type NativeAppRequestChecker = (req: Request) => boolean;

// Track pendingTOTP JWTs that have already been redeemed for a full session.
// The temp_token itself lives 10 minutes (see users.ts) and, as a stateless
// JWT, was previously replayable to mint additional sessions from a single
// successful TOTP exchange. Signature+exp is what jwt.verify checks; this map
// carries the "already consumed" bit that a stateless token can't hold.
const consumedTempTokens = new Map<string, number>();

function isTempTokenConsumed(token: string): boolean {
  const now = Date.now();
  pruneReplayMaps(now);
  return consumedTempTokens.has(hashTempToken(token));
}

// Guard against replay of a valid TOTP code across the ±2-step (~2.5 minute)
// verification window: the same 30-second code should not be accepted twice.
// Keyed by userId → set of recently accepted codes with their expiry.
const usedTOTPCodes = new Map<string, Map<string, number>>();

const TOTP_CODE_REPLAY_TTL_MS = 5 * 60 * 1000;
const TEMP_TOKEN_CONSUMED_TTL_MS = 15 * 60 * 1000;

function pruneReplayMaps(now: number): void {
  for (const [token, expiresAt] of consumedTempTokens) {
    if (expiresAt <= now) consumedTempTokens.delete(token);
  }
  for (const [userId, codes] of usedTOTPCodes) {
    for (const [code, expiresAt] of codes) {
      if (expiresAt <= now) codes.delete(code);
    }
    if (codes.size === 0) usedTOTPCodes.delete(userId);
  }
}

function hashTempToken(token: string): string {
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}

function consumePendingTOTPToken(
  token: string,
  decoded: { exp?: number } | null,
): boolean {
  const now = Date.now();
  pruneReplayMaps(now);
  const digest = hashTempToken(token);
  if (consumedTempTokens.has(digest)) return false;
  const expMs =
    decoded?.exp && Number.isFinite(decoded.exp)
      ? decoded.exp * 1000
      : now + TEMP_TOKEN_CONSUMED_TTL_MS;
  consumedTempTokens.set(digest, expMs);
  return true;
}

function recentlyUsedTOTPCode(userId: string, code: string): boolean {
  const now = Date.now();
  pruneReplayMaps(now);
  const codes = usedTOTPCodes.get(userId);
  if (!codes) return false;
  const expiresAt = codes.get(code);
  return typeof expiresAt === "number" && expiresAt > now;
}

function rememberUsedTOTPCode(userId: string, code: string): void {
  const now = Date.now();
  let codes = usedTOTPCodes.get(userId);
  if (!codes) {
    codes = new Map();
    usedTOTPCodes.set(userId, codes);
  }
  codes.set(code, now + TOTP_CODE_REPLAY_TTL_MS);
}

interface UserTotpRoutesDeps {
  authenticateJWT: RequestHandler;
  authManager: AuthManager;
  isNativeAppRequest: NativeAppRequestChecker;
}

export async function verifyTotpReauth(
  userRecord: UserRecord,
  credential: string,
  userDataKey?: Buffer | null,
): Promise<boolean> {
  if (userRecord.totpSecret) {
    const totpSecret = userDataKey
      ? LazyFieldEncryption.safeGetFieldValue(
          userRecord.totpSecret,
          userDataKey,
          userRecord.id,
          "totpSecret",
        )
      : userRecord.totpSecret;

    if (totpSecret) {
      const totpMatch = speakeasy.totp.verify({
        secret: totpSecret,
        encoding: "base32",
        token: credential,
        window: 2,
      });
      if (totpMatch) {
        return true;
      }
    }
  }

  const rawBackupCodes =
    userDataKey && userRecord.totpBackupCodes
      ? LazyFieldEncryption.safeGetFieldValue(
          userRecord.totpBackupCodes,
          userDataKey,
          userRecord.id,
          "totpBackupCodes",
        )
      : userRecord.totpBackupCodes;

  let backupCodes: unknown = [];
  try {
    backupCodes = rawBackupCodes ? JSON.parse(rawBackupCodes) : [];
  } catch {
    backupCodes = [];
  }
  if (Array.isArray(backupCodes)) {
    // Iterates every entry regardless of an early hit -- lets a mixed list of
    // legacy plaintext and freshly-hashed entries be compared without leaking
    // which format matched through timing.
    const backupIndex = findMatchingBackupCode(backupCodes, credential);
    if (backupIndex !== -1) {
      backupCodes.splice(backupIndex, 1);
      const updatedJson = JSON.stringify(backupCodes);
      const storedValue = userDataKey
        ? FieldCrypto.encryptField(
            updatedJson,
            userDataKey,
            userRecord.id,
            "totpBackupCodes",
          )
        : updatedJson;
      await createCurrentUserRepository().update(userRecord.id, {
        totpBackupCodes: storedValue,
      });
      return true;
    }
  }

  return false;
}

export function registerUserTotpRoutes(
  router: Router,
  { authenticateJWT, authManager, isNativeAppRequest }: UserTotpRoutesDeps,
): void {
  /**
   * @openapi
   * /users/totp/setup:
   *   post:
   *     summary: Setup TOTP
   *     description: Initiates TOTP setup by generating a secret and QR code.
   *     tags:
   *       - Users
   *     responses:
   *       200:
   *         description: TOTP setup initiated with secret and QR code.
   *       400:
   *         description: TOTP is already enabled.
   *       404:
   *         description: User not found.
   *       500:
   *         description: Failed to setup TOTP.
   */
  router.post("/totp/setup", authenticateJWT, async (req, res) => {
    const userId = (req as AuthenticatedRequest).userId;

    try {
      const userRecord = await createCurrentUserRepository().findById(userId);
      if (!userRecord) {
        return res.status(404).json({ error: "User not found" });
      }

      if (userRecord.totpEnabled) {
        return res.status(400).json({ error: "TOTP is already enabled" });
      }

      const secret = speakeasy.generateSecret({
        name: `Termix (${userRecord.username})`,
        length: 32,
      });

      // Store encrypted with the user DEK when available -- the enable/verify
      // paths already assume the column is field-encrypted (they run
      // safeGetFieldValue on it). Lazy migration would only rewrap on next
      // read, so a crash, backup, or replication between /setup and /enable
      // would expose a working TOTP seed.
      const userDataKey = authManager.getUserDataKey(userId);
      const storedSecret = userDataKey
        ? FieldCrypto.encryptField(
            secret.base32,
            userDataKey,
            userId,
            "totpSecret",
          )
        : secret.base32;

      await createCurrentUserRepository().update(userId, {
        totpSecret: storedSecret,
      });

      const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url || "");

      res.json({
        secret: secret.base32,
        qr_code: qrCodeUrl,
      });
    } catch (err) {
      authLogger.error("Failed to setup TOTP", err);
      res.status(500).json({ error: "Failed to setup TOTP" });
    }
  });

  /**
   * @openapi
   * /users/totp/enable:
   *   post:
   *     summary: Enable TOTP
   *     description: Enables TOTP after verifying the initial code.
   *     tags:
   *       - Users
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               totp_code:
   *                 type: string
   *     responses:
   *       200:
   *         description: TOTP enabled successfully with backup codes.
   *       400:
   *         description: TOTP code is required or TOTP already enabled.
   *       401:
   *         description: Invalid TOTP code.
   *       404:
   *         description: User not found.
   *       500:
   *         description: Failed to enable TOTP.
   */
  router.post("/totp/enable", authenticateJWT, async (req, res) => {
    if (isTrustedProxyAuthEnabled()) {
      return res.status(409).json({
        error: "TOTP is disabled while trusted proxy authentication is enabled",
      });
    }
    const userId = (req as AuthenticatedRequest).userId;
    const sessionId = (req as AuthenticatedRequest).sessionId;
    const { totp_code } = req.body;

    if (!totp_code) {
      return res.status(400).json({ error: "TOTP code is required" });
    }

    try {
      const passwordLoginAllowed =
        await createCurrentSettingsRepository().getBoolean(
          "allow_password_login",
          true,
        );
      if (!passwordLoginAllowed) {
        return res.status(409).json({
          error:
            "Cannot enable 2FA while password login is disabled. Enable password login first.",
        });
      }

      const userRecord = await createCurrentUserRepository().findById(userId);
      if (!userRecord) {
        return res.status(404).json({ error: "User not found" });
      }

      if (userRecord.totpEnabled) {
        return res.status(400).json({ error: "TOTP is already enabled" });
      }

      if (!userRecord.totpSecret) {
        return res.status(400).json({ error: "TOTP setup not initiated" });
      }

      const userDataKey = authManager.getUserDataKey(userId);
      const totpSecret = userDataKey
        ? LazyFieldEncryption.safeGetFieldValue(
            userRecord.totpSecret,
            userDataKey,
            userId,
            "totpSecret",
          )
        : userRecord.totpSecret;

      const verified = speakeasy.totp.verify({
        secret: totpSecret,
        encoding: "base32",
        token: totp_code,
        window: 2,
      });

      if (!verified) {
        return res.status(401).json({ error: "Invalid TOTP code" });
      }

      const backupCodes = generateBackupCodes();
      // Hash before persisting: a DB read (backup, snapshot, or a SQLi
      // elsewhere) must not hand the attacker eight working 2FA bypass
      // codes. Field encryption still wraps the JSON on top.
      const storedHashedCodes = hashBackupCodes(backupCodes);

      const backupCodesJson = JSON.stringify(storedHashedCodes);
      const storedBackupCodes = userDataKey
        ? FieldCrypto.encryptField(
            backupCodesJson,
            userDataKey,
            userId,
            "totpBackupCodes",
          )
        : backupCodesJson;

      await createCurrentUserRepository().update(userId, {
        totpEnabled: true,
        totpBackupCodes: storedBackupCodes,
      });

      await createCurrentSessionRepository().revokeAllForUser(
        userId,
        sessionId,
      );
      await createCurrentTrustedDeviceRepository().deleteByUserId(userId);

      try {
        await DatabaseSaveTrigger.forceSave("totp_enable_explicit_save");
      } catch (saveError) {
        authLogger.error(
          "Failed to persist TOTP enablement to disk",
          saveError,
          {
            operation: "totp_enable_db_save_failed",
            userId,
          },
        );
      }

      res.json({
        message: "TOTP enabled successfully",
        backup_codes: backupCodes,
      });
    } catch (err) {
      authLogger.error("Failed to enable TOTP", err);
      res.status(500).json({ error: "Failed to enable TOTP" });
    }
  });

  /**
   * @openapi
   * /users/totp/disable:
   *   post:
   *     summary: Disable TOTP
   *     description: Disables TOTP for a user.
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
   *               totp_code:
   *                 type: string
   *     responses:
   *       200:
   *         description: TOTP disabled successfully.
   *       400:
   *         description: Password or TOTP code is required.
   *       401:
   *         description: Incorrect password or invalid TOTP code.
   *       404:
   *         description: User not found.
   *       500:
   *         description: Failed to disable TOTP.
   */
  router.post("/totp/disable", authenticateJWT, async (req, res) => {
    const userId = (req as AuthenticatedRequest).userId;
    const { password, totp_code } = req.body;
    try {
      const userRecord = await createCurrentUserRepository().findById(userId);
      if (!userRecord) {
        return res.status(404).json({ error: "User not found" });
      }

      // One re-authentication value, whichever kind it is. The dialog offers a
      // single field -- "Enter TOTP code or password" -- so it arrives in
      // whichever of the two body fields the caller happened to use.
      const credential = totp_code || password;
      if (!credential) {
        return res.status(400).json({
          error: userRecord.isOidc
            ? "A TOTP code is required"
            : "A TOTP code or password is required",
        });
      }

      if (!userRecord.totpEnabled) {
        return res.status(400).json({ error: "TOTP is not enabled" });
      }

      const userDataKey = authManager.getUserDataKey(userId);
      // TOTP code or backup code first; verifyTotpReauth deliberately refuses
      // the account password, so that stays a separate comparison here.
      let verified = await verifyTotpReauth(
        userRecord,
        credential,
        userDataKey,
      );

      if (!verified && !userRecord.isOidc && userRecord.passwordHash) {
        verified = await bcrypt.compare(credential, userRecord.passwordHash);
      }

      if (!verified) {
        return res
          .status(401)
          .json({ error: "Incorrect password or invalid TOTP code" });
      }

      await createCurrentUserRepository().update(userId, {
        totpEnabled: false,
        totpSecret: null,
        totpBackupCodes: null,
      });
      authLogger.info("Two-factor authentication disabled", {
        operation: "totp_disable",
        userId,
      });

      res.json({ message: "TOTP disabled successfully" });
    } catch (err) {
      authLogger.error("Failed to disable TOTP", err);
      res.status(500).json({ error: "Failed to disable TOTP" });
    }
  });

  /**
   * @openapi
   * /users/totp/backup-codes:
   *   post:
   *     summary: Generate new backup codes
   *     description: Generates new TOTP backup codes.
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
   *               totp_code:
   *                 type: string
   *     responses:
   *       200:
   *         description: New backup codes generated.
   *       400:
   *         description: Password or TOTP code is required.
   *       401:
   *         description: Incorrect password or invalid TOTP code.
   *       404:
   *         description: User not found.
   *       500:
   *         description: Failed to generate backup codes.
   */
  router.post("/totp/backup-codes", authenticateJWT, async (req, res) => {
    const userId = (req as AuthenticatedRequest).userId;
    const { password, totp_code } = req.body;
    try {
      const userRecord = await createCurrentUserRepository().findById(userId);
      if (!userRecord) {
        return res.status(404).json({ error: "User not found" });
      }

      if (!totp_code || (!userRecord.isOidc && !password)) {
        return res.status(400).json({
          error: userRecord.isOidc
            ? "A TOTP code is required"
            : "Both password and TOTP code are required",
        });
      }

      if (
        !userRecord.isOidc &&
        (!userRecord.passwordHash ||
          !(await bcrypt.compare(password, userRecord.passwordHash)))
      ) {
        return res.status(401).json({ error: "Incorrect password" });
      }

      if (!userRecord.totpEnabled) {
        return res.status(400).json({ error: "TOTP is not enabled" });
      }

      const userDataKey = authManager.getUserDataKey(userId);
      const verified = await verifyTotpReauth(
        userRecord,
        totp_code,
        userDataKey,
      );
      if (!verified) {
        return res
          .status(401)
          .json({ error: "Incorrect password or invalid TOTP code" });
      }

      const backupCodes = generateBackupCodes();
      const storedHashedCodes = hashBackupCodes(backupCodes);

      const backupCodesJson = JSON.stringify(storedHashedCodes);
      const storedBackupCodes = userDataKey
        ? FieldCrypto.encryptField(
            backupCodesJson,
            userDataKey,
            userId,
            "totpBackupCodes",
          )
        : backupCodesJson;

      await createCurrentUserRepository().update(userId, {
        totpBackupCodes: storedBackupCodes,
      });

      res.json({ backup_codes: backupCodes });
    } catch (err) {
      authLogger.error("Failed to generate backup codes", err);
      res.status(500).json({ error: "Failed to generate backup codes" });
    }
  });

  /**
   * @openapi
   * /users/totp/verify-login:
   *   post:
   *     summary: Verify TOTP during login
   *     description: Verifies the TOTP code during login.
   *     tags:
   *       - Users
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               temp_token:
   *                 type: string
   *               totp_code:
   *                 type: string
   *     responses:
   *       200:
   *         description: TOTP verification successful.
   *       400:
   *         description: Token and TOTP code are required.
   *       401:
   *         description: Invalid temporary token or TOTP code.
   *       404:
   *         description: User not found.
   *       500:
   *         description: TOTP verification failed.
   */
  router.post("/totp/verify-login", async (req, res) => {
    const { temp_token, totp_code, rememberMe } = req.body;

    if (!temp_token || !totp_code) {
      return res
        .status(400)
        .json({ error: "Token and TOTP code are required" });
    }

    try {
      const decoded = await authManager.verifyJWTToken(temp_token);
      if (!decoded || !decoded.pendingTOTP) {
        return res.status(401).json({ error: "Invalid temporary token" });
      }

      // Bail out before touching state (DB writes, rate-limit buckets) if the
      // same temp_token has already been redeemed for a full session — a
      // stateless JWT would otherwise stay replayable for its 10-minute life.
      if (isTempTokenConsumed(temp_token)) {
        authLogger.warn("TOTP verification rejected - temp token replayed", {
          operation: "totp_verify_replay_token",
          userId: decoded.userId,
        });
        return res.status(401).json({ error: "Invalid temporary token" });
      }

      const userRecord = await createCurrentUserRepository().findById(
        decoded.userId,
      );
      if (!userRecord) {
        return res.status(404).json({ error: "User not found" });
      }

      const lockStatus = loginRateLimiter.isTOTPLocked(userRecord.id);
      if (lockStatus.locked) {
        authLogger.warn("TOTP verification blocked due to rate limiting", {
          operation: "totp_verify_blocked",
          userId: userRecord.id,
          remainingTime: lockStatus.remainingTime,
        });
        return res.status(429).json({
          error: `Rate limited: Too many TOTP verification attempts. Please wait ${lockStatus.remainingTime} seconds before trying again.`,
          remainingTime: lockStatus.remainingTime,
          code: "TOTP_RATE_LIMITED",
        });
      }

      loginRateLimiter.recordFailedTOTPAttempt(userRecord.id);

      if (!userRecord.totpEnabled || !userRecord.totpSecret) {
        return res
          .status(400)
          .json({ error: "TOTP not enabled for this user" });
      }

      const userDataKey = authManager.getUserDataKey(userRecord.id);
      if (!userDataKey) {
        return res.status(401).json({
          error: "Session expired - please log in again",
          code: "SESSION_EXPIRED",
        });
      }

      const totpSecret = LazyFieldEncryption.safeGetFieldValue(
        userRecord.totpSecret,
        userDataKey,
        userRecord.id,
        "totp_secret",
      );

      if (!totpSecret) {
        await createCurrentUserRepository().update(userRecord.id, {
          totpEnabled: false,
          totpSecret: null,
          totpBackupCodes: null,
        });

        return res.status(400).json({
          error:
            "TOTP has been disabled due to password reset. Please set up TOTP again.",
        });
      }

      const verified = speakeasy.totp.verify({
        secret: totpSecret,
        encoding: "base32",
        token: totp_code,
        window: 2,
      });

      if (!verified) {
        // Read through the field-encryption layer -- reading the raw column
        // silently throws on a decrypted-then-re-encrypted value, and would
        // also permanently downgrade the column below by re-persisting the
        // decrypted array as plaintext.
        const rawBackupCodes = userRecord.totpBackupCodes
          ? LazyFieldEncryption.safeGetFieldValue(
              userRecord.totpBackupCodes,
              userDataKey,
              userRecord.id,
              "totpBackupCodes",
            )
          : null;

        let backupCodes: unknown = [];
        try {
          backupCodes = rawBackupCodes ? JSON.parse(rawBackupCodes) : [];
        } catch {
          backupCodes = [];
        }

        if (!Array.isArray(backupCodes)) {
          backupCodes = [];
        }

        const backupIndex = findMatchingBackupCode(backupCodes, totp_code);

        if (backupIndex === -1) {
          authLogger.warn("TOTP verification failed - invalid code", {
            operation: "totp_verify_failed",
            userId: userRecord.id,
            remainingAttempts: loginRateLimiter.getRemainingTOTPAttempts(
              userRecord.id,
            ),
          });
          return res.status(401).json({
            error: "Invalid TOTP code",
            remainingAttempts: loginRateLimiter.getRemainingTOTPAttempts(
              userRecord.id,
            ),
          });
        }

        (backupCodes as unknown[]).splice(backupIndex, 1);
        const updatedJson = JSON.stringify(backupCodes);
        const storedValue = userDataKey
          ? FieldCrypto.encryptField(
              updatedJson,
              userDataKey,
              userRecord.id,
              "totpBackupCodes",
            )
          : updatedJson;
        await createCurrentUserRepository().update(userRecord.id, {
          totpBackupCodes: storedValue,
        });
      } else {
        // TOTP code was valid, not a backup code. Guard against replay across
        // the ±window: the same 30-second code accepted here must not be
        // accepted a second time in the ~2.5 minutes it is still in-range.
        if (recentlyUsedTOTPCode(userRecord.id, totp_code)) {
          authLogger.warn("TOTP verification rejected - code already used", {
            operation: "totp_verify_replay",
            userId: userRecord.id,
          });
          return res.status(401).json({
            error: "Invalid TOTP code",
            remainingAttempts: loginRateLimiter.getRemainingTOTPAttempts(
              userRecord.id,
            ),
          });
        }
        rememberUsedTOTPCode(userRecord.id, totp_code);
      }

      // The temp_token is a stateless JWT that lives for 10 minutes. Without a
      // consumed marker it can be replayed to mint additional sessions in that
      // window from the same successful TOTP exchange.
      if (!consumePendingTOTPToken(temp_token, decoded)) {
        authLogger.warn("TOTP verification rejected - temp token replayed", {
          operation: "totp_verify_replay_token",
          userId: userRecord.id,
        });
        return res.status(401).json({ error: "Invalid temporary token" });
      }

      loginRateLimiter.resetTOTPAttempts(userRecord.id);

      const deviceInfo = parseUserAgent(req);

      if (rememberMe) {
        const deviceFingerprint = generateDeviceFingerprint(
          deviceInfo,
          getDeviceId(req),
        );
        if (deviceFingerprint) {
          await authManager.addTrustedDevice(
            userRecord.id,
            deviceFingerprint,
            deviceInfo.type,
            deviceInfo.deviceInfo,
          );
          authLogger.info("Device automatically trusted via Remember Me", {
            operation: "totp_auto_trust",
            userId: userRecord.id,
            deviceType: deviceInfo.type,
          });
        }
      }

      const token = await authManager.generateJWTToken(userRecord.id, {
        rememberMe: !!rememberMe,
        deviceType: deviceInfo.type,
        deviceInfo: deviceInfo.deviceInfo,
      });

      authLogger.success("TOTP verification successful", {
        operation: "totp_verify_success",
        userId: userRecord.id,
        deviceType: deviceInfo.type,
        deviceInfo: deviceInfo.deviceInfo,
      });

      const response: Record<string, unknown> = {
        success: true,
        is_admin: !!userRecord.isAdmin,
        username: userRecord.username,
        userId: userRecord.id,
        is_oidc: !!userRecord.isOidc,
        totp_enabled: !!userRecord.totpEnabled,
        ...(isNativeAppRequest(req) ? { token } : {}),
      };

      const timeoutValue = await createCurrentSettingsRepository().get(
        "session_timeout_hours",
      );
      const timeoutHours = timeoutValue ? parseInt(timeoutValue, 10) || 24 : 24;
      const maxAge = rememberMe
        ? 30 * 24 * 60 * 60 * 1000
        : timeoutHours * 60 * 60 * 1000;

      return res
        .cookie("jwt", token, authManager.getSecureCookieOptions(req, maxAge))
        .json(response);
    } catch (err) {
      authLogger.error("TOTP verification failed", err);
      return res.status(500).json({ error: "TOTP verification failed" });
    }
  });
}
