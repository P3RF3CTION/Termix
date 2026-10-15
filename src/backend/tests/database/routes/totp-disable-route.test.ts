import { beforeEach, describe, expect, it, vi } from "vitest";
import bcrypt from "bcryptjs";
import speakeasy from "speakeasy";

const userUpdate = vi.fn().mockResolvedValue(null);
const findById = vi.fn();

vi.mock("../../../database/repositories/factory.js", () => ({
  createCurrentUserRepository: () => ({ findById, update: userUpdate }),
  createCurrentTrustedDeviceRepository: () => ({}),
  createCurrentUserSessionRepository: () => ({}),
}));

vi.mock("../../../utils/logger.js", () => ({
  authLogger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    success: vi.fn(),
  },
}));

vi.mock("../../../utils/database-save-trigger.js", () => ({
  DatabaseSaveTrigger: { forceSave: vi.fn().mockResolvedValue(undefined) },
}));

const { registerUserTotpRoutes } =
  await import("../../../database/routes/user-totp-routes.js");

const secret = speakeasy.generateSecret({ name: "test" }).base32;
const PASSWORD = "correct-horse";

/**
 * The disable dialog now only accepts a TOTP code or a backup code -- the
 * "or password" branch was pulled out because a stolen password on its own
 * would otherwise be enough to remove the second factor 2FA is meant to
 * defend against. The client is expected to send the value in `totp_code`;
 * the `password` field is no longer honoured.
 */
describe("POST /totp/disable", () => {
  let handler: (req: unknown, res: unknown) => Promise<void>;

  beforeEach(() => {
    vi.clearAllMocks();

    const routes = new Map<string, (req: unknown, res: unknown) => unknown>();
    const router = {
      post: (path: string, ...rest: unknown[]) => {
        routes.set(path, rest[rest.length - 1] as never);
      },
      get: () => {},
      put: () => {},
      delete: () => {},
    };

    registerUserTotpRoutes(
      router as never,
      {
        authenticateJWT: (() => {}) as never,
        authManager: { getUserDataKey: () => null } as never,
        isNativeAppRequest: () => false,
      } as never,
    );

    handler = routes.get("/totp/disable") as never;
    findById.mockResolvedValue({
      id: "user-1",
      isOidc: false,
      passwordHash: bcrypt.hashSync(PASSWORD, 4),
      totpSecret: secret,
      totpBackupCodes: JSON.stringify(["BACKUP01"]),
      totpEnabled: true,
    });
  });

  function call(body: Record<string, unknown>) {
    const res = {
      statusCode: 200,
      body: undefined as unknown,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json(payload: unknown) {
        this.body = payload;
        return this;
      },
    };
    return handler({ userId: "user-1", body }, res).then(() => res);
  }

  it("accepts the TOTP code on its own", async () => {
    // What the dialog sends: one value, in whichever field the client used.
    const res = await call({
      totp_code: speakeasy.totp({ secret, encoding: "base32" }),
    });

    expect(res.statusCode).toBe(200);
    expect(userUpdate).toHaveBeenCalledWith(
      "user-1",
      expect.objectContaining({ totpEnabled: false, totpSecret: null }),
    );
  });

  it("refuses the account password on its own", async () => {
    // The security guarantee of TOTP is that a stolen password alone can't
    // take over the account; that includes removing the second factor.
    const res = await call({ password: PASSWORD });

    expect(res.statusCode).toBe(400);
    expect(userUpdate).not.toHaveBeenCalled();
  });

  it("accepts a backup code", async () => {
    const res = await call({ totp_code: "BACKUP01" });

    expect(res.statusCode).toBe(200);
  });

  it("refuses a wrong TOTP code", async () => {
    const res = await call({ totp_code: "000000" });

    expect(res.statusCode).toBe(401);
    expect(userUpdate).not.toHaveBeenCalled();
  });

  it("refuses an empty request rather than disabling anything", async () => {
    const res = await call({});

    expect(res.statusCode).toBe(400);
    expect(userUpdate).not.toHaveBeenCalled();
  });

  it("does not let an OIDC user disable it with a password", async () => {
    // No password compare path exists any more; without a TOTP or backup
    // code the request is rejected on shape alone.
    findById.mockResolvedValue({
      id: "user-1",
      isOidc: true,
      passwordHash: null,
      totpSecret: secret,
      totpBackupCodes: JSON.stringify([]),
      totpEnabled: true,
    });

    const res = await call({ password: "anything" });

    expect(res.statusCode).toBe(400);
    expect(userUpdate).not.toHaveBeenCalled();
  });
});
