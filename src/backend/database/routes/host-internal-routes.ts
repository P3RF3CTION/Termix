import type { Request, Response, Router } from "express";
import { timingSafeEqual } from "node:crypto";
import { SystemCrypto } from "../../utils/system-crypto.js";
import { sshLogger } from "../../utils/logger.js";
import { createCurrentHostResolutionRepository } from "../repositories/factory.js";

/**
 * The internal token is compared byte-wise with early exit if `===` is used,
 * which is measurable over the network with enough samples. `timingSafeEqual`
 * refuses buffers of different lengths, so the length check happens first --
 * cheap, and it also short-circuits the trivial "not even the right shape"
 * case without leaking anything a client could not already learn from a
 * missing header.
 */
function internalTokensEqual(
  provided: unknown,
  expected: string | undefined | null,
): boolean {
  if (typeof provided !== "string" || typeof expected !== "string")
    return false;
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function registerHostInternalRoutes(router: Router): void {
  /**
   * @openapi
   * /host/db/host/internal:
   *   get:
   *     summary: Get internal SSH host data
   *     description: Returns internal SSH host data for autostart tunnels. Requires internal auth token.
   *     tags:
   *       - SSH
   *     responses:
   *       200:
   *         description: A list of autostart hosts.
   *       403:
   *         description: Forbidden.
   *       500:
   *         description: Failed to fetch autostart SSH data.
   */
  router.get("/db/host/internal", async (req: Request, res: Response) => {
    try {
      const internalToken = req.headers["x-internal-auth-token"];
      const systemCrypto = SystemCrypto.getInstance();
      const expectedToken = await systemCrypto.getInternalAuthToken();

      if (!internalTokensEqual(internalToken, expectedToken)) {
        sshLogger.warn(
          "Unauthorized attempt to access internal SSH host endpoint",
          {
            source: req.ip,
            userAgent: req.headers["user-agent"],
            providedToken: internalToken ? "present" : "missing",
          },
        );
        return res.status(403).json({ error: "Forbidden" });
      }
    } catch (error) {
      sshLogger.error("Failed to validate internal auth token", error);
      return res.status(500).json({ error: "Internal server error" });
    }

    try {
      const autostartHosts =
        await createCurrentHostResolutionRepository().listHostsWithTunnelConnections();

      const result = autostartHosts
        .map((host) => {
          const tunnelConnections = host.tunnelConnections
            ? JSON.parse(host.tunnelConnections)
            : [];

          const hasAutoStartTunnels = tunnelConnections.some(
            (tunnel: Record<string, unknown>) => tunnel.autoStart,
          );

          if (!hasAutoStartTunnels) {
            return null;
          }

          return {
            id: host.id,
            userId: host.userId,
            name: host.name || `autostart-${host.id}`,
            ip: host.ip,
            port: host.port,
            username: host.username,
            authType: host.authType,
            keyType: host.keyType,
            credentialId: host.credentialId,
            enableTunnel: true,
            tunnelConnections: tunnelConnections.filter(
              (tunnel: Record<string, unknown>) => tunnel.autoStart,
            ),
            pin: !!host.pin,
            enableTerminal: !!host.enableTerminal,
            enableFileManager: host.enableFileManager !== false,
            showTerminalInSidebar: !!host.showTerminalInSidebar,
            showFileManagerInSidebar: !!host.showFileManagerInSidebar,
            showTunnelInSidebar: !!host.showTunnelInSidebar,
            showDockerInSidebar: !!host.showDockerInSidebar,
            showServerStatsInSidebar: !!host.showServerStatsInSidebar,
            tags: ["autostart"],
          };
        })
        .filter(Boolean);

      res.json(result);
    } catch (err) {
      sshLogger.error("Failed to fetch autostart SSH data", err);
      res.status(500).json({ error: "Failed to fetch autostart SSH data" });
    }
  });

  /**
   * @openapi
   * /host/db/host/internal/all:
   *   get:
   *     summary: Get all internal SSH host data
   *     description: Returns all internal SSH host data. Requires internal auth token.
   *     tags:
   *       - SSH
   *     responses:
   *       200:
   *         description: A list of all hosts.
   *       401:
   *         description: Invalid or missing internal authentication token.
   *       500:
   *         description: Failed to fetch all hosts.
   */
  router.get("/db/host/internal/all", async (req: Request, res: Response) => {
    try {
      const internalToken = req.headers["x-internal-auth-token"];
      if (!internalToken) {
        return res
          .status(401)
          .json({ error: "Internal authentication token required" });
      }

      const systemCrypto = SystemCrypto.getInstance();
      const expectedToken = await systemCrypto.getInternalAuthToken();

      if (!internalTokensEqual(internalToken, expectedToken)) {
        return res
          .status(401)
          .json({ error: "Invalid internal authentication token" });
      }

      const allHosts =
        await createCurrentHostResolutionRepository().listAllHosts();

      const result = allHosts.map((host) => {
        const tunnelConnections = host.tunnelConnections
          ? JSON.parse(host.tunnelConnections)
          : [];

        return {
          id: host.id,
          userId: host.userId,
          name: host.name || `${host.username}@${host.ip}`,
          ip: host.ip,
          port: host.port,
          username: host.username,
          authType: host.authType,
          keyType: host.keyType,
          credentialId: host.credentialId,
          enableTunnel: !!host.enableTunnel,
          tunnelConnections: tunnelConnections,
          pin: !!host.pin,
          enableTerminal: !!host.enableTerminal,
          enableFileManager: host.enableFileManager !== false,
          showTerminalInSidebar: !!host.showTerminalInSidebar,
          showFileManagerInSidebar: !!host.showFileManagerInSidebar,
          showTunnelInSidebar: !!host.showTunnelInSidebar,
          showDockerInSidebar: !!host.showDockerInSidebar,
          showServerStatsInSidebar: !!host.showServerStatsInSidebar,
          defaultPath: host.defaultPath,
          createdAt: host.createdAt,
          updatedAt: host.updatedAt,
        };
      });

      res.json(result);
    } catch (err) {
      sshLogger.error("Failed to fetch all hosts for internal use", err);
      res.status(500).json({ error: "Failed to fetch all hosts" });
    }
  });
}
