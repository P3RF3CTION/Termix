import crypto from "crypto";
import { guacLogger } from "../../utils/logger.js";

export interface GuacamoleConnectionSettings {
  type?: "rdp" | "vnc" | "telnet";
  join?: string;
  readOnly?: boolean;
  guacdHost?: string;
  guacdPort?: number;
  settings: {
    hostname?: string;
    port?: number;
    username?: string;
    password?: string;
    domain?: string;
    width?: number;
    height?: number;
    dpi?: number;
    security?: string;
    "ignore-cert"?: boolean;
    "disable-auth"?: boolean;
    "enable-wallpaper"?: boolean;
    "enable-drive"?: boolean;
    "drive-path"?: string;
    "create-drive-path"?: boolean;
    "swap-red-blue"?: boolean;
    cursor?: string;
    "terminal-type"?: string;
    [key: string]: unknown;
  };
}

export interface TermixGuacMeta {
  termixConnectId: string;
  hostId: number;
  ownerUserId: string;
  protocol: "rdp" | "vnc" | "telnet";
}

export interface GuacamoleToken {
  connection: GuacamoleConnectionSettings;
  recording?: GuacamoleRecordingMetadata;
  termixMeta?: TermixGuacMeta;
}

export interface GuacamoleRecordingMetadata {
  hostId: number;
  userId: string;
  protocol: "rdp" | "vnc" | "telnet";
  path: string;
  /** Directory guacd was told to write into; differs from the backend's view
   * when guacd runs in its own container. */
  guacdPath?: string;
  startedAt: string;
}

const CIPHER = "aes-256-cbc";
const KEY_LENGTH = 32;

export class GuacamoleTokenService {
  private static instance: GuacamoleTokenService;
  private encryptionKey: Buffer;

  private constructor() {
    this.encryptionKey = this.initializeKey();
  }

  static getInstance(): GuacamoleTokenService {
    if (!GuacamoleTokenService.instance) {
      GuacamoleTokenService.instance = new GuacamoleTokenService();
    }
    return GuacamoleTokenService.instance;
  }

  /**
   * Guacamole tokens carry plaintext RDP/VNC/Telnet passwords, so they need
   * a persistent key of their own. The pre-hardening default was
   * `sha256(JWT_SECRET + "_guacamole")`, which coupled two independent
   * secrets (leaking either one broke both), and the fallback was a
   * per-process `randomBytes` that invalidated every token on every restart.
   *
   * Now: honour `GUACAMOLE_ENCRYPTION_KEY` when set, otherwise HKDF-derive a
   * key from the persistent system `ENCRYPTION_KEY` with an explicit
   * "guacamole" context. That key survives restarts, lives in the same
   * `.env` under 0600, and is unrelated to JWT_SECRET, so rotating JWT
   * no longer voids in-flight Guacamole sessions.
   *
   * `ENCRYPTION_KEY` is populated during SystemCrypto's boot phase in
   * `starter.ts`, which runs before Guacamole is loaded, so reading it here
   * is safe.
   */
  private initializeKey(): Buffer {
    const existingKey = process.env.GUACAMOLE_ENCRYPTION_KEY;
    if (existingKey) {
      if (existingKey.length === 64 && /^[0-9a-fA-F]+$/.test(existingKey)) {
        return Buffer.from(existingKey, "hex");
      }
      if (existingKey.length === KEY_LENGTH) {
        return Buffer.from(existingKey, "utf8");
      }
      guacLogger.warn(
        "GUACAMOLE_ENCRYPTION_KEY has an unexpected length; deriving from ENCRYPTION_KEY instead",
        { operation: "guac_key_env_invalid" },
      );
    }

    const systemKey = process.env.ENCRYPTION_KEY;
    if (systemKey && systemKey.length >= 64) {
      return Buffer.from(
        crypto.hkdfSync(
          "sha256",
          Buffer.from(systemKey, "hex"),
          Buffer.alloc(0),
          "termix:guacamole-token-key:v1",
          KEY_LENGTH,
        ),
      );
    }

    // If we reach this branch the system key isn't ready yet -- that is a
    // startup-order bug, not a runtime input error, since starter.ts calls
    // SystemCrypto.initializeEncryptionKey() before importing this module.
    // Emit a loud warning and fall back to a per-process random key so we
    // can at least start; do NOT fall back to JWT_SECRET, which was the
    // whole class of coupling we're trying to remove.
    guacLogger.error(
      "ENCRYPTION_KEY not available while initialising Guacamole key -- Guacamole tokens will not survive restart",
      undefined,
      { operation: "guac_key_no_system_key" },
    );
    return crypto.randomBytes(KEY_LENGTH);
  }

  getEncryptionKey(): Buffer {
    return this.encryptionKey;
  }

  encryptToken(tokenObject: GuacamoleToken): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(CIPHER, this.encryptionKey, iv);

    let encrypted = cipher.update(
      JSON.stringify(tokenObject),
      "utf8",
      "base64",
    );
    encrypted += cipher.final("base64");

    const data = {
      iv: iv.toString("base64"),
      value: encrypted,
    };

    return Buffer.from(JSON.stringify(data)).toString("base64");
  }

  decryptToken(token: string): GuacamoleToken | null {
    try {
      const data = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
      const iv = Buffer.from(data.iv, "base64");
      const decipher = crypto.createDecipheriv(CIPHER, this.encryptionKey, iv);

      let decrypted = decipher.update(data.value, "base64", "utf8");
      decrypted += decipher.final("utf8");

      return JSON.parse(decrypted) as GuacamoleToken;
    } catch (error) {
      guacLogger.error("Failed to decrypt guacamole token", error, {
        operation: "guac_token_decrypt_error",
      });
      return null;
    }
  }

  createRdpToken(
    hostname: string,
    username: string,
    password: string,
    options: Partial<GuacamoleConnectionSettings["settings"]> & {
      guacdHost?: string;
      guacdPort?: number;
    } = {},
    recording?: GuacamoleRecordingMetadata,
    termixMeta?: TermixGuacMeta,
  ): string {
    const { guacdHost, guacdPort, ...settingsOptions } = options;
    const token: GuacamoleToken = {
      connection: {
        type: "rdp",
        ...(guacdHost ? { guacdHost } : {}),
        ...(guacdPort ? { guacdPort } : {}),
        settings: {
          hostname,
          ...(username ? { username } : {}),
          ...(password ? { password } : {}),
          port: 3389,
          "ignore-cert": true,
          ...(!username && !password ? { "disable-auth": true } : {}),
          ...settingsOptions,
        },
      },
      recording,
      termixMeta,
    };
    return this.encryptToken(token);
  }

  createVncToken(
    hostname: string,
    username?: string,
    password?: string,
    options: Partial<GuacamoleConnectionSettings["settings"]> & {
      guacdHost?: string;
      guacdPort?: number;
    } = {},
    recording?: GuacamoleRecordingMetadata,
    termixMeta?: TermixGuacMeta,
  ): string {
    const { guacdHost, guacdPort, ...settingsOptions } = options;
    const token: GuacamoleToken = {
      connection: {
        type: "vnc",
        ...(guacdHost ? { guacdHost } : {}),
        ...(guacdPort ? { guacdPort } : {}),
        settings: {
          hostname,
          ...(username ? { username } : {}),
          password,
          port: 5900,
          ...settingsOptions,
        },
      },
      recording,
      termixMeta,
    };
    return this.encryptToken(token);
  }

  createTelnetToken(
    hostname: string,
    username?: string,
    password?: string,
    options: Partial<GuacamoleConnectionSettings["settings"]> & {
      guacdHost?: string;
      guacdPort?: number;
    } = {},
    recording?: GuacamoleRecordingMetadata,
    termixMeta?: TermixGuacMeta,
  ): string {
    const { guacdHost, guacdPort, ...settingsOptions } = options;
    const token: GuacamoleToken = {
      connection: {
        type: "telnet",
        ...(guacdHost ? { guacdHost } : {}),
        ...(guacdPort ? { guacdPort } : {}),
        settings: {
          hostname,
          username,
          password,
          port: 23,
          ...settingsOptions,
        },
      },
      recording,
      termixMeta,
    };
    return this.encryptToken(token);
  }

  // join tokens never carry recording params - only the primary connection's
  // token should write recording-path/recording-name to guacd.
  createJoinToken(guacamoleConnectionId: string, readOnly: boolean): string {
    const token: GuacamoleToken = {
      connection: {
        join: guacamoleConnectionId,
        readOnly,
        settings: {},
      },
    };
    return this.encryptToken(token);
  }
}
