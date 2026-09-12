import { randomInt, timingSafeEqual } from "node:crypto";
import bcrypt from "bcryptjs";

/**
 * Alphabet for TOTP backup codes. Kept to [0-9A-Z] so the codes look and
 * behave exactly like the ones this app has always issued (8 uppercase
 * alphanumerics) - only the source of randomness changes.
 */
const BACKUP_CODE_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

export const BACKUP_CODE_LENGTH = 8;
export const BACKUP_CODE_COUNT = 8;

/**
 * Backup codes are a full second-factor bypass, so they must come from a
 * CSPRNG. `Math.random()` is seeded per-process and its internal xorshift128+
 * state is recoverable from a handful of outputs, which means one leaked code
 * would expose the other seven generated in the same call - and a code is not
 * always 8 characters long either, because `toString(36)` drops trailing
 * zeroes.
 */
export function generateBackupCode(
  length: number = BACKUP_CODE_LENGTH,
): string {
  let code = "";
  for (let i = 0; i < length; i += 1) {
    code += BACKUP_CODE_ALPHABET[randomInt(BACKUP_CODE_ALPHABET.length)];
  }
  return code;
}

export function generateBackupCodes(
  count: number = BACKUP_CODE_COUNT,
): string[] {
  return Array.from({ length: count }, () => generateBackupCode());
}

/**
 * A recognizable bcrypt digest starts with $2a$, $2b$, or $2y$ followed by the
 * cost and 22 base64 salt chars, and is exactly 60 characters long. Used to
 * tell hashed backup codes apart from legacy plaintext entries during the
 * verify path -- new codes are always hashed on write, but stored columns
 * from before this change still hold the raw code.
 */
const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

function looksHashed(value: string): boolean {
  return typeof value === "string" && BCRYPT_HASH_PATTERN.test(value);
}

/**
 * Backup codes are a full 2FA bypass, so a stolen database or backup that
 * exposes the raw column must not immediately hand the attacker eight working
 * codes -- they must fall back to online guessing against the login rate
 * limiter. Bcrypt at cost 12 gives ~250ms per guess on the target hardware,
 * which combined with the 5-attempt/10-minute lockout makes exhaustion of a
 * 36^8 (~2.8T) code space infeasible. Field-level encryption still wraps the
 * JSON array on top; the hash is the second line of defense.
 */
const BACKUP_CODE_BCRYPT_COST = 12;

export function hashBackupCode(code: string): string {
  return bcrypt.hashSync(code, BACKUP_CODE_BCRYPT_COST);
}

export function hashBackupCodes(codes: string[]): string[] {
  return codes.map(hashBackupCode);
}

/**
 * Returns the index of the matching entry, or -1. Accepts either bcrypt
 * digests (new format, produced by hashBackupCode) or plaintext strings
 * (legacy format from before this change) in the stored array. Every entry
 * is inspected so a stolen partial code list cannot be enumerated by
 * timing.
 */
export function findMatchingBackupCode(
  stored: unknown,
  submitted: string,
): number {
  if (!Array.isArray(stored) || typeof submitted !== "string") return -1;
  let match = -1;
  for (let i = 0; i < stored.length; i += 1) {
    const entry = stored[i];
    if (typeof entry !== "string") continue;
    if (looksHashed(entry)) {
      if (bcrypt.compareSync(submitted, entry) && match === -1) {
        match = i;
      }
      continue;
    }
    // Legacy plaintext entry. Constant-length equality by buffering both
    // sides -- string === in V8 short-circuits on the first differing byte.
    const submittedBuf = Buffer.from(submitted, "utf8");
    const entryBuf = Buffer.from(entry, "utf8");
    if (
      submittedBuf.length === entryBuf.length &&
      timingSafeEqual(submittedBuf, entryBuf) &&
      match === -1
    ) {
      match = i;
    }
  }
  return match;
}
