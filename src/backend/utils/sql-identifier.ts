/**
 * SQLite identifier quoting.
 *
 * Table and column names cannot be bound as statement parameters - only values
 * can - so any query built around a dynamic table or column has to interpolate
 * that name into the SQL string. Interpolating it raw means the name is
 * executed as SQL, which is the pattern static analysis flags as SQL injection
 * even when the name comes from a trusted place such as `sqlite_master` or a
 * `PRAGMA` result.
 *
 * Quoting closes that gap independently of where the name came from: inside
 * double quotes SQLite treats the text as a single identifier, and doubling an
 * embedded quote (the SQL standard escape) means no input can terminate the
 * identifier early and append SQL of its own.
 */

/** Identifiers SQLite accepts unquoted - letters, digits, underscore, `$`. */
const PLAIN_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]*$/;

/**
 * Quote a single SQLite identifier (table, column, index, ...) for safe
 * interpolation into a query string.
 *
 * Throws on an empty name or one containing a NUL byte: both mean the caller
 * passed something that is not an identifier at all, and failing loudly beats
 * emitting a query whose shape nobody intended.
 */
export function quoteIdent(name: string): string {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("SQL identifier must be a non-empty string");
  }
  if (name.includes("\0")) {
    throw new Error("SQL identifier must not contain a NUL byte");
  }
  return `"${name.replace(/"/g, '""')}"`;
}

/** Quote a list of identifiers and join them, e.g. for a column list. */
export function quoteIdentList(names: string[], separator = ", "): string {
  return names.map(quoteIdent).join(separator);
}

/**
 * Whether a name would be a valid bare identifier. Useful where a caller wants
 * to reject an unexpected name outright rather than quote it - for instance
 * when the name is supposed to come from a fixed allow-list.
 */
export function isPlainIdentifier(name: string): boolean {
  return typeof name === "string" && PLAIN_IDENTIFIER.test(name);
}
