import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { quoteIdent, quoteIdentList } from "../../utils/sql-identifier.js";

describe("sql identifier quoting", () => {
  it("wraps plain names in double quotes", () => {
    expect(quoteIdent("ssh_data")).toBe('"ssh_data"');
    expect(quoteIdentList(["id", "user_id"])).toBe('"id", "user_id"');
  });

  it("doubles embedded quotes so a name cannot end the identifier", () => {
    expect(quoteIdent('x" ; DROP TABLE users; --')).toBe(
      '"x"" ; DROP TABLE users; --"',
    );
  });

  it("refuses empty names and NUL bytes", () => {
    expect(() => quoteIdent("")).toThrow();
    expect(() => quoteIdent("a\0b")).toThrow();
  });

  it("keeps SQLite treating quoted and bare names alike", () => {
    const db = new Database(":memory:");
    try {
      db.exec("CREATE TABLE users (id INTEGER, name TEXT)");
      db.prepare(
        `INSERT INTO ${quoteIdent("users")} (${quoteIdentList(["id", "name"])}) VALUES (?, ?)`,
      ).run(1, "a");
      expect(
        db.prepare(`SELECT COUNT(*) AS n FROM ${quoteIdent("users")}`).get(),
      ).toEqual({ n: 1 });
      // A hostile name is one identifier that does not exist, not two
      // statements.
      expect(() =>
        db
          .prepare(`SELECT * FROM ${quoteIdent("users; DELETE FROM users")}`)
          .all(),
      ).toThrow(/no such table/);
      expect(db.prepare("SELECT COUNT(*) AS n FROM users").get()).toEqual({
        n: 1,
      });
    } finally {
      db.close();
    }
  });
});
