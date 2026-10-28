import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "access-")), "nested", "access.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();
    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("keeps one CA, and certificates to requests that exist", () => {
    const db = openDb(":memory:");
    const ca = db.prepare("INSERT INTO ca (id, public_key, private_key, created_at) VALUES (?, 'k', 'v1.x.y', 'now')");
    ca.run(1);
    expect(() => ca.run(2)).toThrow(/CHECK/);
    expect(() =>
      db
        .prepare(
          "INSERT INTO certificates (request_id, key_type, fingerprint, principal, valid_after, valid_before, issued_at) VALUES ('missing', 'ssh-ed25519', 'f', 'p', 'a', 'b', 'c')",
        )
        .run(),
    ).toThrow(/FOREIGN KEY/);
  });
});
