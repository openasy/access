import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- The certificate authority every certificate is signed by (ADR 0061). One row; its private key is sealed with the
   -- install's key (ADR 0021), and servers trust its public key in TrustedUserCAKeys.
   CREATE TABLE ca (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     public_key TEXT NOT NULL,
     private_key TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   -- A server people may ask for, with its policy: the logins one may ask for, the longest grant and how many people
   -- other than the requester must approve.
   CREATE TABLE servers (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     address TEXT NOT NULL,
     port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
     description TEXT NOT NULL DEFAULT '',
     logins TEXT NOT NULL,
     max_minutes INTEGER NOT NULL CHECK (max_minutes > 0),
     approvals INTEGER NOT NULL CHECK (approvals IN (1, 2)),
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   -- A request and, once approved, the grant it became. The server's name is kept, so the record still reads when the
   -- server is removed.
   CREATE TABLE requests (
     id TEXT PRIMARY KEY,
     server_id TEXT NOT NULL,
     server_name TEXT NOT NULL,
     login TEXT NOT NULL,
     minutes INTEGER NOT NULL CHECK (minutes > 0),
     reason TEXT NOT NULL,
     ticket TEXT NOT NULL DEFAULT '',
     requester_id TEXT NOT NULL,
     requester_email TEXT NOT NULL,
     requester_name TEXT NOT NULL,
     approvals_needed INTEGER NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'ended', 'denied', 'cancelled', 'revoked')),
     created_at TEXT NOT NULL,
     starts_at TEXT,
     ends_at TEXT,
     -- Who denied, cancelled, ended or revoked it, and why; "Access" when it ran out.
     closed_by TEXT,
     closed_at TEXT,
     close_comment TEXT
   );
   CREATE INDEX requests_status ON requests (status, ends_at);
   CREATE TABLE approvals (
     request_id TEXT NOT NULL REFERENCES requests (id),
     approver_id TEXT NOT NULL,
     approver_email TEXT NOT NULL,
     approver_name TEXT NOT NULL,
     comment TEXT NOT NULL DEFAULT '',
     at TEXT NOT NULL,
     PRIMARY KEY (request_id, approver_id)
   );
   -- Every certificate issued. The serial is never reused: a revocation list names certificates by it.
   CREATE TABLE certificates (
     serial INTEGER PRIMARY KEY AUTOINCREMENT,
     request_id TEXT NOT NULL REFERENCES requests (id),
     key_type TEXT NOT NULL,
     fingerprint TEXT NOT NULL,
     principal TEXT NOT NULL,
     valid_after TEXT NOT NULL,
     valid_before TEXT NOT NULL,
     issued_at TEXT NOT NULL
   );
   CREATE INDEX certificates_request ON certificates (request_id);
   CREATE INDEX certificates_valid ON certificates (valid_before);
   -- Every request, approval, certificate, change and sign-in (ADR 0013). Rows are added, never changed or removed.
   CREATE TABLE audit (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     at TEXT NOT NULL,
     actor TEXT NOT NULL,
     action TEXT NOT NULL,
     target TEXT NOT NULL,
     result TEXT NOT NULL CHECK (result IN ('success', 'denied')),
     detail TEXT NOT NULL DEFAULT '',
     request_id TEXT
   );
   CREATE INDEX audit_action ON audit (action);
   CREATE INDEX audit_request ON audit (request_id);
   CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
   CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
