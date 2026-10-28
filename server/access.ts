import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { atLeast, type AuthEvent, type Role } from "@openasy/auth";
import type { Keyring } from "./kek.ts";
import { generateCa, KeyError, loadCa, parsePublicKey, revocationList, signCertificate, type Ca } from "./ssh.ts";

export type ProblemCode = "invalid-json" | "invalid-body" | "not-found" | "conflict" | "forbidden" | "mfa-required" | "payload-too-large" | "internal-error";

export class AccessError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

const bad = (detail: string) => new AccessError(422, "invalid-body", detail);
const notFound = (what: string) => new AccessError(404, "not-found", `${what} does not exist.`);
const conflict = (detail: string) => new AccessError(409, "conflict", detail);
const forbidden = (detail: string) => new AccessError(403, "forbidden", detail);

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** Certificates start a minute early, for clocks a little behind. */
const CLOCK_SKEW_MS = MINUTE;
/** A grant gets at most this many certificates: one per computer someone works from, with room to spare. */
const CERTIFICATES_PER_GRANT = 10;
/** The longest grant a server's policy may allow. */
const MAX_GRANT_MINUTES = 24 * 60;
/** What a certificate lets its holder do besides log in: a terminal, and nothing else (no forwarding). */
const EXTENSIONS = ["permit-pty"];

export interface Person {
  id: string;
  email: string;
  name: string;
}

/** Who is calling, as app.ts knows it from the session or token. */
export interface Actor {
  /** The signed-in person; undefined for an API token, which can never ask for, approve or use access. */
  person?: Person;
  /** For the record: the person's name and email, or the token's name. */
  name: string;
  role: Role;
  /** Signed in with a second factor, or through an identity provider, which asks for its own (ADR 0002). */
  mfa: boolean;
}

export interface Server {
  id: string;
  name: string;
  address: string;
  port: number;
  description: string;
  /** The Unix accounts on the server one may ask to log in as. */
  logins: string[];
  maxMinutes: number;
  /** How many people other than the requester must approve. */
  approvals: 1 | 2;
  createdAt: string;
  updatedAt: string;
  /** Grants open on it now. */
  active: number;
}

export type RequestStatus = "pending" | "active" | "ended" | "denied" | "cancelled" | "revoked";

export interface Approval {
  by: Person;
  comment: string;
  at: string;
}

export interface AccessRequest {
  id: string;
  server: { id: string; name: string };
  login: string;
  /** What certificates for this grant carry, and the server's principals file lists: login@server. */
  principal: string;
  minutes: number;
  reason: string;
  ticket: string;
  requester: Person;
  status: RequestStatus;
  createdAt: string;
  startsAt: string | null;
  endsAt: string | null;
  approvalsNeeded: number;
  approvals: Approval[];
  closed: { by: string; at: string; comment: string } | null;
}

export interface Certificate {
  serial: number;
  keyType: string;
  fingerprint: string;
  principal: string;
  validAfter: string;
  validBefore: string;
  issuedAt: string;
  /** Ended before it expired: on the revocation list until it would have. */
  revoked: boolean;
}

export interface AuditEvent {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  result: "success" | "denied";
  detail: string;
  requestId: string | null;
}

export interface AccessOptions {
  keyring: Keyring;
  /** The address people open Access at; servers fetch the revocation list from it. */
  publicUrl: string;
  /** A request nobody has approved after this long is cancelled. */
  pendingHours?: number;
  /** Every event written to the audit log, the CA's first among them, for the structured log (ADR 0017). */
  onEvent?: (e: AuditEvent) => void;
  clock?: () => number;
}

type Row = Record<string, SQLInputValue>;

const text = (v: unknown, name: string, max: number, required = true): string => {
  if (v === undefined || v === null || v === "") {
    if (required) throw bad(`${name} is required.`);
    return "";
  }
  if (typeof v !== "string") throw bad(`${name} must be text.`);
  const t = v.trim();
  if (required && !t) throw bad(`${name} is required.`);
  if (t.length > max) throw bad(`${name} is at most ${max} characters.`);
  return t;
};

const whole = (v: unknown, name: string, min: number, max: number, fallback?: number): number => {
  if (v === undefined && fallback !== undefined) return fallback;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw bad(`${name} must be a whole number from ${min} to ${max}.`);
  return v;
};

/** A server's name goes into every principal, login@name, so it is kept to what a host name may hold. */
const SERVER_NAME = /^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$/;
/** A Unix account name, as useradd takes it by default. */
const LOGIN = /^[a-z_][a-z0-9_-]{0,31}$/;
/** A host name, an IPv4 address or an IPv6 address. */
const ADDRESS = /^([A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9a-fA-F:]{2,39})$/;

const STATUSES: RequestStatus[] = ["pending", "active", "ended", "denied", "cancelled", "revoked"];

/** The kinds of event the audit screen filters by: the start of each action's name. */
export const AUDIT_KINDS = ["request", "grant", "certificate", "server", "ca", "auth"] as const;

const minutesText = (m: number) => (m % 60 === 0 ? `${m / 60} h` : m > 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min`);

/** A cell of the CSV export, quoted, and kept from being read as a formula by a spreadsheet. */
const csvCell = (v: string | number | null) => {
  const s = v === null ? "" : String(v);
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replaceAll('"', '""')}"`;
};

export function createAccess(db: DatabaseSync, { keyring, publicUrl, pendingHours = 24, onEvent, clock = Date.now }: AccessOptions) {
  const iso = (ms = clock()) => new Date(ms).toISOString();
  const page = publicUrl.replace(/\/$/, "");

  // ---------------------------------------------------------------- the record (ADR 0013)

  const insertEvent = db.prepare("INSERT INTO audit (at, actor, action, target, result, detail, request_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
  /** Writes one event to the append-only audit log, and hands it to onEvent. */
  function record(actor: string, action: string, target: string, opts: { result?: "success" | "denied"; detail?: string; requestId?: string } = {}) {
    const event = { at: iso(), actor, action, target, result: opts.result ?? "success", detail: opts.detail ?? "", requestId: opts.requestId ?? null };
    const r = insertEvent.run(event.at, event.actor, event.action, event.target, event.result, event.detail, event.requestId);
    onEvent?.({ id: Number(r.lastInsertRowid), ...event });
  }
  const who = (a: Actor) => (a.person ? `${a.person.name} <${a.person.email}>` : a.name);

  /** Sign-ins, failures and changes to members and tokens from @openasy/auth, which names people by their id. */
  function recordAuth(event: AuthEvent) {
    const person = (id?: string) => {
      const u = id ? (db.prepare("SELECT name, email FROM auth_users WHERE id = ?").get(id) as { name: string; email: string } | undefined) : undefined;
      return u ? `${u.name} <${u.email}>` : (id ?? "");
    };
    record(person(event.actor) || "unknown", `auth.${event.type}`, person(event.target ?? event.actor), {
      result: event.type === "sign-in-failed" ? "denied" : "success",
      detail: [event.method, event.detail, `from ${event.ip}`].filter(Boolean).join(", "),
    });
  }

  // ---------------------------------------------------------------- the certificate authority

  /** The CA, made on first start. A different key cannot open it, and Access does not start then (ADR 0021). */
  let ca: Ca;
  const caRow = db.prepare("SELECT * FROM ca WHERE id = 1").get() as Row | undefined;
  if (caRow) {
    try {
      ca = loadCa(keyring.open(caRow.private_key as string).toString("utf8"));
    } catch {
      throw new Error("the Access CA cannot be opened with this key-encryption key: mount the key it was sealed with");
    }
  } else {
    const made = generateCa();
    db.prepare("INSERT INTO ca (id, public_key, private_key, created_at) VALUES (1, ?, ?, ?)").run(made.publicKey, keyring.seal(made.privateKeyPem), iso());
    ca = loadCa(made.privateKeyPem);
    record("Access", "ca.create", ca.fingerprint, { detail: "Ed25519 certificate authority made on first start" });
  }
  const caPublicKey = (db.prepare("SELECT public_key FROM ca WHERE id = 1").get() as { public_key: string }).public_key;
  const caInfo = () => {
    const r = db.prepare("SELECT created_at FROM ca WHERE id = 1").get() as { created_at: string };
    return { publicKey: caPublicKey, fingerprint: ca.fingerprint, createdAt: r.created_at };
  };

  // ---------------------------------------------------------------- time: grants end, requests lapse

  /** Ends the grants whose time is up and cancels the requests nobody approved in time; every read starts with it. */
  function expire(): number {
    const now = iso();
    const ended = db.prepare("SELECT id, server_name, login FROM requests WHERE status = 'active' AND ends_at <= ?").all(now) as Row[];
    for (const r of ended) {
      db.prepare("UPDATE requests SET status = 'ended', closed_by = 'Access', closed_at = ends_at, close_comment = 'Its time ran out.' WHERE id = ?").run(
        r.id as string,
      );
      record("Access", "grant.end", `${r.login}@${r.server_name}`, { detail: "Its time ran out.", requestId: r.id as string });
    }
    const lapsed = db
      .prepare("SELECT id, server_name, login FROM requests WHERE status = 'pending' AND created_at <= ?")
      .all(iso(clock() - pendingHours * HOUR)) as Row[];
    for (const r of lapsed) {
      const why = `Nobody approved it within ${pendingHours} hours.`;
      db.prepare("UPDATE requests SET status = 'cancelled', closed_by = 'Access', closed_at = ?, close_comment = ? WHERE id = ?").run(now, why, r.id as string);
      record("Access", "request.lapse", `${r.login}@${r.server_name}`, { detail: why, requestId: r.id as string });
    }
    return ended.length + lapsed.length;
  }

  // ---------------------------------------------------------------- servers and their policies

  const toServer = (r: Row): Server => ({
    id: r.id as string,
    name: r.name as string,
    address: r.address as string,
    port: Number(r.port),
    description: r.description as string,
    logins: JSON.parse(r.logins as string) as string[],
    maxMinutes: Number(r.max_minutes),
    approvals: Number(r.approvals) as 1 | 2,
    createdAt: r.created_at as string,
    updatedAt: r.updated_at as string,
    active: Number(r.active ?? 0),
  });
  const SERVER_SELECT = "SELECT s.*, (SELECT COUNT(*) FROM requests q WHERE q.server_id = s.id AND q.status = 'active') AS active FROM servers s";
  const serverRow = (id: string) => db.prepare(`${SERVER_SELECT} WHERE s.id = ?`).get(id) as Row | undefined;

  function servers(): Server[] {
    expire();
    return (db.prepare(`${SERVER_SELECT} ORDER BY s.name`).all() as Row[]).map(toServer);
  }

  function server(id: string): Server {
    expire();
    const r = serverRow(id);
    if (!r) throw notFound("The server");
    return toServer(r);
  }

  function saveServer(id: string | null, body: Record<string, unknown>, actor: Actor): Server {
    const existing = id ? serverRow(id) : undefined;
    if (id && !existing) throw notFound("The server");
    const name = text(body.name, "name", 63).toLowerCase();
    if (!SERVER_NAME.test(name)) throw bad("name is a host name: lower-case letters, digits, dots and dashes, such as api-prod-03.");
    const address = text(body.address, "address", 253);
    if (!ADDRESS.test(address)) throw bad("address is a host name or an IP address, without a port or user.");
    const port = whole(body.port, "port", 1, 65_535, 22);
    const description = text(body.description, "description", 200, false);
    if (!Array.isArray(body.logins) || !body.logins.length || body.logins.length > 16) throw bad("logins is a list of 1 to 16 accounts on the server.");
    const logins = [...new Set(body.logins.map((l, i) => text(l, `logins[${i}]`, 32)))];
    for (const l of logins) if (!LOGIN.test(l)) throw bad(`${l} is not a Unix account name.`);
    const maxMinutes = whole(body.maxMinutes, "maxMinutes", 5, MAX_GRANT_MINUTES, 60);
    const approvals = whole(body.approvals, "approvals", 1, 2, 1) as 1 | 2;
    const clash = db.prepare("SELECT id FROM servers WHERE name = ? AND id != ?").get(name, id ?? "") as Row | undefined;
    if (clash) throw conflict(`There is already a server named ${name}.`);
    const now = iso();
    if (existing) {
      // A rename would change the principal of grants open now and lock their certificates out.
      if (name !== existing.name && Number(existing.active)) throw conflict("The server has grants open now; rename it once they have ended.");
      db.prepare(
        "UPDATE servers SET name = ?, address = ?, port = ?, description = ?, logins = ?, max_minutes = ?, approvals = ?, updated_at = ? WHERE id = ?",
      ).run(name, address, port, description, JSON.stringify(logins), maxMinutes, approvals, now, id!);
    } else {
      id = randomUUID();
      db.prepare(
        "INSERT INTO servers (id, name, address, port, description, logins, max_minutes, approvals, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(id, name, address, port, description, JSON.stringify(logins), maxMinutes, approvals, now, now);
    }
    record(who(actor), existing ? "server.update" : "server.create", name, {
      detail: `${address}:${port}, logins ${logins.join(", ")}, at most ${minutesText(maxMinutes)}, ${approvals} approval${approvals > 1 ? "s" : ""}`,
    });
    return server(id!);
  }

  function deleteServer(id: string, actor: Actor) {
    expire();
    const r = serverRow(id);
    if (!r) throw notFound("The server");
    const open = db.prepare("SELECT COUNT(*) AS n FROM requests WHERE server_id = ? AND status IN ('pending', 'active')").get(id) as { n: number };
    if (open.n) throw conflict("The server has requests waiting or grants open; deny or end them first.");
    db.prepare("DELETE FROM servers WHERE id = ?").run(id);
    record(who(actor), "server.delete", r.name as string);
  }

  /** What an admin runs once on the server, as root, for it to trust the Access CA for its own logins only. */
  function serverSetup(id: string): string {
    const s = server(id);
    const krl = `${page}/api/v1/revoked.krl`;
    return [
      `# Run as root on ${s.name}. It trusts the Access CA for the logins below only, on this server only, and reloads sshd.`,
      "# The accounts must exist. Keys in authorized_keys still work: remove them, or nothing has changed (ADR 0061).",
      `echo '${caPublicKey}' > /etc/ssh/openasy_access_ca.pub`,
      "install -d -m 755 /etc/ssh/openasy_access_principals",
      ...s.logins.map((l) => `echo '${l}@${s.name}' > /etc/ssh/openasy_access_principals/${l}`),
      "# Certificates ended early are refused within a minute. sshd refuses every key when this file is missing.",
      `curl -sf -o /etc/ssh/openasy_access_revoked.krl ${krl}`,
      "if [ -d /etc/cron.d ]; then",
      `  echo '* * * * * root curl -sf -o /etc/ssh/openasy_access_revoked.krl.new ${krl} && mv /etc/ssh/openasy_access_revoked.krl.new /etc/ssh/openasy_access_revoked.krl' > /etc/cron.d/openasy-access`,
      "else",
      `  echo 'No cron here: fetch ${krl} every minute some other way, or revoked certificates work until they expire.' >&2`,
      "fi",
      "cat > /etc/ssh/sshd_config.d/openasy-access.conf <<'OPENASY'",
      "TrustedUserCAKeys /etc/ssh/openasy_access_ca.pub",
      "AuthorizedPrincipalsFile /etc/ssh/openasy_access_principals/%u",
      "RevokedKeys /etc/ssh/openasy_access_revoked.krl",
      "OPENASY",
      "sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)",
      "",
    ].join("\n");
  }

  // ---------------------------------------------------------------- requests and grants

  const approvalsOf = (id: string): Approval[] =>
    (db.prepare("SELECT * FROM approvals WHERE request_id = ? ORDER BY at").all(id) as Row[]).map((a) => ({
      by: { id: a.approver_id as string, email: a.approver_email as string, name: a.approver_name as string },
      comment: a.comment as string,
      at: a.at as string,
    }));

  const toRequest = (r: Row): AccessRequest => ({
    id: r.id as string,
    server: { id: r.server_id as string, name: r.server_name as string },
    login: r.login as string,
    principal: `${r.login}@${r.server_name}`,
    minutes: Number(r.minutes),
    reason: r.reason as string,
    ticket: r.ticket as string,
    requester: { id: r.requester_id as string, email: r.requester_email as string, name: r.requester_name as string },
    status: r.status as RequestStatus,
    createdAt: r.created_at as string,
    startsAt: (r.starts_at as string | null) ?? null,
    endsAt: (r.ends_at as string | null) ?? null,
    approvalsNeeded: Number(r.approvals_needed),
    approvals: approvalsOf(r.id as string),
    closed: r.closed_at ? { by: r.closed_by as string, at: r.closed_at as string, comment: (r.close_comment as string) ?? "" } : null,
  });
  const requestRow = (id: string) => db.prepare("SELECT * FROM requests WHERE id = ?").get(id) as Row | undefined;

  function requests(filter: { status?: string | null; requesterId?: string } = {}, limit = 200): AccessRequest[] {
    expire();
    if (filter.status && !STATUSES.includes(filter.status as RequestStatus)) throw bad(`status is one of ${STATUSES.join(", ")}.`);
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    if (filter.status) (where.push("status = ?"), args.push(filter.status));
    if (filter.requesterId) (where.push("requester_id = ?"), args.push(filter.requesterId));
    const sql = `SELECT * FROM requests ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC LIMIT ?`;
    return (db.prepare(sql).all(...args, limit) as Row[]).map(toRequest);
  }

  function certificatesOf(id: string): Certificate[] {
    const now = iso();
    const r = requestRow(id);
    const closedAt = r && (r.status === "revoked" || r.status === "ended") ? (r.closed_at as string) : null;
    return (db.prepare("SELECT * FROM certificates WHERE request_id = ? ORDER BY serial").all(id) as Row[]).map((c) => ({
      serial: Number(c.serial),
      keyType: c.key_type as string,
      fingerprint: c.fingerprint as string,
      principal: c.principal as string,
      validAfter: c.valid_after as string,
      validBefore: c.valid_before as string,
      issuedAt: c.issued_at as string,
      revoked: !!closedAt && closedAt < (c.valid_before as string) && (c.valid_before as string) > now,
    }));
  }

  function request(id: string) {
    expire();
    const r = requestRow(id);
    if (!r) throw notFound("The request");
    return { ...toRequest(r), certificates: certificatesOf(id), events: events({ requestId: id }, 200).events };
  }

  /** Asking for, approving and using access are a person's acts, done with a second factor. */
  function personOf(actor: Actor, what: string): Person {
    if (!actor.person) throw forbidden(`Only a signed-in person can ${what}; API tokens cannot.`);
    if (!actor.mfa)
      throw new AccessError(
        403,
        "mfa-required",
        `Add a second factor under Account, then sign in with it, to ${what}. Signing in through your identity provider counts.`,
      );
    return actor.person;
  }

  function createRequest(body: Record<string, unknown>, actor: Actor): AccessRequest {
    expire();
    const person = personOf(actor, "ask for access");
    const s = serverRow(text(body.serverId, "serverId", 64));
    if (!s) throw bad("serverId is not a server.");
    const srv = toServer(s);
    const login = text(body.login, "login", 32);
    if (!srv.logins.includes(login)) throw bad(`${srv.name} allows ${srv.logins.join(", ")}, not ${login}.`);
    const minutes = whole(body.minutes, "minutes", 5, srv.maxMinutes);
    const reason = text(body.reason, "reason", 500);
    if (reason.length < 10) throw bad("reason must say why, in at least 10 characters.");
    const ticket = text(body.ticket, "ticket", 64, false);
    const open = db
      .prepare("SELECT id FROM requests WHERE requester_id = ? AND server_id = ? AND login = ? AND status IN ('pending', 'active')")
      .get(person.id, srv.id, login) as Row | undefined;
    if (open) throw conflict(`You already have a request for ${login}@${srv.name} waiting or open.`);
    const id = randomUUID();
    db.prepare(
      "INSERT INTO requests (id, server_id, server_name, login, minutes, reason, ticket, requester_id, requester_email, requester_name, approvals_needed, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
    ).run(id, srv.id, srv.name, login, minutes, reason, ticket, person.id, person.email, person.name, srv.approvals, iso());
    record(who(actor), "request.create", `${login}@${srv.name}`, { detail: `${minutesText(minutes)}${ticket ? `, ${ticket}` : ""}: ${reason}`, requestId: id });
    return toRequest(requestRow(id)!);
  }

  const isRequester = (p: Person, r: Row) => p.id === r.requester_id || p.email.toLowerCase() === (r.requester_email as string).toLowerCase();

  /** The pending request someone other than its requester decides on. A try at one's own is refused and recorded. */
  function decidable(id: string, actor: Actor, verb: "approve" | "deny"): { person: Person; r: Row } {
    expire();
    const person = personOf(actor, `${verb} requests`);
    const r = requestRow(id);
    if (!r) throw notFound("The request");
    const target = `${r.login}@${r.server_name}`;
    if (isRequester(person, r)) {
      record(who(actor), `request.${verb}`, target, { result: "denied", detail: `Tried to ${verb} their own request.`, requestId: id });
      throw forbidden(`You cannot ${verb} your own request; someone else must.`);
    }
    if (r.status !== "pending") throw conflict(`The request is ${r.status}, not waiting for a decision.`);
    return { person, r };
  }

  function approve(id: string, body: Record<string, unknown>, actor: Actor): AccessRequest {
    const { person, r } = decidable(id, actor, "approve");
    const comment = text(body.comment, "comment", 500, false);
    if (db.prepare("SELECT 1 FROM approvals WHERE request_id = ? AND approver_id = ?").get(id, person.id))
      throw conflict("You have approved it already; it needs someone else too.");
    // The server's policy may have changed since the request was made.
    const s = serverRow(r.server_id as string);
    const srv = s && toServer(s);
    if (!srv || srv.name !== r.server_name || !srv.logins.includes(r.login as string) || srv.maxMinutes < Number(r.minutes))
      throw conflict("The server's policy has changed and no longer allows this request; ask again.");
    const now = clock();
    db.exec("BEGIN");
    try {
      db.prepare("INSERT INTO approvals (request_id, approver_id, approver_email, approver_name, comment, at) VALUES (?, ?, ?, ?, ?, ?)").run(
        id,
        person.id,
        person.email,
        person.name,
        comment,
        iso(now),
      );
      const target = `${r.login}@${r.server_name}`;
      record(who(actor), "request.approve", target, { detail: comment, requestId: id });
      const count = (db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE request_id = ?").get(id) as { n: number }).n;
      if (count >= Number(r.approvals_needed)) {
        // The grant starts at the last approval and lasts as long as asked for.
        const ends = iso(now + Number(r.minutes) * MINUTE);
        db.prepare("UPDATE requests SET status = 'active', starts_at = ?, ends_at = ? WHERE id = ?").run(iso(now), ends, id);
        record("Access", "grant.start", target, { detail: `For ${r.requester_name} <${r.requester_email}> until ${ends}`, requestId: id });
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    return toRequest(requestRow(id)!);
  }

  function deny(id: string, body: Record<string, unknown>, actor: Actor): AccessRequest {
    const { person, r } = decidable(id, actor, "deny");
    const comment = text(body.comment, "comment", 500, false);
    db.prepare("UPDATE requests SET status = 'denied', closed_by = ?, closed_at = ?, close_comment = ? WHERE id = ?").run(person.name, iso(), comment, id);
    record(who(actor), "request.deny", `${r.login}@${r.server_name}`, { detail: comment, requestId: id });
    return toRequest(requestRow(id)!);
  }

  function cancel(id: string, actor: Actor): AccessRequest {
    expire();
    const r = requestRow(id);
    if (!r) throw notFound("The request");
    if (!actor.person || !isRequester(actor.person, r)) throw forbidden("Only the person who asked can cancel a request; an approver denies it.");
    if (r.status !== "pending") throw conflict(`The request is ${r.status}; only a waiting request can be cancelled.`);
    db.prepare("UPDATE requests SET status = 'cancelled', closed_by = ?, closed_at = ? WHERE id = ?").run(actor.person.name, iso(), id);
    record(who(actor), "request.cancel", `${r.login}@${r.server_name}`, { requestId: id });
    return toRequest(requestRow(id)!);
  }

  /** Ends a grant before its time: the requester when done, or an editor who revokes it. Its certificates are revoked. */
  function end(id: string, body: Record<string, unknown>, actor: Actor): AccessRequest {
    expire();
    const r = requestRow(id);
    if (!r) throw notFound("The request");
    const own = !!actor.person && isRequester(actor.person, r);
    if (!own && !atLeast(actor.role, "editor")) throw forbidden("Only the person who asked, or an editor, can end a grant.");
    if (r.status !== "active") throw conflict(`The request is ${r.status}, not an open grant.`);
    const comment = text(body.comment, "comment", 500, false);
    const status = own ? "ended" : "revoked";
    db.prepare("UPDATE requests SET status = ?, closed_by = ?, closed_at = ?, close_comment = ? WHERE id = ?").run(
      status,
      actor.person?.name ?? actor.name,
      iso(),
      comment || (own ? "Done." : ""),
      id,
    );
    record(who(actor), own ? "grant.end" : "grant.revoke", `${r.login}@${r.server_name}`, { detail: comment, requestId: id });
    return toRequest(requestRow(id)!);
  }

  /** Signs a certificate for the requester's own public key, valid until the grant ends and on its server only. */
  function issueCertificate(id: string, body: Record<string, unknown>, actor: Actor) {
    expire();
    const person = personOf(actor, "get a certificate");
    const r = requestRow(id);
    if (!r) throw notFound("The request");
    const target = `${r.login}@${r.server_name}`;
    if (!isRequester(person, r)) {
      record(who(actor), "certificate.issue", target, { result: "denied", detail: "Asked for a certificate on someone else's grant.", requestId: id });
      throw forbidden("Only the person who asked for this access can get a certificate for it.");
    }
    if (r.status !== "active") throw conflict(`The request is ${r.status}; certificates are issued only while the grant is open.`);
    const issued = (db.prepare("SELECT COUNT(*) AS n FROM certificates WHERE request_id = ?").get(id) as { n: number }).n;
    if (issued >= CERTIFICATES_PER_GRANT) throw conflict(`A grant gets at most ${CERTIFICATES_PER_GRANT} certificates.`);
    let key;
    try {
      key = parsePublicKey(text(body.publicKey, "publicKey", 16_384));
    } catch (err) {
      if (err instanceof KeyError) throw bad(`publicKey: ${err.message}`);
      throw err;
    }
    const s = serverRow(r.server_id as string);
    const now = clock();
    const validAfter = now - CLOCK_SKEW_MS;
    const validBefore = Date.parse(r.ends_at as string);
    const ins = db
      .prepare("INSERT INTO certificates (request_id, key_type, fingerprint, principal, valid_after, valid_before, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, key.type, key.fingerprint, target, iso(validAfter), iso(validBefore), iso(now));
    const serial = Number(ins.lastInsertRowid);
    // sshd logs the key ID at every login with it, so the server's own log says who it was and for which grant.
    const keyId = `${r.requester_email} access ${id}`;
    const certificate = signCertificate(ca, { key, serial: BigInt(serial), keyId, principals: [target], validAfter, validBefore, extensions: EXTENSIONS });
    record(who(actor), "certificate.issue", target, { detail: `Serial ${serial}, ${key.fingerprint}, until ${iso(validBefore)}`, requestId: id });
    const port = s ? Number(s.port) : 22;
    return {
      serial,
      certificate,
      principal: target,
      fingerprint: key.fingerprint,
      validAfter: iso(validAfter),
      validBefore: iso(validBefore),
      command: s ? `ssh ${port === 22 ? "" : `-p ${port} `}${r.login}@${s.address}` : null,
    };
  }

  /** sshd's RevokedKeys file: the certificates of grants ended early, until they would have expired. */
  function revoked(): Buffer {
    expire();
    const now = iso();
    const serials = db
      .prepare(
        "SELECT c.serial FROM certificates c JOIN requests r ON r.id = c.request_id WHERE r.status IN ('revoked', 'ended') AND r.closed_at < c.valid_before AND c.valid_before > ?",
      )
      .all(now) as Array<{ serial: number }>;
    // The version grows with every change, so a server can tell a newer list from an older one.
    const version = (db.prepare("SELECT COUNT(*) AS n FROM audit WHERE action IN ('grant.end', 'grant.revoke')").get() as { n: number }).n;
    return revocationList(
      ca,
      serials.map((s) => BigInt(s.serial)),
      BigInt(version),
      clock(),
    );
  }

  // ---------------------------------------------------------------- the audit log

  const toEvent = (r: Row): AuditEvent => ({
    id: Number(r.id),
    at: r.at as string,
    actor: r.actor as string,
    action: r.action as string,
    target: r.target as string,
    result: r.result as "success" | "denied",
    detail: r.detail as string,
    requestId: (r.request_id as string | null) ?? null,
  });

  /** Newest first, a page at a time: `next` is the cursor for the page after. */
  function events(filter: { kind?: string | null; requestId?: string; cursor?: string | null } = {}, limit = 100) {
    if (filter.kind && !(AUDIT_KINDS as readonly string[]).includes(filter.kind)) throw bad(`kind is one of ${AUDIT_KINDS.join(", ")}.`);
    let before = Number.MAX_SAFE_INTEGER;
    if (filter.cursor) {
      before = Number(Buffer.from(filter.cursor, "base64url").toString("utf8"));
      if (!Number.isSafeInteger(before)) throw bad("cursor is not one this API gave.");
    }
    const where = ["id < ?"];
    const args: SQLInputValue[] = [before];
    if (filter.kind) (where.push("action LIKE ?"), args.push(`${filter.kind}.%`));
    if (filter.requestId) (where.push("request_id = ?"), args.push(filter.requestId));
    const rows = (db.prepare(`SELECT * FROM audit WHERE ${where.join(" AND ")} ORDER BY id DESC LIMIT ?`).all(...args, limit + 1) as Row[]).map(toEvent);
    const more = rows.length > limit;
    const page = rows.slice(0, limit);
    return { events: page, next: more ? Buffer.from(String(page.at(-1)!.id)).toString("base64url") : null };
  }

  /** The whole log as CSV, oldest first, for an auditor's spreadsheet. */
  function exportCsv(): string {
    const head = ["id", "at", "actor", "action", "target", "result", "detail", "request"].join(",");
    const lines = (db.prepare("SELECT * FROM audit ORDER BY id").all() as Row[])
      .map(toEvent)
      .map((e) => [e.id, e.at, e.actor, e.action, e.target, e.result, e.detail, e.requestId].map(csvCell).join(","));
    return [head, ...lines].join("\r\n") + "\r\n";
  }

  // ---------------------------------------------------------------- overview and metrics

  function summary() {
    expire();
    const now = clock();
    const count = (sql: string, ...args: SQLInputValue[]) => (db.prepare(sql).get(...args) as { n: number }).n;
    const since = iso(now - 30 * DAY);
    // How long people wait: from the request to the start of its grant, over the last 30 days.
    const waits = (db.prepare("SELECT created_at, starts_at FROM requests WHERE starts_at IS NOT NULL AND created_at >= ?").all(since) as Row[])
      .map((r) => (Date.parse(r.starts_at as string) - Date.parse(r.created_at as string)) / MINUTE)
      .sort((a, b) => a - b);
    const median = waits.length ? waits[Math.floor((waits.length - 1) / 2)]! : null;
    const today = Math.floor(now / DAY) * DAY;
    const perDay = Array.from({ length: 14 }, (_, i) => {
      const from = today - (13 - i) * DAY;
      return {
        day: iso(from).slice(0, 10),
        requests: count("SELECT COUNT(*) AS n FROM requests WHERE created_at >= ? AND created_at < ?", iso(from), iso(from + DAY)),
        granted: count("SELECT COUNT(*) AS n FROM requests WHERE starts_at >= ? AND starts_at < ?", iso(from), iso(from + DAY)),
      };
    });
    return {
      requests: {
        pending: count("SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'"),
        lastDay: count("SELECT COUNT(*) AS n FROM requests WHERE created_at >= ?", iso(now - DAY)),
      },
      grants: { active: count("SELECT COUNT(*) AS n FROM requests WHERE status = 'active'") },
      certificates: { lastDay: count("SELECT COUNT(*) AS n FROM certificates WHERE issued_at >= ?", iso(now - DAY)) },
      servers: count("SELECT COUNT(*) AS n FROM servers"),
      medianWaitMinutes: median === null ? null : Math.round(median * 10) / 10,
      perDay,
      pending: requests({ status: "pending" }),
      active: requests({ status: "active" }),
    };
  }

  function gauges() {
    expire();
    const count = (sql: string, ...args: SQLInputValue[]) => (db.prepare(sql).get(...args) as { n: number }).n;
    return {
      pending: count("SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'"),
      active: count("SELECT COUNT(*) AS n FROM requests WHERE status = 'active'"),
      servers: count("SELECT COUNT(*) AS n FROM servers"),
      certificatesLastDay: count("SELECT COUNT(*) AS n FROM certificates WHERE issued_at >= ?", iso(clock() - DAY)),
      refusedLastDay: count("SELECT COUNT(*) AS n FROM audit WHERE result = 'denied' AND at >= ?", iso(clock() - DAY)),
    };
  }

  return {
    ca: caInfo,
    servers,
    server,
    saveServer,
    deleteServer,
    serverSetup,
    requests,
    request,
    createRequest,
    approve,
    deny,
    cancel,
    end,
    issueCertificate,
    revoked,
    events,
    exportCsv,
    record,
    recordAuth,
    tick: expire,
    summary,
    gauges,
  };
}

export type Access = ReturnType<typeof createAccess>;
