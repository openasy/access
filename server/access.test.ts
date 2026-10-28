import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { startApp, T0 } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
let p: Awaited<ReturnType<Awaited<ReturnType<typeof startApp>>["people"]>>;
let web = "";
let db2 = "";

const MIN = 60_000;

function publicKeyLine() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const x = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
  const s = (b: Buffer) => Buffer.concat([Buffer.from([0, 0, 0, b.length]), b]);
  return `ssh-ed25519 ${Buffer.concat([s(Buffer.from("ssh-ed25519")), s(x)]).toString("base64")} ece@laptop`;
}

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
  p = await app.people();
  const add = async (body: Record<string, unknown>) => ((await (await app.send("POST", "/api/v1/servers", body)).json()) as { id: string }).id;
  web = await add({ name: "web-1", address: "10.0.0.5", logins: ["deploy", "www-data"], maxMinutes: 120 });
  db2 = await add({ name: "db-prod-01", address: "db.internal", port: 2222, logins: ["postgres"], approvals: 2 });
});
afterAll(() => app.close());

const ask = (b: (typeof p)["eng"], body: Record<string, unknown>) =>
  b.post("/api/v1/requests", { serverId: web, login: "deploy", minutes: 60, reason: "Debug order 1927731 (INC-2291)", ...body });

describe("servers", () => {
  it("keep their policy, with defaults: port 22, one approval, an hour", async () => {
    const s = await app.get(`/api/v1/servers/${web}`);
    expect(s).toMatchObject({ name: "web-1", port: 22, logins: ["deploy", "www-data"], maxMinutes: 120, approvals: 1, active: 0 });
    const d = await app.get(`/api/v1/servers/${db2}`);
    expect(d).toMatchObject({ port: 2222, approvals: 2, maxMinutes: 60 });
  });

  it("refuse names that cannot be a principal, accounts that are not Unix names, and a name in use", async () => {
    const bad = async (body: Record<string, unknown>) => ((await (await app.send("POST", "/api/v1/servers", body)).json()) as { detail: string }).detail;
    expect(await bad({ name: "Web 1", address: "a", logins: ["x"] })).toMatch(/host name/);
    expect(await bad({ name: "web-2", address: "root@a", logins: ["x"] })).toMatch(/address/);
    expect(await bad({ name: "web-2", address: "a", logins: ["Root"] })).toMatch(/Unix account/);
    expect(await bad({ name: "web-2", address: "a", logins: [] })).toMatch(/1 to 16/);
    expect(await bad({ name: "web-2", address: "a", logins: ["x"], maxMinutes: 2000 })).toMatch(/5 to 1440/);
    expect((await app.send("POST", "/api/v1/servers", { name: "web-1", address: "a", logins: ["x"] })).status).toBe(409);
  });

  it("are kept by admins only", async () => {
    expect((await p.lead.post("/api/v1/servers", { name: "x", address: "a", logins: ["x"] })).status).toBe(403);
  });

  it("give a setup that trusts the CA for their own logins on that server only", async () => {
    const script = await (await app.admin(`/api/v1/servers/${web}/setup`)).text();
    const { publicKey } = await app.get("/api/v1/ca");
    expect(publicKey).toMatch(/^ssh-ed25519 \S+ openasy-access$/);
    expect(script).toContain(`echo '${publicKey}' > /etc/ssh/openasy_access_ca.pub`);
    expect(script).toContain("echo 'deploy@web-1' > /etc/ssh/openasy_access_principals/deploy");
    expect(script).toContain("echo 'www-data@web-1' > /etc/ssh/openasy_access_principals/www-data");
    expect(script).toContain("AuthorizedPrincipalsFile /etc/ssh/openasy_access_principals/%u");
    expect(script).toContain("https://access.example.com/api/v1/revoked.krl");
  });
});

describe("asking for access", () => {
  it("needs a server's own login, a duration within its policy and a reason", async () => {
    expect((await ask(p.eng, { login: "root" })).body.detail).toMatch(/allows deploy, www-data, not root/);
    expect((await ask(p.eng, { minutes: 121 })).body.detail).toMatch(/5 to 120/);
    expect((await ask(p.eng, { reason: "pls" })).body.detail).toMatch(/at least 10/);
  });

  it("is a person's act, with a second factor", async () => {
    expect((await ask(p.nomfa, {})).body).toMatchObject({ status: 403, code: "mfa-required" });
    const token = await app.send("POST", "/api/v1/requests", { serverId: web, login: "deploy", minutes: 60, reason: "From a script, without anyone" });
    expect(await token.json()).toMatchObject({ status: 403, code: "forbidden" });
  });

  it("waits for someone other than the requester, who can never approve their own", async () => {
    const mine = await ask(p.lead, { ticket: "OPS-1874" });
    expect(mine).toMatchObject({ status: 201, body: { status: "pending", requester: { email: "lead@example.com" }, principal: "deploy@web-1" } });
    const self = await p.lead.post(`/api/v1/requests/${mine.body.id}/approve`);
    expect(self.body).toMatchObject({ status: 403, code: "forbidden" });
    expect((await p.lead.post(`/api/v1/requests/${mine.body.id}/deny`)).status).toBe(403);
    const { events } = await app.get(`/api/v1/requests/${mine.body.id}`);
    expect(events.map((e: { action: string; result: string }) => `${e.action} ${e.result}`)).toEqual([
      "request.deny denied",
      "request.approve denied",
      "request.create success",
    ]);
    const other = await p.lead2.post(`/api/v1/requests/${mine.body.id}/approve`, { comment: "Go ahead" });
    expect(other.body).toMatchObject({ status: "active", startsAt: new Date(T0).toISOString(), endsAt: new Date(T0 + 60 * MIN).toISOString() });
    expect(other.body.approvals).toEqual([
      { by: { id: p.lead2.id, email: "leo@example.com", name: "Leo Lead" }, comment: "Go ahead", at: new Date(T0).toISOString() },
    ]);
  });

  it("is refused for viewers to decide, and while one for the same login is open", async () => {
    const r = await ask(p.eng, {});
    expect(r.status).toBe(201);
    expect((await p.eng.post(`/api/v1/requests/${r.body.id}/approve`)).status).toBe(403);
    expect((await ask(p.eng, {})).status).toBe(409);
    expect((await p.lead.post(`/api/v1/requests/${r.body.id}/deny`, { comment: "Use staging" })).body).toMatchObject({
      status: "denied",
      closed: { by: "Lale Lead", comment: "Use staging" },
    });
    expect((await p.lead2.post(`/api/v1/requests/${r.body.id}/approve`)).status).toBe(409);
  });

  it("needs two different people where the server says two", async () => {
    const r = await p.eng.post("/api/v1/requests", { serverId: db2, login: "postgres", minutes: 30, reason: "Read the orders table for INC-2291" });
    expect(r.body.approvalsNeeded).toBe(2);
    expect((await p.lead.post(`/api/v1/requests/${r.body.id}/approve`)).body.status).toBe("pending");
    expect((await p.lead.post(`/api/v1/requests/${r.body.id}/approve`)).status).toBe(409);
    expect((await p.lead2.post(`/api/v1/requests/${r.body.id}/approve`)).body.status).toBe("active");
  });

  it("can be cancelled by the requester only, while it waits", async () => {
    const r = await ask(p.eng, { login: "www-data" });
    expect((await p.lead.post(`/api/v1/requests/${r.body.id}/cancel`)).status).toBe(403);
    expect((await p.eng.post(`/api/v1/requests/${r.body.id}/cancel`)).body).toMatchObject({ status: "cancelled", closed: { by: "Ece Engineer" } });
    expect((await p.eng.post(`/api/v1/requests/${r.body.id}/cancel`)).status).toBe(409);
  });

  it("lapses when nobody approves within a day", async () => {
    const r = await ask(p.eng, { login: "www-data" });
    app.later(24 * 60 * MIN);
    expect((await app.get(`/api/v1/requests/${r.body.id}`)).closed).toMatchObject({ by: "Access", comment: "Nobody approved it within 24 hours." });
  });
});

describe("a grant", () => {
  let id = "";
  let key = "";

  beforeAll(async () => {
    const r = await ask(p.eng, {});
    id = r.body.id;
    await p.lead.post(`/api/v1/requests/${id}/approve`);
    key = publicKeyLine();
  });

  it("gives the requester certificates for their own key, valid until it ends, for that server only", async () => {
    const c = await p.eng.post(`/api/v1/requests/${id}/certificates`, { publicKey: key });
    expect(c.status).toBe(201);
    expect(c.body).toMatchObject({ principal: "deploy@web-1", command: "ssh deploy@10.0.0.5", validBefore: new Date(app.now() + 60 * MIN).toISOString() });
    expect(c.body.certificate).toMatch(/^ssh-ed25519-cert-v01@openssh\.com \S+ ece@example\.com access /);
    const detail = await app.get(`/api/v1/requests/${id}`);
    expect(detail.certificates).toEqual([expect.objectContaining({ serial: c.body.serial, keyType: "ssh-ed25519", revoked: false })]);
    expect(detail.events[0]).toMatchObject({ action: "certificate.issue", actor: "Ece Engineer <ece@example.com>" });
  });

  it.skipIf(!hasSshKeygen())("gives certificates ssh-keygen accepts", async () => {
    const dir = mkdtempSync(join(tmpdir(), "access-grant-"));
    const c = await p.eng.post(`/api/v1/requests/${id}/certificates`, { publicKey: key });
    writeFileSync(join(dir, "id-cert.pub"), c.body.certificate + "\n");
    expect(execFileSync("ssh-keygen", ["-L", "-f", join(dir, "id-cert.pub")], { encoding: "utf8" })).toMatch(/Principals: \n\s+deploy@web-1\n/);
  });

  it("gives nobody else a certificate for it, and records the try", async () => {
    expect((await p.lead.post(`/api/v1/requests/${id}/certificates`, { publicKey: key })).status).toBe(403);
    expect((await app.send("POST", `/api/v1/requests/${id}/certificates`, { publicKey: key })).status).toBe(403);
    expect((await app.get(`/api/v1/requests/${id}`)).events[0]).toMatchObject({
      action: "certificate.issue",
      result: "denied",
      actor: "Lale Lead <lead@example.com>",
    });
    expect((await p.eng.post(`/api/v1/requests/${id}/certificates`, { publicKey: "ssh-dss AAAA" })).body.detail).toMatch(/^publicKey: /);
  });

  it("keeps its server from being renamed or removed while open", async () => {
    expect((await app.send("PUT", `/api/v1/servers/${web}`, { name: "web-9", address: "10.0.0.5", logins: ["deploy"] })).status).toBe(409);
    expect((await app.send("DELETE", `/api/v1/servers/${web}`)).status).toBe(409);
    expect((await app.get(`/api/v1/servers/${web}`)).active).toBe(1);
  });

  it("ends by itself at its time, and no certificate is issued after", async () => {
    app.later(60 * MIN);
    const r = await app.get(`/api/v1/requests/${id}`);
    expect(r).toMatchObject({ status: "ended", closed: { by: "Access", at: r.endsAt } });
    expect(r.certificates.every((c: { revoked: boolean }) => !c.revoked)).toBe(true);
    expect((await p.eng.post(`/api/v1/requests/${id}/certificates`, { publicKey: key })).status).toBe(409);
    expect((await app.get(`/api/v1/audit?kind=grant`)).events[0]).toMatchObject({ action: "grant.end", actor: "Access", requestId: id });
  });
});

describe("ending a grant early", () => {
  const open = async (login = "deploy") => {
    const r = await ask(p.eng, { login });
    await p.lead.post(`/api/v1/requests/${r.body.id}/approve`);
    const c = await p.eng.post(`/api/v1/requests/${r.body.id}/certificates`, { publicKey: publicKeyLine() });
    return { id: r.body.id as string, serial: c.body.serial as number };
  };

  it("by the requester ends it; by an editor revokes it; and puts its certificates on the revocation list", async () => {
    const done = await open();
    const bad = await open("www-data");
    expect((await p.nomfa.post(`/api/v1/requests/${done.id}/end`)).status).toBe(403);
    expect((await p.eng.post(`/api/v1/requests/${done.id}/end`)).body).toMatchObject({ status: "ended", closed: { by: "Ece Engineer", comment: "Done." } });
    expect((await p.lead.post(`/api/v1/requests/${bad.id}/end`, { comment: "Laptop stolen" })).body).toMatchObject({
      status: "revoked",
      closed: { by: "Lale Lead", comment: "Laptop stolen" },
    });
    expect((await app.get(`/api/v1/requests/${bad.id}`)).certificates[0].revoked).toBe(true);
    const krl = Buffer.from(await (await fetch(`${app.base}/api/v1/revoked.krl`)).arrayBuffer());
    expect(krl.subarray(0, 8).toString("latin1")).toBe("SSHKRL\n\0");
    // The serials are the list's last 8-byte numbers, in order.
    const serials = [done.serial, bad.serial].sort((a, b) => a - b);
    expect([...Array(2).keys()].map((i) => Number(krl.readBigUInt64BE(krl.length - 16 + i * 8)))).toEqual(serials);
  });

  it("drops certificates from the list once they would have expired", async () => {
    app.later(61 * MIN);
    const krl = Buffer.from(await (await fetch(`${app.base}/api/v1/revoked.krl`)).arrayBuffer());
    expect(krl.length).toBe(8 + 4 + 8 + 8 + 8 + 4 + 4 + "OpenAsy Access".length);
  });
});

describe("the audit log", () => {
  it("has every step, newest first, a page at a time", async () => {
    const first = await app.get("/api/v1/audit?limit=3");
    expect(first.events).toHaveLength(3);
    const second = await app.get(`/api/v1/audit?limit=3&cursor=${first.next}`);
    expect(second.events[0].id).toBeLessThan(first.events[2].id);
    const all = (await app.get("/api/v1/audit?limit=500")).events.map((e: { action: string }) => e.action);
    for (const a of ["ca.create", "server.create", "request.create", "request.approve", "grant.start", "certificate.issue", "grant.revoke", "auth.setup"])
      expect(all).toContain(a);
  });

  it("cannot be changed or emptied, even from inside", () => {
    expect(() => app.db.prepare("UPDATE audit SET actor = 'someone else'").run()).toThrow(/append-only/);
    expect(() => app.db.prepare("DELETE FROM audit").run()).toThrow(/append-only/);
  });

  it("exports as CSV, with cells a spreadsheet will not run", async () => {
    app.access.record('=HYPERLINK("http://evil")', "request.create", "x");
    const res = await app.admin("/api/v1/audit/export");
    expect(res.headers.get("content-disposition")).toMatch(/^attachment; filename="access-audit-\d{4}-\d{2}-\d{2}\.csv"$/);
    const csv = await res.text();
    expect(csv.split("\r\n")[0]).toBe("id,at,actor,action,target,result,detail,request");
    expect(csv).toContain(`"'=HYPERLINK(""http://evil"")"`);
  });
});

function hasSshKeygen() {
  try {
    execFileSync("ssh-keygen", ["-?"], { stdio: "ignore" });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== "ENOENT";
  }
}
