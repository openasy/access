// The steps of e2e/run.sh that use the API and ssh: people sign in with a second factor, as in a browser.
import { execFileSync, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [setupLink, dir] = process.argv.slice(2) as [string, string];
const base = new URL(setupLink).origin;
const PASSWORD = "correct horse battery";
let failed = false;
const check = (ok: boolean, what: string) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failed = true;
};

/** A browser: a cookie jar, the product's own origin. */
function browser() {
  const cookies = new Map<string, string>();
  const call = async (path: string, body?: unknown) => {
    const res = await fetch(base + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        origin: base,
        "user-agent": "Mozilla/5.0 (X11; Linux) Firefox/140.0",
        cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(body !== undefined && { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      cookies.set(pair!.slice(0, pair!.indexOf("=")), pair!.slice(pair!.indexOf("=") + 1));
    }
    const type = res.headers.get("content-type") ?? "";
    return { status: res.status, body: (type.includes("json") ? await res.json() : await res.text()) as any };
  };
  return { call };
}

const totp = (secret: string) => {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "")) bits += a.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const h = createHmac("sha1", key).update(msg).digest();
  return String((h.readUInt32BE(h[19]! & 15) & 0x7fffffff) % 1e6).padStart(6, "0");
};
const addTotp = async (b: ReturnType<typeof browser>) => {
  const { body } = await b.call("/api/v1/auth/me/totp", {});
  await b.call("/api/v1/auth/me/totp/confirm", { code: totp(body.secret) });
};

const owner = browser();
await owner.call("/api/v1/auth/setup", {
  token: new URL(setupLink).searchParams.get("setup"),
  name: "Olivia Owner",
  email: "owner@example.com",
  password: PASSWORD,
});
await addTotp(owner);
const invite = async (name: string, email: string, role: string) => {
  const { body } = await owner.call("/api/v1/auth/members", { email, name, role });
  const b = browser();
  await b.call(`/api/v1/auth/links/${new URL(body.link).searchParams.get("link")}`, { password: PASSWORD });
  await addTotp(b);
  return b;
};
const lead = await invite("Lale Lead", "lead@example.com", "editor");
const eng = await invite("Ece Engineer", "ece@example.com", "viewer");

const server = await owner.call("/api/v1/servers", { name: "sshd-1", address: "127.0.0.1", port: 12222, logins: ["deploy"] });
check(server.status === 201, "an admin adds sshd-1 with the account deploy");

// The server's setup, as an admin would run it: the revocation list comes from Access over the compose network here.
const setup = (await owner.call(`/api/v1/servers/${server.body.id}/setup`)).body as string;
const script = setup.replaceAll(base, "http://e2e-access:8080").replace(/^sshd -t && .*$/m, "/usr/sbin/sshd -t && /usr/sbin/sshd");
const run = spawnSync("docker", ["exec", "-i", "e2e-sshd", "sh", "-e"], { input: script, encoding: "utf8" });
check(run.status === 0, `the setup runs on the server${run.status ? `: ${run.stderr}` : ""}`);

execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "ece@laptop", "-f", join(dir, "id_ed25519")]);
const key = join(dir, "id_ed25519");
const ssh = (login: string) =>
  spawnSync(
    "ssh",
    [
      "-F",
      "none",
      "-i",
      key,
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-p",
      "12222",
      `${login}@127.0.0.1`,
      "whoami",
    ],
    { encoding: "utf8" },
  );

/** sshd answered and said no, rather than not answering at all. */
const refused = (r: ReturnType<typeof ssh>) => r.status !== 0 && r.stderr.includes("Permission denied");

check(refused(ssh("deploy")), "without a certificate, the key does not log in");

const asked = await eng.call("/api/v1/requests", {
  serverId: server.body.id,
  login: "deploy",
  minutes: 30,
  reason: "Look at the nginx error log for INC-2291",
});
check(asked.status === 201, "Ece asks for deploy@sshd-1 for 30 minutes");
check(
  (await eng.call(`/api/v1/requests/${asked.body.id}/certificates`, { publicKey: readFileSync(`${key}.pub`, "utf8") })).status === 409,
  "no certificate before approval",
);
check((await lead.call(`/api/v1/requests/${asked.body.id}/approve`, {})).body.status === "active", "Lale approves it");

const cert = await eng.call(`/api/v1/requests/${asked.body.id}/certificates`, { publicKey: readFileSync(`${key}.pub`, "utf8") });
check(cert.status === 201, "Ece gets a certificate for her own key");
writeFileSync(`${key}-cert.pub`, `${cert.body.certificate}\n`);

const ok = ssh("deploy");
check(ok.status === 0 && ok.stdout.trim() === "deploy", `ssh logs in as deploy with it${ok.status ? `: ${ok.stderr.trim()}` : ""}`);
check(refused(ssh("ops")), "the certificate does not log in as another account");
check(refused(ssh("root")), "nor as root");

check((await lead.call(`/api/v1/requests/${asked.body.id}/end`, { comment: "Laptop left unlocked" })).body.status === "revoked", "Lale revokes it");
// What the server's cron job does every minute.
spawnSync("docker", ["exec", "e2e-sshd", "sh", "-c", "curl -sf -o /etc/ssh/openasy_access_revoked.krl http://e2e-access:8080/api/v1/revoked.krl"]);
check(refused(ssh("deploy")), "once the server has the revocation list, the certificate no longer logs in");

const events = (await owner.call("/api/v1/audit?limit=500")).body.events.map((e: { action: string }) => e.action);
check(
  ["request.create", "request.approve", "grant.start", "certificate.issue", "grant.revoke"].every((a) => events.includes(a)),
  "the audit log has every step",
);

process.exit(failed ? 1 : 0);
