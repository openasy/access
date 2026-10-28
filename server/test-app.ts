// Starts the app on a random port for tests, with people signed in as a browser would be: an owner, two team leads
// (editors), an engineer and a viewer without a second factor.
import { createHmac } from "node:crypto";
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createAccess, type AccessOptions } from "./access.ts";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createKeyring } from "./kek.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const KEK = Buffer.alloc(32, 7);
export const T0 = Date.parse("2026-10-28T09:00:00Z");
export const UA = "Mozilla/5.0 (Macintosh) Chrome/141.0";
export const PASSWORD = "correct horse battery";

/** fetch with a cookie jar, as a browser: cookies are kept by name, which is enough for one host. */
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly base: string;
  constructor(base: string) {
    this.base = base;
  }
  async fetch(path: string, init: { method?: string; body?: unknown } = {}) {
    const res = await fetch(this.base + path, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      redirect: "manual",
      headers: {
        origin: this.base,
        "user-agent": UA,
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(init.body !== undefined && { "content-type": "application/json" }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const name = pair!.slice(0, pair!.indexOf("="));
      const value = pair!.slice(pair!.indexOf("=") + 1);
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }
  async json<T = any>(path: string, init: { method?: string; body?: unknown } = {}) {
    const res = await this.fetch(path, init);
    return { status: res.status, body: (res.status === 204 ? {} : await res.json()) as T };
  }
  /** POSTs, with an empty body when none is given, as the UI does. */
  post<T = any>(path: string, body: unknown = {}) {
    return this.json<T>(path, { method: "POST", body });
  }
}

export const totp = (secret: string) => {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "")) bits += a.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const h = createHmac("sha1", key).update(msg).digest();
  return String((h.readUInt32BE(h[19]! & 15) & 0x7fffffff) % 1e6).padStart(6, "0");
};

export async function startApp(opts: Partial<AppOptions> & { version: string; accessOptions?: Partial<AccessOptions> }) {
  const db = openDb(":memory:");
  let now = T0;
  const { accessOptions, ...appOptions } = opts;
  const access = createAccess(db, { keyring: createKeyring(KEK), publicUrl: "https://access.example.com", clock: () => now, ...accessOptions });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "access", productName: "OpenAsy Access", origin: base, secretsKey: KEK, onEvent: access.recordAuth });
  handler = createApp({ db, access, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const admin = (path: string, init: RequestInit = {}) =>
    fetch(base + path, { ...init, headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json", ...init.headers } });
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));

  /** Adds a second factor to the signed-in session, as Account does. */
  const addTotp = async (b: Browser) => {
    const { body } = await b.post<{ secret: string }>("/api/v1/auth/me/totp");
    await b.post("/api/v1/auth/me/totp/confirm", { code: totp(body.secret) });
  };

  /** The owner from the first-start link, then members invited by them, each signed in from their own browser. */
  async function people() {
    const owner = new Browser(base);
    const token = new URL(auth.setupLink()!).searchParams.get("setup");
    await owner.post("/api/v1/auth/setup", { token, name: "Olivia Owner", email: "owner@example.com", password: PASSWORD });
    await addTotp(owner);
    const invite = async (name: string, email: string, role: string, mfa = true) => {
      const { body } = await owner.post<{ member: { id: string }; link: string }>("/api/v1/auth/members", { email, name, role });
      const b = new Browser(base);
      await b.post(`/api/v1/auth/links/${new URL(body.link).searchParams.get("link")}`, { password: PASSWORD });
      if (mfa) await addTotp(b);
      return Object.assign(b, { id: body.member.id, email });
    };
    return {
      owner,
      lead: await invite("Lale Lead", "lead@example.com", "editor"),
      lead2: await invite("Leo Lead", "leo@example.com", "editor"),
      eng: await invite("Ece Engineer", "ece@example.com", "viewer"),
      nomfa: await invite("Nil Nofactor", "nil@example.com", "viewer", false),
    };
  }

  return { db, access, auth, base, admin, get, send, close, people, later: (ms: number) => (now += ms), now: () => now };
}
