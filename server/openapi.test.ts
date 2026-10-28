import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, startApp, UA, type Browser } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "access-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
let p: Awaited<ReturnType<Awaited<ReturnType<typeof startApp>>["people"]>>;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
  p = await app.people();
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const json = (body: unknown) => (body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) });
const admin = (body?: unknown): RequestInit => ({ headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" }, ...json(body) });
/** As a person in their browser: their session cookie, from the product's own origin. */
const as = (b: Browser, body?: unknown): RequestInit => ({
  headers: { cookie: [...b.cookies].map(([k, v]) => `${k}=${v}`).join("; "), origin: base, "user-agent": UA, "content-type": "application/json" },
  ...json(body),
});

function publicKeyLine() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const x = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
  const s = (b: Buffer) => Buffer.concat([Buffer.from([0, 0, 0, b.length]), b]);
  return `ssh-ed25519 ${Buffer.concat([s(Buffer.from("ssh-ed25519")), s(x)]).toString("base64")}`;
}

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // Access's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((path) => !path.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let server = "";
  let pending = "";
  let active = "";

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
    await call("GET", "/api/v1/ca");
    await call("GET", "/api/v1/revoked.krl");
  });

  it("servers", async () => {
    const body = { name: "web-1", address: "10.0.0.5", logins: ["deploy"], maxMinutes: 120 };
    server = ((await call("POST", "/api/v1/servers", admin(body))).body as { id: string }).id;
    await call("POST", "/api/v1/servers", admin(body));
    await call("POST", "/api/v1/servers", admin({ ...body, name: "Not A Name" }));
    await call("POST", "/api/v1/servers", admin("nope"));
    await call("POST", "/api/v1/servers", as(p.lead, { ...body, name: "web-2" }));
    await call("POST", "/api/v1/servers", { headers: { "content-type": "application/json" }, ...json(body) });
    await call("GET", "/api/v1/servers", admin());
    await call("GET", "/api/v1/servers", {});
    const s = "/api/v1/servers/{id}";
    await call("GET", s, admin(), `/api/v1/servers/${server}`);
    await call("GET", s, admin(), "/api/v1/servers/missing");
    await call("GET", s, {}, `/api/v1/servers/${server}`);
    await call("PUT", s, admin({ ...body, logins: ["deploy", "www-data"] }), `/api/v1/servers/${server}`);
    await call("PUT", s, admin({ ...body, logins: [] }), `/api/v1/servers/${server}`);
    await call("PUT", s, admin("nope"), `/api/v1/servers/${server}`);
    await call("PUT", s, admin(body), "/api/v1/servers/missing");
    await call("PUT", s, as(p.lead, body), `/api/v1/servers/${server}`);
    await call("PUT", s, {}, `/api/v1/servers/${server}`);
    const setup = "/api/v1/servers/{id}/setup";
    await call("GET", setup, admin(), `/api/v1/servers/${server}/setup`);
    await call("GET", setup, admin(), "/api/v1/servers/missing/setup");
    await call("GET", setup, {}, `/api/v1/servers/${server}/setup`);
  });

  it("requests and their refusals", async () => {
    const ask = { serverId: server, login: "deploy", minutes: 60, reason: "Rotate the TLS certificate (OPS-1874)" };
    pending = ((await call("POST", "/api/v1/requests", as(p.eng, ask))).body as { id: string }).id;
    await call("POST", "/api/v1/requests", as(p.eng, ask));
    await call("POST", "/api/v1/requests", as(p.eng, { ...ask, login: "root" }));
    await call("POST", "/api/v1/requests", as(p.eng, "nope"));
    await call("POST", "/api/v1/requests", as(p.nomfa, ask));
    await call("POST", "/api/v1/requests", admin(ask));
    await call("POST", "/api/v1/requests", {});
    active = ((await call("POST", "/api/v1/requests", as(p.lead, { ...ask, login: "www-data" }))).body as { id: string }).id;
    await call("GET", "/api/v1/requests", admin());
    await call("GET", "/api/v1/requests", as(p.eng), "/api/v1/requests?mine=true&status=pending");
    await call("GET", "/api/v1/requests", admin(), "/api/v1/requests?status=gone");
    await call("GET", "/api/v1/requests", {});
    const r = "/api/v1/requests/{id}";
    await call("GET", r, admin(), `/api/v1/requests/${pending}`);
    await call("GET", r, admin(), "/api/v1/requests/missing");
    await call("GET", r, {}, `/api/v1/requests/${pending}`);

    const approve = "/api/v1/requests/{id}/approve";
    await call("POST", approve, as(p.lead, {}), `/api/v1/requests/${active}/approve`);
    await call("POST", approve, as(p.lead2, { comment: "Go ahead" }), `/api/v1/requests/${active}/approve`);
    await call("POST", approve, as(p.lead2, {}), `/api/v1/requests/${active}/approve`);
    await call("POST", approve, as(p.lead2, "nope"), `/api/v1/requests/${active}/approve`);
    await call("POST", approve, as(p.lead2, {}), "/api/v1/requests/missing/approve");
    await call("POST", approve, as(p.eng, {}), `/api/v1/requests/${pending}/approve`);
    await call("POST", approve, {}, `/api/v1/requests/${pending}/approve`);
    const deny = "/api/v1/requests/{id}/deny";
    await call("POST", deny, as(p.lead, { comment: "Not today" }), `/api/v1/requests/${pending}/deny`);
    await call("POST", deny, as(p.lead, {}), `/api/v1/requests/${pending}/deny`);
    await call("POST", deny, as(p.lead, "nope"), `/api/v1/requests/${pending}/deny`);
    await call("POST", deny, as(p.lead, {}), "/api/v1/requests/missing/deny");
    await call("POST", deny, {}, `/api/v1/requests/${pending}/deny`);
    const cancel = "/api/v1/requests/{id}/cancel";
    const again = ((await call("POST", "/api/v1/requests", as(p.eng, ask))).body as { id: string }).id;
    await call("POST", cancel, as(p.lead), `/api/v1/requests/${again}/cancel`);
    await call("POST", cancel, as(p.eng), `/api/v1/requests/${again}/cancel`);
    await call("POST", cancel, as(p.eng), `/api/v1/requests/${again}/cancel`);
    await call("POST", cancel, as(p.eng), "/api/v1/requests/missing/cancel");
    await call("POST", cancel, {}, `/api/v1/requests/${again}/cancel`);
  });

  it("certificates, ending and the revocation list", async () => {
    const c = "/api/v1/requests/{id}/certificates";
    await call("POST", c, as(p.lead, { publicKey: publicKeyLine() }), `/api/v1/requests/${active}/certificates`);
    await call("POST", c, as(p.lead, { publicKey: "ssh-dss AAAA" }), `/api/v1/requests/${active}/certificates`);
    await call("POST", c, as(p.lead, "nope"), `/api/v1/requests/${active}/certificates`);
    await call("POST", c, as(p.eng, { publicKey: publicKeyLine() }), `/api/v1/requests/${active}/certificates`);
    await call("POST", c, as(p.lead, { publicKey: publicKeyLine() }), `/api/v1/requests/${pending}/certificates`);
    await call("POST", c, as(p.lead, { publicKey: publicKeyLine() }), "/api/v1/requests/missing/certificates");
    await call("POST", c, as(p.nomfa, { publicKey: publicKeyLine() }), `/api/v1/requests/${active}/certificates`);
    await call("POST", c, {}, `/api/v1/requests/${active}/certificates`);
    await call("GET", "/api/v1/requests/{id}", admin(), `/api/v1/requests/${active}`);
    await call("DELETE", "/api/v1/servers/{id}", admin(), `/api/v1/servers/${server}`);

    const end = "/api/v1/requests/{id}/end";
    await call("POST", end, as(p.nomfa, {}), `/api/v1/requests/${active}/end`);
    await call("POST", end, as(p.lead, "nope"), `/api/v1/requests/${active}/end`);
    await call("POST", end, as(p.lead2, { comment: "Done for today" }), `/api/v1/requests/${active}/end`);
    await call("POST", end, as(p.lead, {}), `/api/v1/requests/${active}/end`);
    await call("POST", end, as(p.lead, {}), "/api/v1/requests/missing/end");
    await call("POST", end, {}, `/api/v1/requests/${active}/end`);
    await call("GET", "/api/v1/revoked.krl");
  });

  it("the audit log and the overview", async () => {
    const page = (await call("GET", "/api/v1/audit", admin(), "/api/v1/audit?limit=2")).body as { next: string };
    await call("GET", "/api/v1/audit", admin(), `/api/v1/audit?limit=2&cursor=${page.next}&kind=request`);
    await call("GET", "/api/v1/audit", admin(), "/api/v1/audit?kind=nope");
    await call("GET", "/api/v1/audit", admin(), "/api/v1/audit?limit=0");
    await call("GET", "/api/v1/audit", {});
    await call("GET", "/api/v1/audit/export", admin());
    await call("GET", "/api/v1/audit/export", {});
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("removes servers, and refuses what is not there", async () => {
    await call("DELETE", "/api/v1/servers/{id}", as(p.lead), `/api/v1/servers/${server}`);
    await call("DELETE", "/api/v1/servers/{id}", admin(), `/api/v1/servers/${server}`);
    await call("DELETE", "/api/v1/servers/{id}", admin(), `/api/v1/servers/${server}`);
    await call("DELETE", "/api/v1/servers/{id}", {}, `/api/v1/servers/${server}`);
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
