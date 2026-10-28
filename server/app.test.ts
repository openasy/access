import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAccess } from "./access.ts";
import { openDb } from "./db.ts";
import { createKeyring } from "./kek.ts";
import { KEK, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

describe("the product", () => {
  it("names itself, and has metrics for Prometheus", async () => {
    expect(await (await fetch(`${app.base}/api/v1/version`)).json()).toEqual({ product: "access", version: "0.1.0" });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="access",version="0.1.0"} 1');
    expect(metrics).toContain("openasy_access_requests_pending 0");
    expect(metrics).toContain("openasy_access_grants_active 0");
    expect(metrics).toContain("openasy_access_refused 0");
  });

  it("shows nothing but its version, the CA's public key and the revocation list without signing in", async () => {
    for (const path of ["/api/v1/summary", "/api/v1/servers", "/api/v1/requests", "/api/v1/audit", "/api/v1/audit/export"])
      expect((await fetch(app.base + path)).status, path).toBe(401);
    const ca = (await (await fetch(`${app.base}/api/v1/ca`)).json()) as { publicKey: string; fingerprint: string };
    expect(ca.fingerprint).toMatch(/^SHA256:/);
    expect(ca.publicKey).not.toMatch(/PRIVATE/);
    expect((await fetch(`${app.base}/api/v1/revoked.krl`)).headers.get("content-type")).toBe("application/octet-stream");
  });

  it("sends security headers", async () => {
    const res = await fetch(`${app.base}/api/v1/version`);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
  });
});

describe("the certificate authority", () => {
  it("is made once, sealed, and opened again with the same key only", () => {
    const db = openDb(join(mkdtempSync(join(tmpdir(), "access-ca-")), "access.db"));
    const first = createAccess(db, { keyring: createKeyring(KEK), publicUrl: "https://a" });
    const row = db.prepare("SELECT private_key FROM ca").get() as { private_key: string };
    expect(row.private_key).toMatch(/^v1\./);
    expect(row.private_key).not.toContain("PRIVATE KEY");
    const again = createAccess(db, { keyring: createKeyring(KEK), publicUrl: "https://a" });
    expect(again.ca()).toEqual(first.ca());
    expect(() => createAccess(db, { keyring: createKeyring(Buffer.alloc(32, 9)), publicUrl: "https://a" })).toThrow(/cannot be opened/);
    expect((db.prepare("SELECT COUNT(*) AS n FROM audit WHERE action = 'ca.create'").get() as { n: number }).n).toBe(1);
  });
});

describe("the web UI", () => {
  it("falls back to the single-page app, and keeps API paths for the API", async () => {
    const webDir = mkdtempSync(join(tmpdir(), "access-web-"));
    writeFileSync(join(webDir, "index.html"), '<!doctype html><div id="root"></div>');
    const ui = await startApp({ version: "0.1.0", webDir });
    expect(await (await fetch(`${ui.base}/requests/abc`)).text()).toContain('<div id="root">');
    expect((await fetch(`${ui.base}/api/v1/nope`)).status).toBe(404);
    await ui.close();
  });
});
