import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { AccessError, type Access, type Actor, type ProblemCode } from "./access.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";

export interface AppOptions {
  db: DatabaseSync;
  access: Access;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(access: Access, version: string) {
  return renderMetrics(version, access.gauges());
}

/** Serves only /metrics, for a port that is not exposed with the rest (ACCESS_METRICS_PORT). */
export function createMetricsHandler(access: Access, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(access, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) =>
  send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  forbidden: "Forbidden",
  "mfa-required": "Second factor required",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) throw new AccessError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new AccessError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003). */
type Need = "none" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request: a person, with whether they used a second factor, or a token. */
  actor: () => Actor;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Need;
  handle: (ctx: Ctx) => unknown;
}

export function createApp({ db, access, version, auth, adminToken, webDir, docsDir, openapi, serveMetrics = true, products = [] }: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "access", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => access.summary() },

    // What servers trust: the CA's public key, and the certificates ended before their time. Neither is a secret, and
    // a server's cron job fetches the list without a token.
    { method: "GET", path: "/api/v1/ca", auth: "none", handle: () => access.ca() },
    {
      method: "GET",
      path: "/api/v1/revoked.krl",
      auth: "none",
      handle: ({ res }) => send(res, 200, access.revoked(), "application/octet-stream", { "cache-control": "no-store" }),
    },

    // Servers and their policy: logins, longest grant, approvals. Admins keep them.
    { method: "GET", path: "/api/v1/servers", auth: "viewer", handle: () => ({ servers: access.servers() }) },
    {
      method: "POST",
      path: "/api/v1/servers",
      auth: "admin",
      handle: async ({ res, body, actor }) => json(res, 201, access.saveServer(null, await body(), actor())),
    },
    { method: "GET", path: "/api/v1/servers/:id", auth: "viewer", handle: ({ params }) => access.server(params[0]!) },
    {
      method: "PUT",
      path: "/api/v1/servers/:id",
      auth: "admin",
      handle: async ({ params, body, actor }) => access.saveServer(params[0]!, await body(), actor()),
    },
    {
      method: "DELETE",
      path: "/api/v1/servers/:id",
      auth: "admin",
      handle: ({ res, params, actor }) => (access.deleteServer(params[0]!, actor()), noContent(res)),
    },
    {
      method: "GET",
      path: "/api/v1/servers/:id/setup",
      auth: "viewer",
      handle: ({ res, params }) => send(res, 200, access.serverSetup(params[0]!), "text/plain; charset=utf-8"),
    },

    // Requests: anyone signed in asks for themselves; an editor other than the requester approves.
    {
      method: "GET",
      path: "/api/v1/requests",
      auth: "viewer",
      handle: ({ url, actor }) => {
        const mine = url.searchParams.get("mine") === "true";
        const me = actor().person;
        return { requests: access.requests({ status: url.searchParams.get("status"), requesterId: mine ? (me?.id ?? "-") : undefined }) };
      },
    },
    {
      method: "POST",
      path: "/api/v1/requests",
      auth: "viewer",
      handle: async ({ res, body, actor }) => json(res, 201, access.createRequest(await body(), actor())),
    },
    { method: "GET", path: "/api/v1/requests/:id", auth: "viewer", handle: ({ params }) => access.request(params[0]!) },
    {
      method: "POST",
      path: "/api/v1/requests/:id/approve",
      auth: "editor",
      handle: async ({ params, body, actor }) => access.approve(params[0]!, await body(), actor()),
    },
    {
      method: "POST",
      path: "/api/v1/requests/:id/deny",
      auth: "editor",
      handle: async ({ params, body, actor }) => access.deny(params[0]!, await body(), actor()),
    },
    { method: "POST", path: "/api/v1/requests/:id/cancel", auth: "viewer", handle: ({ params, actor }) => access.cancel(params[0]!, actor()) },
    {
      method: "POST",
      path: "/api/v1/requests/:id/end",
      auth: "viewer",
      handle: async ({ params, body, actor }) => access.end(params[0]!, await body(), actor()),
    },
    {
      method: "POST",
      path: "/api/v1/requests/:id/certificates",
      auth: "viewer",
      handle: async ({ res, params, body, actor }) => json(res, 201, access.issueCertificate(params[0]!, await body(), actor())),
    },

    // The audit log, for auditors and for a SIEM.
    {
      method: "GET",
      path: "/api/v1/audit",
      auth: "viewer",
      handle: ({ url }) => {
        const limit = Number(url.searchParams.get("limit") ?? 100);
        if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new AccessError(422, "invalid-body", "limit is a whole number from 1 to 500.");
        return access.events({ kind: url.searchParams.get("kind"), cursor: url.searchParams.get("cursor") }, limit);
      },
    },
    {
      method: "GET",
      path: "/api/v1/audit/export",
      auth: "viewer",
      handle: ({ res }) =>
        send(res, 200, access.exportCsv(), "text/csv; charset=utf-8", {
          "content-disposition": `attachment; filename="access-audit-${new Date().toISOString().slice(0, 10)}.csv"`,
        }),
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/[.]/g, "\\.").replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null for a route that needs nobody. */
  function authorize(req: IncomingMessage, need: Need): Actor | null {
    if (need === "none") return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return { name: "admin token", role: "admin", mfa: false };
    const p = auth.authorize(req, need);
    if (p.kind === "token") return { name: `API token ${p.name}`, role: p.role, mfa: false };
    // People who sign in through an identity provider use its second factor (ADR 0002).
    return { person: { id: p.user.id, email: p.user.email, name: p.user.name }, name: p.user.name, role: p.role, mfa: p.mfa || p.method.startsWith("oidc:") };
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to sign as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(access, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const actor = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({
          req,
          res,
          url,
          params,
          body: () => readJson(req),
          actor: () => actor ?? { name: "unknown", role: "viewer", mfa: false },
        });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof AccessError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
