import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createAccess } from "./access.ts";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createKeyring } from "./kek.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.ACCESS_DB ?? "/data/access.db";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.ACCESS_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.ACCESS_METRICS_PORT ? Number(process.env.ACCESS_METRICS_PORT) : undefined;
const pendingHours = Number(process.env.ACCESS_PENDING_HOURS ?? 24);
if (!Number.isInteger(pendingHours) || pendingHours < 1 || pendingHours > 168)
  throw new Error("ACCESS_PENDING_HOURS must be a whole number of hours, 1 to 168");

// The CA's private key and sign-in secrets are sealed with it (ADR 0021): Access does not start without it.
const secretsKeyFile = process.env.ACCESS_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const kek = readSecretsKey(secretsKeyFile);
if (!kek) {
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32) and set ACCESS_SECRETS_KEY_FILE if not at the default", {
    file: secretsKeyFile,
  });
  process.exit(1);
}

const db = openDb(dbPath);
// The address people open Access at, behind the TLS proxy (ADR 0026). Cookies, passkeys, OIDC redirects and the
// servers' setup use it.
const publicUrl = (process.env.ACCESS_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
// A CA sealed with another key cannot be opened; Access stops rather than make a new one servers do not trust.
const access = (() => {
  try {
    // Every event of the audit log also goes to stdout, for a SIEM to collect (ADR 0013, 0017).
    return createAccess(db, {
      keyring: createKeyring(kek),
      publicUrl,
      pendingHours,
      onEvent: (event) => log(event.result === "denied" ? "warn" : "info", "audit", { event }),
    });
  } catch (err) {
    log("error", (err as Error).message, { file: secretsKeyFile });
    process.exit(1);
  }
})();
const auth = createAuth({
  db,
  product: "access",
  productName: "OpenAsy Access",
  origin: publicUrl,
  // Locally the same Access is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.ACCESS_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "ACCESS_"),
  secretsKey: kek,
  // Every sign-in, failure and change to members and tokens joins the audit log (ADR 0013).
  onEvent: (event) => access.recordAuth(event),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

const server = createServer(
  createApp({
    db,
    access,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(access, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "access started", { version, port, db: dbPath, headless, pendingHours, ca: access.ca().fingerprint }));
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "ACCESS_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put Access behind TLS (ADR 0026)", { url: publicUrl });
}
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

// Grants end at their time even when nobody opens a screen, so the audit log says when.
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(() => access.tick(), 15_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
