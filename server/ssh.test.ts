import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fingerprint, generateCa, loadCa, parsePublicKey, revocationList, signCertificate } from "./ssh.ts";

// OpenSSH's own ssh-keygen reads what we write: it checks a certificate's signature as it parses it, and answers
// whether a KRL revokes one. CI has it; without it these checks are skipped.
const sshKeygen = (() => {
  try {
    execFileSync("ssh-keygen", ["-?"], { stdio: "ignore" });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== "ENOENT";
  }
})();

const dir = mkdtempSync(join(tmpdir(), "access-ssh-"));
const keygen = (...args: string[]) => execFileSync("ssh-keygen", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

/** An Ed25519 public key line, as ~/.ssh/id_ed25519.pub holds it. */
function ed25519Line(comment = "ece@laptop") {
  const { publicKey } = generateKeyPairSync("ed25519");
  const x = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
  const s = (b: Buffer) => Buffer.concat([Buffer.from([0, 0, 0, b.length]), b]);
  return `ssh-ed25519 ${Buffer.concat([s(Buffer.from("ssh-ed25519")), s(x)]).toString("base64")} ${comment}`;
}

const ca = loadCa(generateCa().privateKeyPem);
const now = Date.parse("2026-10-28T09:00:00Z");

describe("public keys", () => {
  it("reads an Ed25519 key with its comment and fingerprint", () => {
    const line = ed25519Line("ece@laptop work");
    const key = parsePublicKey(`  ${line}\n`);
    expect(key).toMatchObject({ type: "ssh-ed25519", comment: "ece@laptop work" });
    expect(key.fingerprint).toBe(fingerprint(key.blob));
    expect(key.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("refuses private keys, certificates, other types and damaged keys", () => {
    expect(() => parsePublicKey("-----BEGIN OPENSSH PRIVATE KEY----- abc")).toThrow(/private key/);
    expect(() => parsePublicKey("ssh-ed25519-cert-v01@openssh.com AAAA")).toThrow(/certificate/);
    expect(() => parsePublicKey("ssh-dss AAAAB3NzaC1kc3M=")).toThrow(/not supported/);
    expect(() => parsePublicKey("ssh-ed25519")).toThrow(/Paste one public key/);
    expect(() => parsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==")).toThrow(/ends too early/);
    const [, data] = ed25519Line().split(" ");
    expect(() => parsePublicKey(`ssh-rsa ${data}`)).toThrow(/does not match/);
    expect(() => parsePublicKey(`ssh-ed25519 ${Buffer.concat([Buffer.from(data!, "base64"), Buffer.from([0])]).toString("base64")}`)).toThrow(/after its end/);
  });

  it.skipIf(!sshKeygen)("reads every type ssh-keygen makes, and refuses short RSA keys", () => {
    for (const [type, bits] of [
      ["ed25519", ""],
      ["ecdsa", "256"],
      ["ecdsa", "521"],
      ["rsa", "3072"],
    ] as const) {
      const file = join(dir, `id_${type}${bits}`);
      keygen("-q", "-t", type, ...(bits ? ["-b", bits] : []), "-N", "", "-C", "test", "-f", file);
      const key = parsePublicKey(readFileSync(`${file}.pub`, "utf8"));
      expect(`${key.fingerprint} test`).toBe(keygen("-l", "-E", "sha256", "-f", `${file}.pub`).split(" ").slice(1, 3).join(" "));
    }
    keygen("-q", "-t", "rsa", "-b", "1024", "-N", "", "-f", join(dir, "id_short"));
    expect(() => parsePublicKey(readFileSync(join(dir, "id_short.pub"), "utf8"))).toThrow(/at least 2048 bits/);
  });
});

describe("certificates", () => {
  const sign = (line: string, serial = 7n) =>
    signCertificate(ca, {
      key: parsePublicKey(line),
      serial,
      keyId: "ece@example.com access r-1",
      principals: ["deploy@web-1"],
      validAfter: now - 60_000,
      validBefore: now + 3_600_000,
      extensions: ["permit-pty"],
    });

  it("are one line of the certificate type, named by their key ID", () => {
    const cert = sign(ed25519Line());
    expect(cert).toMatch(/^ssh-ed25519-cert-v01@openssh\.com [A-Za-z0-9+/=]+ ece@example\.com access r-1$/);
  });

  it.skipIf(!sshKeygen)("are read and their signature checked by ssh-keygen, with the grant's principal and times", () => {
    for (const name of ["id_ed25519", "id_ecdsa256", "id_rsa3072"]) {
      const file = join(dir, `${name}-cert.pub`);
      writeFileSync(file, sign(readFileSync(join(dir, `${name}.pub`), "utf8")) + "\n");
      const out = keygen("-L", "-f", file);
      expect(out).toContain("user certificate");
      expect(out).toContain(`Signing CA: ED25519 ${ca.fingerprint}`);
      expect(out).toContain('Key ID: "ece@example.com access r-1"');
      expect(out).toContain("Serial: 7");
      expect(out).toMatch(/Principals: \n\s+deploy@web-1\n/);
      expect(out).toMatch(/Critical Options: \(none\)/);
      expect(out).toMatch(/Extensions: \n\s+permit-pty\n/);
    }
  });
});

describe("revocation lists", () => {
  it("start with the KRL header, and name nothing when nothing is revoked", () => {
    const empty = revocationList(ca, [], 1n, now);
    expect(empty.subarray(0, 8).toString("latin1")).toBe("SSHKRL\n\0");
    expect(empty.length).toBe(8 + 4 + 8 + 8 + 8 + 4 + 4 + "OpenAsy Access".length);
  });

  it.skipIf(!sshKeygen)("revoke exactly the serials named, as ssh-keygen reads them", () => {
    const line = readFileSync(join(dir, "id_ed25519.pub"), "utf8");
    const keep = join(dir, "keep-cert.pub");
    const drop = join(dir, "drop-cert.pub");
    writeFileSync(keep, sign(line, 8n) + "\n");
    writeFileSync(drop, sign(line, 9n) + "\n");
    const krl = join(dir, "revoked.krl");
    writeFileSync(krl, revocationList(ca, [9n, 3n, 9n], 2n, now));
    expect(keygen("-Q", "-f", krl, keep)).toContain(": ok");
    expect(() => keygen("-Q", "-f", krl, drop)).toThrow();
    expect(keygen("-Q", "-l", "-f", krl)).toMatch(/serial: 3\nserial: 9/);
  });

  function sign(line: string, serial: bigint) {
    return signCertificate(ca, {
      key: parsePublicKey(line),
      serial,
      keyId: "k",
      principals: ["deploy@web-1"],
      validAfter: Date.now() - 60_000,
      validBefore: Date.now() + 3_600_000,
      extensions: [],
    });
  }
});
