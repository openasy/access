import { describe, expect, it } from "vitest";
import { createKeyring } from "./kek.ts";

describe("keyring", () => {
  const kek = Buffer.alloc(32, 1);

  it("seals each secret with its own data key, and only the same key opens it", () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI...\n-----END PRIVATE KEY-----\n";
    const a = createKeyring(kek).seal(pem);
    const b = createKeyring(kek).seal(pem);
    expect(a).toMatch(/^v1\.[\w-]+\.[\w-]+$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain("PRIVATE");
    expect(createKeyring(kek).open(a).toString()).toBe(pem);
    expect(() => createKeyring(Buffer.alloc(32, 2)).open(a)).toThrow();
  });

  it("needs a 32-byte key", () => {
    expect(() => createKeyring(Buffer.alloc(16))).toThrow(/32 bytes/);
  });
});
