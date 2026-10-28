// OpenSSH certificates and revocation lists, written by hand from OpenSSH's PROTOCOL.certkeys and PROTOCOL.krl, so
// the image needs no ssh-keygen (ADR 0061). The certificate authority is an Ed25519 key; people's own keys may be
// Ed25519, ECDSA, RSA or a security key, and never leave their computer.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

/** A fault in a public key someone sent, with the reason to show them. */
export class KeyError extends Error {}

// ---------------------------------------------------------------- wire format (RFC 4251)

const uint32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const uint64 = (n: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
};
const string = (v: string | Buffer) => {
  const b = typeof v === "string" ? Buffer.from(v, "utf8") : v;
  return Buffer.concat([uint32(b.length), b]);
};

/** Reads strings from a blob, and fails on anything that runs past its end. */
function reader(blob: Buffer) {
  let at = 0;
  return {
    string(): Buffer {
      if (at + 4 > blob.length) throw new KeyError("The key ends too early.");
      const n = blob.readUInt32BE(at);
      if (at + 4 + n > blob.length) throw new KeyError("The key ends too early.");
      const out = blob.subarray(at + 4, at + 4 + n);
      at += 4 + n;
      return out;
    },
    get done() {
      return at === blob.length;
    },
  };
}

// ---------------------------------------------------------------- people's public keys

/** Key types a certificate can be issued for, with the certificate type of each. */
const CERT_TYPES: Record<string, string> = {
  "ssh-ed25519": "ssh-ed25519-cert-v01@openssh.com",
  "sk-ssh-ed25519@openssh.com": "sk-ssh-ed25519-cert-v01@openssh.com",
  "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256-cert-v01@openssh.com",
  "ecdsa-sha2-nistp384": "ecdsa-sha2-nistp384-cert-v01@openssh.com",
  "ecdsa-sha2-nistp521": "ecdsa-sha2-nistp521-cert-v01@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com": "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
  "ssh-rsa": "ssh-rsa-cert-v01@openssh.com",
};

/** The length of an uncompressed ECDSA point on each curve. */
const POINT: Record<string, number> = { nistp256: 65, nistp384: 97, nistp521: 133 };

/** RSA keys shorter than this are refused; OpenSSH itself refuses under 1024 bits. */
const RSA_MIN_BITS = 2048;

export interface PublicKey {
  type: string;
  blob: Buffer;
  comment: string;
  /** As ssh-keygen -l prints it: SHA256:... */
  fingerprint: string;
}

export const fingerprint = (blob: Buffer) => `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;

/** Parses one line of an OpenSSH public key file, such as ~/.ssh/id_ed25519.pub, and checks its fields. */
export function parsePublicKey(line: string): PublicKey {
  const parts = line.trim().split(/\s+/);
  const [type, data] = parts;
  if (!type || !data) throw new KeyError("Paste one public key, such as the line in ~/.ssh/id_ed25519.pub.");
  if (type.includes("-cert-v01@")) throw new KeyError("That is a certificate; paste the public key it was made for.");
  if (/PRIVATE KEY/.test(line)) throw new KeyError("That is a private key. Never paste it anywhere; paste the .pub file.");
  if (!CERT_TYPES[type]) throw new KeyError(`${type} keys are not supported: use Ed25519, ECDSA, RSA or a security key.`);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(data)) throw new KeyError("The key is not base64.");
  const blob = Buffer.from(data, "base64");
  const r = reader(blob);
  if (r.string().toString("utf8") !== type) throw new KeyError("The key's type does not match its contents.");
  if (type === "ssh-ed25519" || type === "sk-ssh-ed25519@openssh.com") {
    if (r.string().length !== 32) throw new KeyError("An Ed25519 key is 32 bytes.");
  } else if (type.includes("ecdsa")) {
    const curve = r.string().toString("utf8");
    if (!type.includes(curve) || r.string().length !== POINT[curve]) throw new KeyError("The ECDSA key's curve or point is wrong.");
  } else {
    r.string(); // e
    const n = r.string();
    const bits = (n.length - (n[0] === 0 ? 1 : 0)) * 8;
    if (bits < RSA_MIN_BITS) throw new KeyError(`RSA keys must have at least ${RSA_MIN_BITS} bits; this one has ${bits}.`);
  }
  if (type.startsWith("sk-")) r.string(); // the security key's application, ssh: by default
  if (!r.done) throw new KeyError("The key has bytes after its end.");
  return { type, blob, comment: parts.slice(2).join(" "), fingerprint: fingerprint(blob) };
}

// ---------------------------------------------------------------- the certificate authority

export interface CaKey {
  /** One line, as sshd's TrustedUserCAKeys file takes it. */
  publicKey: string;
  /** PKCS#8 PEM; sealed before it is stored (ADR 0021). */
  privateKeyPem: string;
}

/** The SSH public key blob of an Ed25519 key. */
function ed25519Blob(key: KeyObject): Buffer {
  const x = key.export({ format: "jwk" }).x;
  if (!x) throw new Error("not an Ed25519 key");
  return Buffer.concat([string("ssh-ed25519"), string(Buffer.from(x, "base64url"))]);
}

export function generateCa(comment = "openasy-access"): CaKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: `ssh-ed25519 ${ed25519Blob(publicKey).toString("base64")} ${comment}`,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

/** The CA, ready to sign: its private key and its public blob, which goes in every certificate and every KRL. */
export function loadCa(privateKeyPem: string) {
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("the Access CA must be an Ed25519 key");
  const blob = ed25519Blob(createPublicKey(privateKey));
  return { privateKey, blob, fingerprint: fingerprint(blob) };
}

export type Ca = ReturnType<typeof loadCa>;

// ---------------------------------------------------------------- certificates (PROTOCOL.certkeys)

const SSH_CERT_TYPE_USER = 1;

export interface CertificateRequest {
  key: PublicKey;
  serial: bigint;
  /** Logged by sshd at every login with the certificate: who it is for and which grant. */
  keyId: string;
  principals: string[];
  validAfter: number;
  validBefore: number;
  /** Extensions without values, such as permit-pty. */
  extensions: string[];
}

/** A user certificate signed by the CA, as one line of an id_*-cert.pub file. */
export function signCertificate(ca: Ca, req: CertificateRequest): string {
  const certType = CERT_TYPES[req.key.type];
  if (!certType) throw new KeyError(`${req.key.type} keys are not supported.`);
  const keyFields = req.key.blob.subarray(reader(req.key.blob).string().length + 4);
  // Extensions and options are sorted by name, each a name and an empty value for a flag.
  const extensions = Buffer.concat([...req.extensions].sort().map((e) => Buffer.concat([string(e), string("")])));
  const body = Buffer.concat([
    string(certType),
    string(randomBytes(32)), // nonce
    keyFields,
    uint64(req.serial),
    uint32(SSH_CERT_TYPE_USER),
    string(req.keyId),
    string(Buffer.concat(req.principals.map((p) => string(p)))),
    uint64(BigInt(Math.floor(req.validAfter / 1000))),
    uint64(BigInt(Math.floor(req.validBefore / 1000))),
    string(""), // critical options: none
    string(extensions),
    string(""), // reserved
    string(ca.blob),
  ]);
  const signature = Buffer.concat([string("ssh-ed25519"), string(sign(null, body, ca.privateKey))]);
  return `${certType} ${Buffer.concat([body, string(signature)]).toString("base64")} ${req.keyId}`;
}

// ---------------------------------------------------------------- revocation (PROTOCOL.krl)

const KRL_MAGIC = 0x5353484b524c0a00n; // "SSHKRL\n\0"
const KRL_FORMAT_VERSION = 1;
const KRL_SECTION_CERTIFICATES = 1;
const KRL_SECTION_CERT_SERIAL_LIST = 0x20;

/**
 * A key revocation list for sshd's RevokedKeys: the serials of this CA's certificates that must no longer be
 * accepted. Without serials it revokes nothing, and sshd still needs the file to exist.
 */
export function revocationList(ca: Ca, serials: bigint[], version: bigint, generatedAt: number): Buffer {
  const header = Buffer.concat([
    uint64(KRL_MAGIC),
    uint32(KRL_FORMAT_VERSION),
    uint64(version),
    uint64(BigInt(Math.floor(generatedAt / 1000))),
    uint64(0n), // flags
    string(""), // reserved
    string("OpenAsy Access"),
  ]);
  if (!serials.length) return header;
  const sorted = [...new Set(serials)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const certs = Buffer.concat([
    string(ca.blob),
    string(""), // reserved
    Buffer.from([KRL_SECTION_CERT_SERIAL_LIST]),
    string(Buffer.concat(sorted.map(uint64))),
  ]);
  return Buffer.concat([header, Buffer.from([KRL_SECTION_CERTIFICATES]), string(certs)]);
}
