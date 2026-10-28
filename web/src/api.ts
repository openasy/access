// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type RequestStatus = "pending" | "active" | "ended" | "denied" | "cancelled" | "revoked";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Person {
  id: string;
  email: string;
  name: string;
}

export interface Server {
  id: string;
  name: string;
  address: string;
  port: number;
  description: string;
  logins: string[];
  maxMinutes: number;
  approvals: 1 | 2;
  createdAt: string;
  updatedAt: string;
  active: number;
}

export interface AccessRequest {
  id: string;
  server: { id: string; name: string };
  login: string;
  principal: string;
  minutes: number;
  reason: string;
  ticket: string;
  requester: Person;
  status: RequestStatus;
  createdAt: string;
  startsAt: string | null;
  endsAt: string | null;
  approvalsNeeded: number;
  approvals: Array<{ by: Person; comment: string; at: string }>;
  closed: { by: string; at: string; comment: string } | null;
}

export interface Certificate {
  serial: number;
  keyType: string;
  fingerprint: string;
  principal: string;
  validAfter: string;
  validBefore: string;
  issuedAt: string;
  revoked: boolean;
}

export interface AuditEvent {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  result: "success" | "denied";
  detail: string;
  requestId: string | null;
}

export type RequestDetail = AccessRequest & { certificates: Certificate[]; events: AuditEvent[] };

export interface IssuedCertificate {
  serial: number;
  certificate: string;
  principal: string;
  fingerprint: string;
  validAfter: string;
  validBefore: string;
  command: string | null;
}

export interface Summary {
  requests: { pending: number; lastDay: number };
  grants: { active: number };
  certificates: { lastDay: number };
  servers: number;
  medianWaitMinutes: number | null;
  perDay: Array<{ day: string; requests: number; granted: number }>;
  pending: AccessRequest[];
  active: AccessRequest[];
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return ((res.headers.get("content-type") ?? "").includes("json") ? await res.json() : await res.text()) as T;
}
