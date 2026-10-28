// What the search window (Cmd+K) finds in Access: servers by name and address, and requests by who asked, the
// principal and the reason. They are read whole and filtered here.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Inbox, Server as ServerIcon } from "lucide-react";
import type { AccessRequest, Server } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [{ servers }, { requests }] = await Promise.all([
      call<{ servers: Server[] }>("/api/v1/servers", { signal }),
      call<{ requests: AccessRequest[] }>("/api/v1/requests", { signal }),
    ]);
    const has = (...v: string[]) => v.some((x) => x.toLowerCase().includes(q));
    return [
      ...servers
        .filter((s) => has(s.name, s.address, s.description))
        .slice(0, 5)
        .map((s): SearchResult => ({
          id: `server:${s.id}`,
          label: s.name,
          detail: s.address,
          kind: t("search.server"),
          icon: ServerIcon,
          href: `/servers?id=${s.id}`,
        })),
      ...requests
        .filter((r) => has(r.principal, r.requester.name, r.requester.email, r.reason, r.ticket))
        .slice(0, 8)
        .map((r): SearchResult => ({
          id: `request:${r.id}`,
          label: `${r.principal} · ${r.requester.name}`,
          detail: t(`statuses.${r.status}`),
          kind: t("search.request"),
          icon: Inbox,
          severity: r.status === "pending" ? "medium" : undefined,
          href: `/requests/${r.id}`,
        })),
    ];
  };
}
