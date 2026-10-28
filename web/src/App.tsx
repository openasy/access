import {
  AppShell,
  Avatar,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  EmptyState,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SelectField,
  StatusBadge,
  Tabs,
  TextField,
  TimeSeriesChart,
  toLocale,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  Check,
  Download,
  History,
  Inbox,
  KeyRound,
  LogIn,
  LogOut,
  Plus,
  ScrollText,
  Server as ServerIcon,
  ShieldCheck,
  Square,
  TerminalSquare,
  Timer,
  Trash2,
  UserRound,
  Users,
  Wrench,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type AccessRequest,
  type AuditEvent,
  type IssuedCertificate,
  type Person as PersonInfo,
  type ProductLink,
  type RequestDetail,
  type RequestStatus,
  type Server,
  type Summary,
} from "./api.ts";
import { useT } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["open", "history", "servers", "audit", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Route = { page: "overview" | (typeof PAGES)[number] } | { page: "request"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["overview", "requests", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "requests" && id) return { page: "request", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "overview" };
}

/** A query parameter of the address. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads a list once and on demand, for the pages that change what they show. */
function useList<T>(call: Call, path: string, key: string) {
  const [items, setItems] = useState<T[]>();
  const load = useCallback(
    () =>
      void call<Record<string, T[]>>(path).then(
        (r) => setItems(r[key]),
        () => setItems([]),
      ),
    [call, path, key],
  );
  useEffect(load, [load]);
  return [items, load] as const;
}

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const day = (iso: string) => new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });

/** Runs a change and reports its error, the way every form here does. */
function useAction(after: () => void) {
  const [error, setError] = useState<string>();
  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        setError(undefined);
        after();
        return true;
      } catch (err) {
        setError((err as Error).message);
        return false;
      }
    },
    [after],
  );
  return [run, error] as const;
}

/** The signed-in person, and whether the API will let them ask for, approve and use access. */
function useMe() {
  const { me, can } = useAuth();
  // People who sign in through an identity provider use its second factor (ADR 0002).
  const strong = me.session.mfa || me.session.method.startsWith("oidc:");
  return { me: me.user, strong, can, isMine: (r: AccessRequest) => r.requester.id === me.user.id };
}

const STATUS_TONE: Record<RequestStatus, Tone> = {
  pending: "warning",
  active: "success",
  ended: "neutral",
  denied: "danger",
  cancelled: "neutral",
  revoked: "danger",
};

function StatusOf({ status }: { status: RequestStatus }) {
  const t = useT();
  return <StatusBadge tone={STATUS_TONE[status]}>{t(`statuses.${status}`)}</StatusBadge>;
}

function Person({ person }: { person: PersonInfo }) {
  return (
    <span className="flex min-w-0 items-center gap-2">
      <Avatar name={person.name} size="sm" />
      <span className="flex min-w-0 flex-col">
        <span className="truncate font-medium">{person.name}</span>
        <span className="truncate text-2xs text-fg-muted">{person.email}</span>
      </span>
    </span>
  );
}

function Code({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <pre
      tabIndex={0}
      aria-label={label}
      className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap break-all text-fg"
    >
      {children}
    </pre>
  );
}

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

/** Minutes as people say them: 30 min, 1 h, 1 h 30 min. */
function useDuration() {
  const t = useT();
  return (m: number) =>
    m < 60 ? t("time.minutes", { count: m }) : m % 60 ? t("time.hoursMinutes", { h: Math.floor(m / 60), m: m % 60 }) : t("time.hours", { count: m / 60 });
}

/** How long a grant has left, from the page's clock. */
function useLeft() {
  const duration = useDuration();
  return (endsAt: string | null) => (endsAt ? duration(Math.max(0, Math.ceil((Date.parse(endsAt) - Date.now()) / 60_000))) : "–");
}

// ---------------------------------------------------------------- Requests

/** One request waiting for a decision: who, what, how long and why, with what the viewer may do about it. */
function PendingItem({ r, call, onDone }: { r: AccessRequest; call: Call; onDone: () => void }) {
  const t = useT();
  const duration = useDuration();
  const { can, isMine, strong } = useMe();
  const [comment, setComment] = useState("");
  const [run, error] = useAction(onDone);
  const decide = (verb: "approve" | "deny") => void run(() => call(`/api/v1/requests/${r.id}/${verb}`, { method: "POST", body: JSON.stringify({ comment }) }));
  const mine = isMine(r);
  return (
    <li className="access-pending">
      <Person person={r.requester} />
      <div className="flex min-w-0 flex-col gap-1">
        <span className="flex flex-wrap items-center gap-1.5 text-sm">
          <a href={`/requests/${r.id}`} className="font-mono font-medium">
            {r.principal}
          </a>
          <span className="font-medium">{t("requestsPage.forDuration", { duration: duration(r.minutes) })}</span>
          <span className="text-2xs text-fg-muted">· {when(r.createdAt)}</span>
          {r.approvalsNeeded > 1 && <Badge>{t("requestsPage.approvalsOf", { n: r.approvals.length, of: r.approvalsNeeded })}</Badge>}
        </span>
        <span className="text-sm text-fg-muted">
          {r.ticket && <span className="font-mono text-xs text-fg">{r.ticket} </span>}
          {r.reason}
        </span>
        {!mine && can("editor") && strong && (
          <TextField
            label={t("requestsPage.comment")}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder={t("requestsPage.commentPlaceholder")}
          />
        )}
        <ErrorText message={error} />
      </div>
      <div className="flex items-center justify-end gap-1.5">
        {mine ? (
          <>
            <Badge tone="info">{t("requestsPage.yours")}</Badge>
            <Button size="sm" onClick={() => void run(() => call(`/api/v1/requests/${r.id}/cancel`, { method: "POST" }))}>
              {t("requestsPage.cancel")}
            </Button>
          </>
        ) : can("editor") && strong ? (
          <>
            <Button
              size="sm"
              variant="primary"
              icon={<Check />}
              aria-label={t("requestsPage.approveWho", { who: r.requester.name })}
              onClick={() => decide("approve")}
            >
              {t("requestsPage.approve")}
            </Button>
            <Button size="sm" icon={<X />} aria-label={t("requestsPage.denyWho", { who: r.requester.name })} onClick={() => decide("deny")}>
              {t("requestsPage.deny")}
            </Button>
          </>
        ) : (
          <StatusOf status="pending" />
        )}
      </div>
    </li>
  );
}

function AskForm({ call, servers, onDone }: { call: Call; servers: Server[]; onDone: (id: string) => void }) {
  const t = useT();
  const duration = useDuration();
  const [serverId, setServerId] = useState(param("server") ?? servers[0]?.id ?? "");
  const server = servers.find((s) => s.id === serverId) ?? servers[0];
  const [login, setLogin] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState("");
  const [error, setError] = useState<string>();
  if (!server) return null;
  const chosenLogin = server.logins.includes(login) ? login : server.logins[0]!;
  const choices = [15, 30, 60, 120, 240, 480, 720, 1440].filter((m) => m <= server.maxMinutes);
  if (!choices.includes(server.maxMinutes)) choices.push(server.maxMinutes);
  const chosenMinutes = Math.min(Number(minutes), server.maxMinutes);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void call<AccessRequest>("/api/v1/requests", {
      method: "POST",
      body: JSON.stringify({ serverId: server.id, login: chosenLogin, minutes: chosenMinutes, reason, ...(ticket.trim() && { ticket }) }),
    }).then(
      (r) => (setError(undefined), setReason(""), setTicket(""), onDone(r.id)),
      (err: Error) => setError(err.message),
    );
  };
  return (
    <form className="flex flex-col gap-2.5" onSubmit={submit} aria-label={t("requestsPage.ask")}>
      <div className="access-cols-3">
        <SelectField
          label={t("requestsPage.server")}
          value={server.id}
          onChange={(e) => setServerId(e.target.value)}
          options={servers.map((s) => ({ value: s.id, label: s.name }))}
        />
        <SelectField
          label={t("requestsPage.login")}
          value={chosenLogin}
          onChange={(e) => setLogin(e.target.value)}
          options={server.logins.map((l) => ({ value: l, label: l }))}
        />
        <SelectField
          label={t("requestsPage.duration")}
          value={String(choices.includes(chosenMinutes) ? chosenMinutes : choices[0])}
          onChange={(e) => setMinutes(e.target.value)}
          options={choices.map((m) => ({ value: String(m), label: duration(m) }))}
        />
      </div>
      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">{t("requestsPage.reason")}</span>
        <textarea
          className="access-textarea"
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t("requestsPage.reasonPlaceholder")}
        />
      </label>
      <TextField
        label={t("requestsPage.ticket")}
        mono
        value={ticket}
        onChange={(e) => setTicket(e.target.value)}
        placeholder="INC-2291"
        hint={t("requestsPage.ticketHint")}
      />
      <p className="m-0 text-xs text-fg-muted">
        {server.approvals > 1 ? t("requestsPage.needsTwo") : t("requestsPage.needsOne")}{" "}
        {t("requestsPage.principal", { principal: `${chosenLogin}@${server.name}` })}
      </p>
      <ErrorText message={error} />
      <div>
        <Button type="submit" variant="primary" icon={<Plus />} disabled={reason.trim().length < 10}>
          {t("requestsPage.send")}
        </Button>
      </div>
    </form>
  );
}

function useRequestColumns(): Column<AccessRequest>[] {
  const t = useT();
  const duration = useDuration();
  return [
    { id: "who", header: t("requestsPage.who"), width: "24%", sortValue: (r) => r.requester.name, cell: (r) => <Person person={r.requester} /> },
    {
      id: "what",
      header: t("requestsPage.what"),
      sortValue: (r) => r.principal,
      cell: (r) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-mono text-xs font-medium">{r.principal}</span>
          <span className="access-clamp text-2xs text-fg-muted" title={r.reason}>
            {r.ticket ? `${r.ticket} ` : ""}
            {r.reason}
          </span>
        </span>
      ),
    },
    { id: "for", header: t("requestsPage.duration"), width: "100px", align: "right", sortValue: (r) => r.minutes, cell: (r) => duration(r.minutes) },
    { id: "status", header: t("requestsPage.status"), width: "120px", sortValue: (r) => r.status, cell: (r) => <StatusOf status={r.status} /> },
    {
      id: "at",
      header: t("requestsPage.asked"),
      width: "150px",
      align: "right",
      sortValue: (r) => r.createdAt,
      cell: (r) => <span className="whitespace-nowrap text-fg-muted">{when(r.createdAt)}</span>,
    },
  ];
}

function RequestsPage({ call, summary, reload }: { call: Call; summary: Summary; reload: () => void }) {
  const t = useT();
  const { strong, can } = useMe();
  const [servers] = useList<Server>(call, "/api/v1/servers", "servers");
  const [mine, loadMine] = useList<AccessRequest>(call, "/api/v1/requests?mine=true", "requests");
  const columns = useRequestColumns();
  const after = useCallback(() => {
    loadMine();
    reload();
  }, [loadMine, reload]);
  const s = summary;
  return (
    <>
      <PageHeader
        title={t("requestsPage.requests")}
        description={t("requestsPage.description", { count: s.servers })}
        meta={
          <StatusBadge tone={s.requests.pending ? "warning" : "success"}>
            {s.requests.pending ? t("requestsPage.pending", { count: s.requests.pending }) : t("requestsPage.allDecided")}
          </StatusBadge>
        }
      />
      {!strong && (
        <Callout
          tone="warning"
          title={t("requestsPage.needFactor")}
          action={
            <Button size="sm" onClick={() => navigate("/account")}>
              {t("product.account")}
            </Button>
          }
        >
          {t("requestsPage.needFactorDetail")}
        </Callout>
      )}
      <KpiGrid minWidth={150}>
        <KpiCard label={t("requestsPage.waiting")} value={s.requests.pending} icon={Inbox} tone={s.requests.pending ? "warning" : undefined} />
        <KpiCard label={t("requestsPage.openNow")} value={s.grants.active} icon={TerminalSquare} href="/open" />
        <KpiCard
          label={t("requestsPage.medianWait")}
          value={s.medianWaitMinutes === null ? "–" : s.medianWaitMinutes}
          unit={s.medianWaitMinutes === null ? undefined : t("requestsPage.min")}
          icon={Timer}
        />
        <KpiCard
          label={t("requestsPage.certificates24h")}
          value={s.certificates.lastDay}
          icon={KeyRound}
          trend={s.perDay.map((d) => d.granted)}
          href="/audit?kind=certificate"
        />
      </KpiGrid>
      <Panel title={t("requestsPage.waitingTitle")} description={can("editor") ? t("requestsPage.waitingEditor") : t("requestsPage.waitingViewer")} flush>
        {s.pending.length ? (
          <ul aria-label={t("requestsPage.waitingTitle")} className="flex flex-col">
            {s.pending.map((r) => (
              <PendingItem key={r.id} r={r} call={call} onDone={after} />
            ))}
          </ul>
        ) : (
          <EmptyState title={t("requestsPage.noneWaiting")}>{t("requestsPage.noneWaitingDetail")}</EmptyState>
        )}
      </Panel>
      {strong && servers && servers.length > 0 && (
        <Panel title={t("requestsPage.ask")} description={t("requestsPage.askDetail")}>
          <AskForm call={call} servers={servers} onDone={(id) => (after(), navigate(`/requests/${id}`))} />
        </Panel>
      )}
      <Panel title={t("requestsPage.mine")} flush>
        <DataTable
          label={t("requestsPage.mine")}
          columns={columns}
          rows={mine ?? []}
          loading={!mine}
          getRowId={(r) => r.id}
          onRowClick={(r) => navigate(`/requests/${r.id}`)}
          defaultSort={{ id: "at", direction: "desc" }}
          minWidth={760}
          empty={<EmptyState title={t("requestsPage.noneMine")} />}
        />
      </Panel>
      <Panel title={t("requestsPage.perDay")} description={t("requestsPage.perDayDetail")}>
        <TimeSeriesChart
          label={t("requestsPage.perDay")}
          labels={s.perDay.map((d) => day(d.day))}
          height={160}
          series={[
            { id: "requests", name: t("requestsPage.asked"), data: s.perDay.map((d) => d.requests) },
            { id: "granted", name: t("requestsPage.granted"), data: s.perDay.map((d) => d.granted) },
          ]}
        />
      </Panel>
    </>
  );
}

/** The first screen, until there is a server to ask for. */
function WelcomePage() {
  const t = useT();
  const { can } = useMe();
  return (
    <>
      <PageHeader title={t("welcomePage.getStarted")} description={t("welcomePage.description")} />
      <Panel title={t("welcomePage.steps")}>
        <ol className="access-steps text-sm">
          <li>{t("welcomePage.step1")}</li>
          <li>{t("welcomePage.step2")}</li>
          <li>{t("welcomePage.step3")}</li>
          <li>{t("welcomePage.step4")}</li>
        </ol>
        <div className="mt-3 flex flex-wrap gap-2">
          {can("admin") ? (
            <Button variant="primary" icon={<ServerIcon />} onClick={() => navigate("/servers")}>
              {t("welcomePage.addServer")}
            </Button>
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("welcomePage.askAdmin")}</p>
          )}
        </div>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- One request

function CertificateForm({ call, id, onDone }: { call: Call; id: string; onDone: () => void }) {
  const t = useT();
  const [publicKey, setPublicKey] = useState("");
  const [issued, setIssued] = useState<IssuedCertificate>();
  const [error, setError] = useState<string>();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void call<IssuedCertificate>(`/api/v1/requests/${id}/certificates`, { method: "POST", body: JSON.stringify({ publicKey }) }).then(
      (c) => (setIssued(c), setError(undefined), onDone()),
      (err: Error) => setError(err.message),
    );
  };
  // Named as ssh looks for it next to the key it was made for: id_ed25519-cert.pub, id_ecdsa-cert.pub or id_rsa-cert.pub.
  const fileName = (c: IssuedCertificate) =>
    `id_${c.certificate.startsWith("ssh-rsa") ? "rsa" : c.certificate.includes("ecdsa") ? "ecdsa" : "ed25519"}${c.certificate.startsWith("sk-") ? "_sk" : ""}-cert.pub`;
  return (
    <div className="flex flex-col gap-2.5">
      <form className="flex flex-col gap-2.5" onSubmit={submit} aria-label={t("requestPage.getCertificate")}>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">{t("requestPage.publicKey")}</span>
          <textarea
            className="access-textarea"
            rows={3}
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… you@laptop"
            spellCheck={false}
          />
          <span className="text-xs text-fg-muted">{t("requestPage.publicKeyHint")}</span>
        </label>
        <ErrorText message={error} />
        <div>
          <Button type="submit" variant="primary" icon={<KeyRound />} disabled={!publicKey.trim()}>
            {t("requestPage.getCertificate")}
          </Button>
        </div>
      </form>
      {issued && (
        <Callout tone="success" title={t("requestPage.issued", { serial: issued.serial, until: when(issued.validBefore) })}>
          <div className="flex flex-col gap-2">
            <span>{t("requestPage.save")}</span>
            <Code label={t("requestPage.certificate")}>{issued.certificate}</Code>
            <div>
              <a className="text-sm" href={`data:text/plain;charset=utf-8,${encodeURIComponent(`${issued.certificate}\n`)}`} download={fileName(issued)}>
                <Download className="inline size-3.5" aria-hidden /> {t("requestPage.download", { file: fileName(issued) })}
              </a>
            </div>
            {issued.command && (
              <>
                <span>{t("requestPage.then")}</span>
                <Code label={t("requestPage.command")}>{issued.command}</Code>
              </>
            )}
          </div>
        </Callout>
      )}
    </div>
  );
}

function RequestPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const t = useT();
  const duration = useDuration();
  const left = useLeft();
  const { can, isMine, strong } = useMe();
  const [r, setR] = useState<RequestDetail | null>();
  const load = useCallback(() => void call<RequestDetail>(`/api/v1/requests/${encodeURIComponent(id)}`).then(setR, () => setR(null)), [call, id]);
  useEffect(load, [load]);
  const after = useCallback(() => {
    load();
    reload();
  }, [load, reload]);
  const [run, error] = useAction(after);
  if (r === null)
    return (
      <EmptyState title={t("requestPage.notFound")} action={<Button onClick={() => navigate("/")}>{t("requestPage.back")}</Button>}>
        {t("requestPage.notFoundDetail")}
      </EmptyState>
    );
  if (!r) return <EmptyState title={t("product.loading")} icon={<Inbox />} />;
  const mine = isMine(r);
  const end = () => void run(() => call(`/api/v1/requests/${r.id}/end`, { method: "POST", body: "{}" }));
  const facts: Array<[string, ReactNode]> = [
    [t("requestPage.requester"), <Person key="p" person={r.requester} />],
    [
      t("requestPage.server"),
      <a key="s" href={`/servers?id=${r.server.id}`}>
        {r.server.name}
      </a>,
    ],
    [
      t("requestPage.login"),
      <span key="l" className="font-mono">
        {r.login}
      </span>,
    ],
    [t("requestsPage.duration"), duration(r.minutes)],
    [t("requestsPage.reason"), r.reason],
    ...(r.ticket
      ? ([
          [
            t("requestsPage.ticket"),
            <span key="t" className="font-mono">
              {r.ticket}
            </span>,
          ],
        ] as Array<[string, ReactNode]>)
      : []),
    [t("requestsPage.asked"), when(r.createdAt)],
    [
      t("requestPage.approvals"),
      r.approvals.length
        ? r.approvals.map((a) => `${a.by.name}, ${when(a.at)}${a.comment ? `: ${a.comment}` : ""}`).join("; ")
        : t("requestPage.noApprovals", { count: r.approvalsNeeded }),
    ],
    ...(r.startsAt && r.endsAt ? ([[t("requestPage.window"), `${when(r.startsAt)} → ${when(r.endsAt)}`]] as Array<[string, ReactNode]>) : []),
    ...(r.closed
      ? ([[t("requestPage.closed"), `${r.closed.by}, ${when(r.closed.at)}${r.closed.comment ? `: ${r.closed.comment}` : ""}`]] as Array<[string, ReactNode]>)
      : []),
  ];
  return (
    <>
      <PageHeader
        title={r.principal}
        breadcrumbs={[{ label: t("requestsPage.requests"), href: "/" }, { label: r.principal }]}
        description={r.status === "active" ? t("requestPage.openFor", { left: left(r.endsAt) }) : t(`statusDetail.${r.status}`)}
        meta={<StatusOf status={r.status} />}
        actions={
          r.status === "active" &&
          (mine || can("editor")) && (
            <Button variant={mine ? "secondary" : "danger"} icon={<Square />} onClick={end}>
              {mine ? t("requestPage.endMine") : t("requestPage.revoke")}
            </Button>
          )
        }
      />
      <ErrorText message={error} />
      <Panel title={t("requestPage.request")}>
        <dl className="access-facts text-sm">
          {facts.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-fg-muted">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      </Panel>
      {r.status === "pending" && <PendingPanel r={r} call={call} onDone={after} />}
      {r.status === "active" && mine && (
        <Panel title={t("requestPage.getCertificate")} description={t("requestPage.getCertificateDetail")}>
          {strong ? <CertificateForm call={call} id={r.id} onDone={load} /> : <p className="m-0 text-sm text-warning">{t("requestsPage.needFactorDetail")}</p>}
        </Panel>
      )}
      <Panel title={t("requestPage.certificates")} flush>
        <DataTable
          label={t("requestPage.certificates")}
          columns={[
            { id: "serial", header: t("requestPage.serial"), width: "80px", mono: true, cell: (c) => c.serial },
            { id: "key", header: t("requestPage.key"), cell: (c) => <span className="access-wrap font-mono text-xs">{`${c.keyType} ${c.fingerprint}`}</span> },
            { id: "until", header: t("requestPage.validUntil"), width: "160px", cell: (c) => <span className="whitespace-nowrap">{when(c.validBefore)}</span> },
            {
              id: "state",
              header: t("requestsPage.status"),
              width: "120px",
              cell: (c) =>
                c.revoked ? (
                  <StatusBadge tone="danger">{t("requestPage.certRevoked")}</StatusBadge>
                ) : Date.parse(c.validBefore) > Date.now() ? (
                  <StatusBadge tone="success">{t("requestPage.certValid")}</StatusBadge>
                ) : (
                  <StatusBadge tone="neutral">{t("requestPage.certExpired")}</StatusBadge>
                ),
            },
          ]}
          rows={r.certificates}
          getRowId={(c) => String(c.serial)}
          minWidth={620}
          empty={<EmptyState title={t("requestPage.noCertificates")} />}
        />
      </Panel>
      <Panel title={t("requestPage.record")} flush>
        <AuditTable events={r.events} />
      </Panel>
    </>
  );
}

function PendingPanel({ r, call, onDone }: { r: AccessRequest; call: Call; onDone: () => void }) {
  const t = useT();
  return (
    <Panel title={t("requestsPage.waitingTitle")} flush>
      <ul aria-label={t("requestsPage.waitingTitle")} className="flex flex-col">
        <PendingItem r={r} call={call} onDone={onDone} />
      </ul>
    </Panel>
  );
}

// ---------------------------------------------------------------- Open access and history

function OpenPage({ call, summary, reload }: { call: Call; summary: Summary; reload: () => void }) {
  const t = useT();
  const left = useLeft();
  const { can, isMine } = useMe();
  const [run, error] = useAction(reload);
  const columns: Column<AccessRequest>[] = [
    { id: "who", header: t("requestsPage.who"), width: "26%", sortValue: (r) => r.requester.name, cell: (r) => <Person person={r.requester} /> },
    {
      id: "what",
      header: t("requestsPage.what"),
      sortValue: (r) => r.principal,
      cell: (r) => <span className="font-mono text-xs font-medium">{r.principal}</span>,
    },
    {
      id: "by",
      header: t("openPage.approvedBy"),
      cell: (r) => <span className="text-xs">{r.approvals.map((a) => a.by.name).join(", ")}</span>,
    },
    {
      id: "left",
      header: t("openPage.left"),
      width: "110px",
      align: "right",
      sortValue: (r) => r.endsAt ?? "",
      cell: (r) => <span className="whitespace-nowrap">{left(r.endsAt)}</span>,
    },
    {
      id: "act",
      header: <span className="sr-only">{t("openPage.actions")}</span>,
      width: "100px",
      align: "right",
      cell: (r) =>
        (isMine(r) || can("editor")) && (
          <Button
            size="xs"
            icon={<Square />}
            aria-label={t("openPage.endFor", { who: r.requester.name, principal: r.principal })}
            onClick={(e) => (e.stopPropagation(), void run(() => call(`/api/v1/requests/${r.id}/end`, { method: "POST", body: "{}" })))}
          >
            {isMine(r) ? t("openPage.end") : t("requestPage.revoke")}
          </Button>
        ),
    },
  ];
  return (
    <>
      <PageHeader title={t("openPage.open")} description={t("openPage.description")} />
      <ErrorText message={error} />
      <Panel title={t("openPage.open")} flush>
        <DataTable
          label={t("openPage.open")}
          columns={columns}
          rows={summary.active}
          getRowId={(r) => r.id}
          onRowClick={(r) => navigate(`/requests/${r.id}`)}
          defaultSort={{ id: "left", direction: "asc" }}
          minWidth={760}
          empty={<EmptyState title={t("openPage.none")}>{t("openPage.noneDetail")}</EmptyState>}
        />
      </Panel>
      <Callout tone="info" title={t("openPage.sessions")}>
        {t("openPage.sessionsDetail")}
      </Callout>
    </>
  );
}

const STATUSES: RequestStatus[] = ["pending", "active", "ended", "denied", "cancelled", "revoked"];

function HistoryPage({ call }: { call: Call }) {
  const t = useT();
  const [status, setStatus] = useState<RequestStatus | "all">("all");
  const [rows, setRows] = useState<AccessRequest[]>();
  const columns = useRequestColumns();
  useEffect(() => {
    setRows(undefined);
    void call<{ requests: AccessRequest[] }>(`/api/v1/requests${status === "all" ? "" : `?status=${status}`}`).then(
      (r) => setRows(r.requests),
      () => setRows([]),
    );
  }, [call, status]);
  return (
    <>
      <PageHeader title={t("historyPage.history")} description={t("historyPage.description")} />
      <Tabs
        label={t("requestsPage.status")}
        value={status}
        onChange={setStatus}
        items={[{ value: "all" as const, label: t("historyPage.all") }, ...STATUSES.map((s) => ({ value: s, label: t(`statuses.${s}`) }))]}
      />
      <Panel title={t("historyPage.history")} flush>
        <DataTable
          label={t("historyPage.history")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(r) => r.id}
          onRowClick={(r) => navigate(`/requests/${r.id}`)}
          defaultSort={{ id: "at", direction: "desc" }}
          minWidth={760}
          empty={<EmptyState title={t("historyPage.none")} />}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Servers

function ServerForm({ call, server, onDone }: { call: Call; server?: Server; onDone: () => void }) {
  const t = useT();
  const [name, setName] = useState(server?.name ?? "");
  const [address, setAddress] = useState(server?.address ?? "");
  const [port, setPort] = useState(String(server?.port ?? 22));
  const [logins, setLogins] = useState(server?.logins.join(", ") ?? "");
  const [maxMinutes, setMaxMinutes] = useState(String(server?.maxMinutes ?? 60));
  const [approvals, setApprovals] = useState(String(server?.approvals ?? 1));
  const [description, setDescription] = useState(server?.description ?? "");
  const [run, error] = useAction(onDone);
  const duration = useDuration();
  const save = (e: FormEvent) => {
    e.preventDefault();
    void run(() =>
      call(server ? `/api/v1/servers/${server.id}` : "/api/v1/servers", {
        method: server ? "PUT" : "POST",
        body: JSON.stringify({
          name,
          address,
          port: Number(port),
          description,
          logins: logins
            .split(",")
            .map((l) => l.trim())
            .filter(Boolean),
          maxMinutes: Number(maxMinutes),
          approvals: Number(approvals),
        }),
      }),
    );
  };
  return (
    <form className="flex flex-col gap-2.5" onSubmit={save} aria-label={server ? t("serversPage.edit", { name: server.name }) : t("serversPage.add")}>
      <div className="access-cols-3">
        <TextField
          label={t("serversPage.name")}
          mono
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="api-prod-03"
          hint={t("serversPage.nameHint")}
        />
        <TextField label={t("serversPage.address")} mono value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.5" />
        <TextField label={t("serversPage.port")} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
      </div>
      <TextField
        label={t("serversPage.logins")}
        mono
        value={logins}
        onChange={(e) => setLogins(e.target.value)}
        placeholder="deploy, www-data"
        hint={t("serversPage.loginsHint")}
      />
      <div className="access-cols-3">
        <SelectField
          label={t("serversPage.maxGrant")}
          value={maxMinutes}
          onChange={(e) => setMaxMinutes(e.target.value)}
          options={[...new Set([30, 60, 120, 240, 480, 720, 1440, Number(server?.maxMinutes ?? 60)])]
            .sort((a, b) => a - b)
            .map((m) => ({ value: String(m), label: duration(m) }))}
        />
        <SelectField
          label={t("serversPage.approvals")}
          value={approvals}
          onChange={(e) => setApprovals(e.target.value)}
          options={[
            { value: "1", label: t("serversPage.oneApprover") },
            { value: "2", label: t("serversPage.twoApprovers") },
          ]}
        />
        <TextField
          label={t("serversPage.descriptionField")}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder={t("serversPage.descriptionPlaceholder")}
        />
      </div>
      <ErrorText message={error} />
      <div>
        <Button type="submit" variant="primary" disabled={!name.trim() || !address.trim() || !logins.trim()}>
          {t("serversPage.save")}
        </Button>
      </div>
    </form>
  );
}

function ServersPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const duration = useDuration();
  const { can } = useMe();
  const admin = can("admin");
  const [servers, load] = useList<Server>(call, "/api/v1/servers", "servers");
  const [editing, setEditing] = useState<string | null>(param("id"));
  const done = useCallback(() => {
    setEditing(null);
    load();
    reload();
  }, [load, reload]);
  const [run, error] = useAction(done);
  const current = servers?.find((s) => s.id === editing);
  const columns: Column<Server>[] = [
    {
      id: "name",
      header: t("serversPage.name"),
      width: "22%",
      sortValue: (s) => s.name,
      cell: (s) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-mono font-medium">{s.name}</span>
          <span className="truncate text-2xs text-fg-muted">{s.description || `${s.address}${s.port === 22 ? "" : `:${s.port}`}`}</span>
        </span>
      ),
    },
    { id: "logins", header: t("serversPage.logins"), cell: (s) => <span className="font-mono text-xs">{s.logins.join(", ")}</span> },
    { id: "max", header: t("serversPage.maxGrant"), width: "110px", sortValue: (s) => s.maxMinutes, cell: (s) => duration(s.maxMinutes) },
    {
      id: "approvals",
      header: t("serversPage.approvals"),
      width: "130px",
      cell: (s) => (s.approvals > 1 ? t("serversPage.twoApprovers") : t("serversPage.oneApprover")),
    },
    { id: "open", header: t("serversPage.openNow"), width: "90px", align: "right", mono: true, sortValue: (s) => s.active, cell: (s) => s.active },
    {
      id: "act",
      header: <span className="sr-only">{t("openPage.actions")}</span>,
      width: "200px",
      align: "right",
      cell: (s) => (
        <span className="flex justify-end gap-1">
          <Button size="xs" icon={<Wrench />} onClick={(e) => (e.stopPropagation(), navigate(`/setup?server=${s.id}`))}>
            {t("serversPage.setup")}
          </Button>
          {admin && (
            <Button
              size="xs"
              icon={<Trash2 />}
              aria-label={t("serversPage.remove", { name: s.name })}
              onClick={(e) => (e.stopPropagation(), void run(() => call(`/api/v1/servers/${s.id}`, { method: "DELETE" })))}
            />
          )}
        </span>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        title={t("serversPage.servers")}
        description={t("serversPage.description")}
        actions={
          admin && (
            <Button variant="primary" icon={<Plus />} onClick={() => setEditing("new")}>
              {t("serversPage.add")}
            </Button>
          )
        }
      />
      <ErrorText message={error} />
      {admin && editing === "new" && (
        <Panel title={t("serversPage.add")}>
          <ServerForm call={call} onDone={done} />
        </Panel>
      )}
      {admin && current && (
        <Panel title={t("serversPage.edit", { name: current.name })}>
          <ServerForm key={current.id} call={call} server={current} onDone={done} />
        </Panel>
      )}
      <Panel title={t("serversPage.servers")} flush>
        <DataTable
          label={t("serversPage.servers")}
          columns={columns}
          rows={servers ?? []}
          loading={!servers}
          getRowId={(s) => s.id}
          onRowClick={admin ? (s) => setEditing(s.id) : undefined}
          activeRowId={current?.id}
          minWidth={820}
          empty={<EmptyState title={t("serversPage.none")}>{t("serversPage.noneDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Audit

function AuditTable({ events }: { events: AuditEvent[] }) {
  const t = useT();
  const columns: Column<AuditEvent>[] = [
    { id: "at", header: t("auditPage.when"), width: "160px", cell: (e) => <span className="whitespace-nowrap">{when(e.at)}</span> },
    { id: "actor", header: t("auditPage.actor"), width: "22%", cell: (e) => <span className="access-wrap text-xs">{e.actor}</span> },
    { id: "action", header: t("auditPage.action"), width: "150px", mono: true, cell: (e) => e.action },
    {
      id: "target",
      header: t("auditPage.target"),
      cell: (e) => (
        <span className="flex min-w-0 flex-col">
          {e.requestId ? (
            <a href={`/requests/${e.requestId}`} className="font-mono text-xs">
              {e.target}
            </a>
          ) : (
            <span className="font-mono text-xs">{e.target}</span>
          )}
          {e.detail && (
            <span className="access-clamp text-2xs text-fg-muted" title={e.detail}>
              {e.detail}
            </span>
          )}
        </span>
      ),
    },
    {
      id: "result",
      header: t("auditPage.result"),
      width: "100px",
      cell: (e) => <StatusBadge tone={e.result === "success" ? "success" : "warning"}>{t(`auditPage.results.${e.result}`)}</StatusBadge>,
    },
  ];
  return (
    <DataTable
      label={t("auditPage.events")}
      columns={columns}
      rows={events}
      getRowId={(e) => String(e.id)}
      minWidth={860}
      empty={<EmptyState title={t("auditPage.none")} />}
    />
  );
}

const KINDS = ["all", "request", "grant", "certificate", "server", "auth"] as const;
type Kind = (typeof KINDS)[number];

function AuditPage({ call }: { call: Call }) {
  const t = useT();
  const [kind, setKind] = useState<Kind>(() => ((KINDS as readonly string[]).includes(param("kind") ?? "") ? (param("kind") as Kind) : "all"));
  const [events, setEvents] = useState<AuditEvent[]>();
  const [next, setNext] = useState<string | null>(null);
  const load = useCallback(
    (cursor?: string) =>
      void call<{ events: AuditEvent[]; next: string | null }>(
        `/api/v1/audit?${new URLSearchParams({ ...(kind !== "all" && { kind }), ...(cursor && { cursor }) }).toString()}`,
      ).then(
        (r) => (setEvents((e) => (cursor ? [...(e ?? []), ...r.events] : r.events)), setNext(r.next)),
        () => setEvents([]),
      ),
    [call, kind],
  );
  useEffect(() => {
    setEvents(undefined);
    load();
  }, [load]);
  return (
    <>
      <PageHeader
        title={t("auditPage.audit")}
        description={t("auditPage.description")}
        actions={
          // The answer is an attachment: the browser saves it and stays on this page.
          <Button icon={<Download />} onClick={() => window.location.assign("/api/v1/audit/export")}>
            {t("auditPage.export")}
          </Button>
        }
      />
      <Tabs label={t("auditPage.kind")} value={kind} onChange={setKind} items={KINDS.map((k) => ({ value: k, label: t(`auditPage.kinds.${k}`) }))} />
      <Panel
        title={t("auditPage.events")}
        flush
        footer={
          next && (
            <Button size="sm" onClick={() => load(next)}>
              {t("auditPage.more")}
            </Button>
          )
        }
      >
        {events ? <AuditTable events={events} /> : <EmptyState title={t("product.loading")} />}
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage({ call }: { call: Call }) {
  const t = useT();
  const [servers] = useList<Server>(call, "/api/v1/servers", "servers");
  const [ca, setCa] = useState<{ publicKey: string; fingerprint: string }>();
  const [serverId, setServerId] = useState(param("server") ?? "");
  const [script, setScript] = useState<string>();
  const chosen = servers?.find((s) => s.id === serverId) ?? servers?.[0];
  useEffect(() => void call<{ publicKey: string; fingerprint: string }>("/api/v1/ca").then(setCa, () => {}), [call]);
  useEffect(() => {
    if (!chosen) return;
    void call<string>(`/api/v1/servers/${chosen.id}/setup`).then(setScript, () => setScript(undefined));
  }, [call, chosen]);
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.description")} />
      <Panel title={t("setupPage.ca")} description={ca ? t("setupPage.caDetail", { fingerprint: ca.fingerprint }) : undefined}>
        {ca && <Code label={t("setupPage.ca")}>{ca.publicKey}</Code>}
      </Panel>
      <Panel
        title={t("setupPage.server")}
        description={t("setupPage.serverDetail")}
        actions={
          servers &&
          servers.length > 0 && (
            <SelectField
              label={t("requestsPage.server")}
              value={chosen?.id ?? ""}
              onChange={(e) => setServerId(e.target.value)}
              options={servers.map((s) => ({ value: s.id, label: s.name }))}
            />
          )
        }
      >
        {servers && !servers.length ? (
          <EmptyState title={t("serversPage.none")}>{t("serversPage.noneDetail")}</EmptyState>
        ) : (
          script && <Code label={t("setupPage.server")}>{script}</Code>
        )}
      </Panel>
      <Panel title={t("setupPage.people")} description={t("setupPage.peopleDetail")}>
        <ol className="access-steps text-sm">
          <li>{t("setupPage.people1")}</li>
          <li>{t("setupPage.people2")}</li>
          <li>{t("setupPage.people3")}</li>
        </ol>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "access" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "overview", label: msg("product.requests"), icon: Inbox, count: summary?.requests.pending || undefined },
    { id: "open", label: msg("product.open"), icon: TerminalSquare, count: summary?.grants.active || undefined },
    { id: "history", label: msg("product.history"), icon: History },
    { id: "servers", label: msg("product.servers"), icon: ServerIcon, count: summary?.servers || undefined },
    { id: "audit", label: msg("product.audit"), icon: ScrollText },
    { id: "setup", label: msg("product.setup"), icon: ShieldCheck },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens";

  return (
    <AppShell
      product="access"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={route.page === "request" ? "overview" : route.page}
      onNavigate={(id) => navigate(id === "overview" ? "/" : `/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={route.page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary ? (
        <EmptyState title={msg("product.loading")} icon={<Inbox />}>
          {msg("product.reading")}
        </EmptyState>
      ) : route.page === "overview" && !summary.servers ? (
        <WelcomePage />
      ) : route.page === "overview" ? (
        <RequestsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "request" ? (
        <RequestPage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "open" ? (
        <OpenPage call={call} summary={summary} reload={reload} />
      ) : route.page === "history" ? (
        <HistoryPage call={call} />
      ) : route.page === "servers" ? (
        <ServersPage key={window.location.search} call={call} reload={reload} />
      ) : route.page === "audit" ? (
        <AuditPage key={window.location.search} call={call} />
      ) : (
        <SetupPage key={window.location.search} call={call} />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Access">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
