// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  pending: number;
  active: number;
  servers: number;
  certificatesLastDay: number;
  refusedLastDay: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="access",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_access_requests_pending Requests waiting for approval.",
    "# TYPE openasy_access_requests_pending gauge",
    `openasy_access_requests_pending ${g.pending}`,
    "# HELP openasy_access_grants_active Grants open now: someone may log in with them.",
    "# TYPE openasy_access_grants_active gauge",
    `openasy_access_grants_active ${g.active}`,
    "# HELP openasy_access_servers Servers people may ask for.",
    "# TYPE openasy_access_servers gauge",
    `openasy_access_servers ${g.servers}`,
    "# HELP openasy_access_certificates_issued Certificates issued in the last 24 hours.",
    "# TYPE openasy_access_certificates_issued gauge",
    `openasy_access_certificates_issued ${g.certificatesLastDay}`,
    "# HELP openasy_access_refused Refused attempts in the last 24 hours, such as approving one's own request.",
    "# TYPE openasy_access_refused gauge",
    `openasy_access_refused ${g.refusedLastDay}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
