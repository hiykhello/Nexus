export interface StatusResponse {
  instance: string;
  state: string;
  workers: number;
  listeners: number;
  control_generation: string;
  active_sessions: number;
  upload_bytes_total: string;
  download_bytes_total: string;
}

export interface OutboundMember {
  name: string;
  state: string;
  latency_ms?: number;
  ewma_ms?: number;
  last_status?: number;
  breaker_open?: boolean;
}

export interface OutboundGroup {
  name: string;
  mode: string;
  selected: string;
  override: boolean;
  members: OutboundMember[];
}

export interface ConnectionItem {
  id: string;
  listener: number;
  protocol: string;
  path: string;
  destination_port: number;
  upload_bytes: string;
  download_bytes: string;
  duration_ms: number;
  can_close: boolean;
  inbound?: string;
  source?: string;
  target?: string;
  outbound?: string;
  route_mode?: string;
  route_rule?: string;
  process_path?: string;
  source_uid?: number;
}

export interface LogEntry {
  seq: number;
  timestamp_ns: number;
  level: string;
  domain: string;
  event: number;
  session: number;
  message: string;
}

export interface LogsResponse {
  latest_seq: number;
  evicted: number;
  entries: LogEntry[];
}

export interface DiagnosticsResponse {
  instance: string;
  control_generation: string;
  authorized_requests: number;
  unauthorized_requests: number;
  expired_requests: number;
  reply_failed: number;
  listeners: number;
  active_connections: number;
}

export interface AcmeCertItem {
  domain: string;
  issuer: string;
  not_after_epoch: number;
  days_remaining: number;
  challenge: string;
}

export interface AcmeStatusResponse {
  certificates: AcmeCertItem[];
}

export interface SsmapiUserItem {
  username: string;
  enabled: boolean;
  uplinkBytes: number;
  downlinkBytes: number;
  byteQuota: number;
  tcpSessions: number;
  udpSessions: number;
}

export interface SsmapiStatsResponse {
  userCount: number;
  totalUplinkBytes: number;
  totalDownlinkBytes: number;
}

const TOKEN_STORAGE_KEY = 'nexus_control_bearer_token';

export function getBearerToken(): string {
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setBearerToken(token: string): void {
  try {
    const trimmed = token.trim();
    if (trimmed) window.sessionStorage.setItem(TOKEN_STORAGE_KEY, trimmed);
    else window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Ignore storage restriction in private frames
  }
}

export function formatBytes(raw: number | string): string {
  const n = typeof raw === 'string' ? Number(raw) : raw;
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n < 1024) return `${Math.round(n)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  const token = getBearerToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const resp = await fetch(path, { ...init, headers, cache: 'no-store' });
  const text = await resp.text();
  if (!resp.ok) {
    let detail = text || `HTTP ${resp.status}`;
    try {
      const err = JSON.parse(text) as { error?: { code?: string; message?: string } };
      if (err?.error?.message) detail = `${err.error.code ?? resp.status}: ${err.error.message}`;
    } catch {
      // keep raw text
    }
    throw new Error(detail);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

export const nexusApi = {
  health: () => requestJson<{ status: string; instance: string }>('/v1/health'),
  status: () => requestJson<StatusResponse>('/v1/status'),
  outbounds: () => requestJson<{ groups: OutboundGroup[] }>('/v1/outbounds'),
  selectGroup: (tag: string, member: string) =>
    requestJson(`/v1/groups/${encodeURIComponent(tag)}`, {
      method: 'PUT',
      body: JSON.stringify({ member }),
    }),
  probeGroup: (tag: string) =>
    requestJson(`/v1/groups/${encodeURIComponent(tag)}/probe`, {
      method: 'POST',
      body: '{}',
    }),
  connections: () => requestJson<{ connections: ConnectionItem[] }>('/v1/connections'),
  connectionDetail: (id: string) => requestJson<ConnectionItem>(`/v1/connections/${encodeURIComponent(id)}`),
  closeConnection: (id: string) =>
    requestJson(`/v1/connections/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  closeAllConnections: () => requestJson('/v1/connections', { method: 'DELETE' }),
  logs: (params: { level?: string; domain?: string; search?: string; since?: number; limit?: number }) => {
    const q = new URLSearchParams();
    if (params.level && params.level !== 'all') q.set('level', params.level);
    if (params.domain && params.domain !== 'all') q.set('domain', params.domain);
    if (params.search) q.set('search', params.search);
    if (params.since && params.since > 0) q.set('since', String(params.since));
    q.set('limit', String(params.limit ?? 200));
    return requestJson<LogsResponse>(`/v1/logs?${q.toString()}`);
  },
  setLogLevel: (level: string, domain = 'global') =>
    requestJson('/v1/log-level', {
      method: 'POST',
      body: JSON.stringify({ domain, level }),
    }),
  diagnostics: () => requestJson<DiagnosticsResponse>('/v1/diagnostics'),
  reload: () => requestJson('/v1/reload', { method: 'POST', body: '{}' }),
  clearCache: (target: 'all' | 'dns' | 'rulesets' = 'all') =>
    requestJson('/v1/state/clear-cache', {
      method: 'POST',
      body: JSON.stringify({ target }),
    }),
  acmeStatus: () => requestJson<AcmeStatusResponse>('/v1/acme/status'),
  ssmapiUsers: () => requestJson<{ users: SsmapiUserItem[] }>('/v1/ssmapi/users'),
  ssmapiStats: () => requestJson<SsmapiStatsResponse>('/v1/ssmapi/stats'),
};
