import { ManagedStream } from './sse.ts';
import type {
  CacheClearResponse,
  CacheClearTarget,
  ConnectionItem,
  ConnectionsResponse,
  DiagnosticsResponse,
  DnsQueryResponse,
  EventsResponse,
  FakeIpFlushResponse,
  HealthResponse,
  LatencyTier,
  LogEntry,
  LogsResponse,
  ModeResponse,
  NetworkChangeResponse,
  OutboundGroup,
  OutboundProbeRequest,
  OutboundProbeResult,
  ReloadResponse,
  RouteMode,
  RulesResponse,
  SsmapiStatsResponse,
  SsmapiUserItem,
  StatusResponse,
  StreamState,
} from './types.ts';

export type * from './types.ts';

const TOKEN_STORAGE_KEY = 'nexus_control_bearer_token';
const authBus = new EventTarget();

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(message: string, status: number, code = 'http-error') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export function getBearerToken(): string {
  if (typeof window === 'undefined') return '';
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setBearerToken(token: string): void {
  if (typeof window !== 'undefined') {
    try {
      const trimmed = token.trim();
      if (trimmed) window.sessionStorage.setItem(TOKEN_STORAGE_KEY, trimmed);
      else window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      // Ignore storage restriction in private frames
    }
  }
  authBus.dispatchEvent(new CustomEvent('token-changed'));
}

export function notifyUnauthorized(): void {
  authBus.dispatchEvent(new CustomEvent('unauthorized'));
}

export function onAuthEvent(type: 'token-changed' | 'unauthorized', cb: () => void): () => void {
  authBus.addEventListener(type, cb);
  return () => authBus.removeEventListener(type, cb);
}

export function formatBytes(raw: number | string): string {
  const n = typeof raw === 'string' ? Number(raw) : raw;
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  if (n < 1024) return `${Math.round(n)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '0ms';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const remSec = sec % 60;
  if (min < 60) return `${min}m ${remSec}s`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

export function formatTimestampNs(ns: number): string {
  if (!Number.isFinite(ns) || ns <= 0) return '--:--:--';
  const ms = ns > 1e14 ? Math.floor(ns / 1e6) : ns > 1e11 ? ns : ns * 1000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  const pad = (v: number) => String(v).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function getLatencyTier(ms: number | null | undefined, state?: string): LatencyTier {
  const st = (state ?? '').toLowerCase();
  if (ms === undefined || ms === null || ms <= 0) {
    if (st === 'down' || st === 'timeout' || st === 'unreachable' || st === 'error' || st === 'failed') {
      return 'down';
    }
    return 'unprobed';
  }
  if (ms < 80) return 'fast';
  if (ms < 180) return 'good';
  if (ms < 350) return 'mid';
  return 'slow';
}

export function latencyBars(ms: number | null | undefined): number {
  if (ms === undefined || ms === null || ms <= 0) return 0;
  if (ms < 80) return 4;
  if (ms < 180) return 3;
  if (ms < 350) return 2;
  return 1;
}

function encodeQuery(pairs: Array<[string, string]>): string {
  return pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
}

export function buildDnsQueryUrl(params: { name: string; type?: string; server?: string }): string {
  const pairs: Array<[string, string]> = [['name', params.name.trim()]];
  if (params.type) pairs.push(['type', params.type.trim().toUpperCase()]);
  if (params.server?.trim()) pairs.push(['server', params.server.trim()]);
  return `/v1/dns/query?${encodeQuery(pairs)}`;
}

export function buildLogsQuery(
  params: { level?: string; domain?: string; search?: string; since?: number; limit?: number },
  stream = false,
): string {
  const pairs: Array<[string, string]> = [];
  if (stream) pairs.push(['stream', '1']);
  if (params.level && params.level !== 'all') pairs.push(['level', params.level]);
  if (params.domain && params.domain !== 'all') pairs.push(['domain', params.domain]);
  if (params.search?.trim()) pairs.push(['search', params.search.trim()]);
  if (params.since !== undefined && params.since > 0) pairs.push(['since', String(params.since)]);
  if (!stream) pairs.push(['limit', String(params.limit ?? 250)]);
  return `/v1/logs?${encodeQuery(pairs)}`;
}

async function requestRaw(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers ?? {});
  const token = getBearerToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const resp = await fetch(path, { ...init, headers, cache: 'no-store' });
  if (resp.status === 401) notifyUnauthorized();
  return resp;
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const resp = await requestRaw(path, init);
  const text = await resp.text();
  if (!resp.ok) {
    let detail = text.trim() || `HTTP ${resp.status}`;
    let code = `http-${resp.status}`;
    try {
      const err = JSON.parse(text) as { error?: { code?: string; message?: string } | string };
      if (typeof err?.error === 'string') {
        detail = err.error;
      } else if (err?.error?.message) {
        code = err.error.code ?? code;
        detail = err.error.code ? `${err.error.code}: ${err.error.message}` : err.error.message;
      }
    } catch {
      // keep raw text
    }
    throw new ApiError(detail, resp.status, code);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

export const nexusApi = {
  health: () => requestJson<HealthResponse>('/v1/health'),
  status: () => requestJson<StatusResponse>('/v1/status'),
  mode: () => requestJson<ModeResponse>('/v1/mode'),
  setMode: (mode: RouteMode, outbound?: string) =>
    requestJson<ModeResponse>('/v1/mode', {
      method: 'PUT',
      body: JSON.stringify(outbound ? { mode, outbound } : { mode }),
    }),
  outbounds: () => requestJson<{ groups: OutboundGroup[] }>('/v1/outbounds'),
  selectGroup: (tag: string, member: string) =>
    requestJson<{ group: string; selected: string; result: string }>(
      `/v1/groups/${encodeURIComponent(tag)}`,
      { method: 'PUT', body: JSON.stringify({ member }) },
    ),
  probeGroup: (tag: string) =>
    requestJson<{ group: string; probe: string }>(`/v1/groups/${encodeURIComponent(tag)}/probe`, {
      method: 'POST',
      body: '{}',
    }),
  probeOutbound: (tag: string, opts: OutboundProbeRequest = {}) =>
    requestJson<OutboundProbeResult>(`/v1/outbounds/${encodeURIComponent(tag)}/probe`, {
      method: 'POST',
      body: JSON.stringify(opts),
    }),
  rules: () => requestJson<RulesResponse>('/v1/rules'),
  dnsQuery: (params: { name: string; type?: string; server?: string }) =>
    requestJson<DnsQueryResponse>(buildDnsQueryUrl(params)),
  flushFakeIp: () =>
    requestJson<FakeIpFlushResponse>('/v1/cache/fakeip/flush', { method: 'POST', body: '{}' }),
  clearCache: (target: CacheClearTarget = 'all') =>
    requestJson<CacheClearResponse>('/v1/state/clear-cache', {
      method: 'POST',
      body: JSON.stringify({ target }),
    }),
  connections: () => requestJson<ConnectionsResponse>('/v1/connections'),
  connectionDetail: (id: string) =>
    requestJson<ConnectionItem>(`/v1/connections/${encodeURIComponent(id)}`),
  closeConnection: (id: string) =>
    requestJson<{ id: string; closed: boolean }>(`/v1/connections/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  closeAllConnections: () =>
    requestJson<{ closed: number }>('/v1/connections', { method: 'DELETE' }),
  logs: (params: { level?: string; domain?: string; search?: string; since?: number; limit?: number }) =>
    requestJson<LogsResponse>(buildLogsQuery(params, false)),
  setLogLevel: (level: string, domain = 'global') =>
    requestJson<{ domain: string; level: string }>('/v1/log-level', {
      method: 'POST',
      body: JSON.stringify({ domain, level }),
    }),
  diagnostics: () => requestJson<DiagnosticsResponse>('/v1/diagnostics'),
  events: (cursor = 0) => requestJson<EventsResponse>(`/v1/events?cursor=${Math.max(0, cursor)}`),
  reload: () => requestJson<ReloadResponse>('/v1/reload', { method: 'POST', body: '{}' }),
  networkChange: () =>
    requestJson<NetworkChangeResponse>('/v1/network-change', { method: 'POST', body: '{}' }),
  metricsText: async (): Promise<string> => {
    const resp = await requestRaw('/metrics');
    const text = await resp.text();
    if (!resp.ok) throw new ApiError(text.trim() || `HTTP ${resp.status}`, resp.status);
    return text;
  },
  ssmapiUsers: () => requestJson<{ users: SsmapiUserItem[] }>('/ssmapi/users'),
  ssmapiStats: () => requestJson<SsmapiStatsResponse>('/ssmapi/stats'),
};

export function createStatusStream(
  onData: (status: StatusResponse) => void,
  onState: (state: StreamState) => void,
  onError?: (err: string) => void,
  intervalMs = 1500,
): ManagedStream<StatusResponse> {
  return new ManagedStream<StatusResponse>({
    buildUrl: () => `/v1/status?stream=1&interval_ms=${intervalMs}`,
    getToken: getBearerToken,
    parseFrame: (frame) => {
      if (frame.event !== 'status' && frame.event !== 'message') return null;
      try {
        return JSON.parse(frame.data) as StatusResponse;
      } catch {
        return null;
      }
    },
    onData,
    onState,
    onError,
    onUnauthorized: notifyUnauthorized,
    pollFallback: async () => onData(await nexusApi.status()),
    pollIntervalMs: Math.max(2000, intervalMs),
  });
}

export function createConnectionsStream(
  onData: (items: ConnectionItem[]) => void,
  onState: (state: StreamState) => void,
  onError?: (err: string) => void,
  intervalMs = 2000,
): ManagedStream<ConnectionItem[]> {
  return new ManagedStream<ConnectionItem[]>({
    buildUrl: () => `/v1/connections?stream=1&interval_ms=${intervalMs}`,
    getToken: getBearerToken,
    parseFrame: (frame) => {
      if (frame.event !== 'connections' && frame.event !== 'message') return null;
      try {
        const parsed = JSON.parse(frame.data) as ConnectionsResponse;
        return parsed.connections ?? [];
      } catch {
        return null;
      }
    },
    onData,
    onState,
    onError,
    onUnauthorized: notifyUnauthorized,
    pollFallback: async () => {
      const resp = await nexusApi.connections();
      onData(resp.connections ?? []);
    },
    pollIntervalMs: Math.max(2500, intervalMs),
  });
}

export function createLogsStream(
  getFilters: () => { level?: string; domain?: string; search?: string; since?: number },
  onEntry: (entry: LogEntry) => void,
  onPollBatch: (resp: LogsResponse) => void,
  onState: (state: StreamState) => void,
  onError?: (err: string) => void,
): ManagedStream<LogEntry> {
  return new ManagedStream<LogEntry>({
    buildUrl: () => buildLogsQuery(getFilters(), true),
    getToken: getBearerToken,
    parseFrame: (frame) => {
      if (frame.event !== 'log' && frame.event !== 'message') return null;
      try {
        return JSON.parse(frame.data) as LogEntry;
      } catch {
        return null;
      }
    },
    onData: onEntry,
    onState,
    onError,
    onUnauthorized: notifyUnauthorized,
    pollFallback: async () => {
      const f = getFilters();
      onPollBatch(await nexusApi.logs({ ...f, limit: 250 }));
    },
    pollIntervalMs: 2000,
  });
}
