export type RouteMode = 'rule' | 'global' | 'direct';

export type CacheClearTarget = 'all' | 'dns' | 'rulesets' | 'fakeip';

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

export type LogDomain =
  | 'all'
  | 'global'
  | 'core'
  | 'net'
  | 'tls'
  | 'quic'
  | 'dns'
  | 'route'
  | 'tun'
  | 'proxy'
  | 'control'
  | 'state';

export type DnsRecordType =
  | 'A'
  | 'AAAA'
  | 'HTTPS'
  | 'SVCB'
  | 'CNAME'
  | 'TXT'
  | 'MX'
  | 'SRV'
  | 'NS'
  | 'PTR'
  | 'SOA'
  | 'CAA';

export type StreamState = 'connecting' | 'live' | 'polling' | 'unauthorized' | 'offline';

export type ThemePreference = 'system' | 'dark' | 'light';

export type LatencyTier = 'fast' | 'good' | 'mid' | 'slow' | 'down' | 'unprobed';

export interface HealthResponse {
  status: string;
  instance: string;
}

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

export interface ModeResponse {
  mode: RouteMode | string;
  outbound: string;
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

export interface OutboundProbeRequest {
  url?: string;
  timeout_ms?: number;
  mode?: 'http' | 'h2-ping';
}

export interface OutboundProbeResult {
  id?: number;
  outbound: string;
  resolved_outbound: string;
  state: 'up' | 'down' | 'pending' | string;
  latency_ms?: number | null;
  status_code?: number;
  url: string;
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

export interface ConnectionsResponse {
  connections: ConnectionItem[];
}

export interface RuleItem {
  index: number;
  type: string;
  action: string;
  target: string;
  summary: string;
}

export interface RulesResponse {
  rules: RuleItem[];
}

export interface DnsAnswer {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

export interface DnsQueryResponse {
  name: string;
  type: string;
  rcode: number;
  rcode_name: string;
  ttl: number;
  elapsed_ms: number;
  answers: DnsAnswer[];
  state?: string;
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

export interface ControlEventItem {
  id: number;
  event: string;
  control_generation: number;
  operation?: number;
}

export interface EventsResponse {
  instance: string;
  next: number;
  latest: number;
  gap: boolean;
  events: ControlEventItem[];
}

export interface FakeIpFlushResponse {
  flushed: number;
  fakeip: boolean;
}

export interface CacheClearResponse {
  target: string;
  cleared: boolean;
  detail: string;
}

export interface ReloadResponse {
  state: string;
  detail: string;
}

export interface NetworkChangeResponse {
  accepted: boolean;
  detail: string;
}

export interface SsmapiUserItem {
  username: string;
  enabled: boolean;
  uplinkBytes: number;
  downlinkBytes: number;
  uplinkPackets?: number;
  downlinkPackets?: number;
  byteQuota: number;
  tcpSessions: number;
  udpSessions: number;
}

export interface SsmapiStatsResponse {
  userCount: number;
  uplinkBytes: number;
  downlinkBytes: number;
  uplinkPackets?: number;
  downlinkPackets?: number;
  tcpSessions?: number;
  udpSessions?: number;
}

export interface RateSample {
  up: number;
  down: number;
  ts: number;
}
