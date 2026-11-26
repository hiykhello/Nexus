import type { ConnectionItem, LogEntry, StatusResponse, StreamState } from './types.ts';

export type WsChannel = 'logs' | 'connections' | 'metrics';

export interface WsLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null;
}

export interface ControlWsOptions {
  buildUrl?: () => string;
  getToken: () => string;
  getSubscribe: () => { channels: WsChannel[]; since?: number; interval_ms?: number };
  onMetrics?: (status: StatusResponse) => void;
  onConnections?: (items: ConnectionItem[]) => void;
  onLog?: (entry: LogEntry) => void;
  onState: (state: StreamState) => void;
  onError?: (err: string, code?: string) => void;
  onUnauthorized?: () => void;
  onFallback?: () => void;
  onRecovered?: () => void;
  createSocket?: (url: string) => WsLike;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
  pingIntervalMs?: number;
}

const WS_OPEN = 1;
const WS_CLOSE_UNAUTHORIZED = 4401;

export function buildControlWsUrl(loc?: { protocol: string; host: string }): string {
  const target = loc ?? (typeof window !== 'undefined' ? window.location : null);
  if (!target || !target.host) return 'ws://127.0.0.1:9090/v1/ws';
  return `${target.protocol === 'https:' ? 'wss:' : 'ws:'}//${target.host}/v1/ws`;
}

export class ControlWsClient {
  private readonly opts: ControlWsOptions;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly pingIntervalMs: number;
  private socket: WsLike | null = null;
  private running = false;
  private authenticated = false;
  private connGen = 0;
  private backoffMs: number;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private subscribedChannels = new Set<WsChannel>();
  private state: StreamState = 'connecting';

  constructor(opts: ControlWsOptions) {
    this.opts = opts;
    this.baseBackoffMs = opts.baseBackoffMs ?? 1000;
    this.maxBackoffMs = opts.maxBackoffMs ?? 15000;
    this.pingIntervalMs = opts.pingIntervalMs ?? 20000;
    this.backoffMs = this.baseBackoffMs;
  }

  get isLive(): boolean {
    return this.running && this.authenticated && this.socket?.readyState === WS_OPEN;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.backoffMs = this.baseBackoffMs;
    this.setState('connecting');
    this.connect();
  }

  restart(): void {
    this.stop();
    this.start();
  }

  stop(): void {
    this.running = false;
    this.authenticated = false;
    this.connGen++;
    this.subscribedChannels.clear();
    this.clearTimers();
    this.closeSocket('client stop');
  }

  syncSubscriptions(): void {
    if (!this.isLive) return;
    const desired = this.opts.getSubscribe();
    const desiredSet = new Set<WsChannel>(desired.channels);
    const removed = [...this.subscribedChannels].filter((c) => !desiredSet.has(c));
    if (removed.length > 0) this.sendJson({ type: 'unsubscribe', channels: removed });
    if (desired.channels.length > 0) {
      this.sendJson({
        type: 'subscribe',
        channels: desired.channels,
        since: desired.since ?? 0,
        interval_ms: desired.interval_ms ?? 1000,
      });
    }
    this.subscribedChannels = desiredSet;
  }

  private setState(next: StreamState): void {
    if (this.state === next) return;
    this.state = next;
    this.opts.onState(next);
  }

  private clearTimers(): void {
    if (this.reconnectTimer !== null) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    if (this.pingTimer !== null) { clearInterval(this.pingTimer); this.pingTimer = null; }
  }

  private closeSocket(reason: string): void {
    const sock = this.socket;
    this.socket = null;
    if (!sock) return;
    sock.onopen = sock.onmessage = sock.onerror = sock.onclose = null;
    try { sock.close(1000, reason); } catch { /* ignore */ }
  }

  private startPingTimer(gen: number): void {
    if (this.pingTimer !== null) clearInterval(this.pingTimer);
    if (this.pingIntervalMs <= 0) return;
    this.pingTimer = setInterval(() => {
      if (this.running && gen === this.connGen && this.isLive) this.sendJson({ type: 'ping' });
    }, this.pingIntervalMs);
  }

  private sendJson(payload: Record<string, unknown>): void {
    if (!this.socket || this.socket.readyState !== WS_OPEN) return;
    try { this.socket.send(JSON.stringify(payload)); } catch { /* onclose handles fallback */ }
  }

  private handleUnauthorized(): void {
    this.authenticated = false;
    this.connGen++;
    this.clearTimers();
    this.closeSocket('unauthorized');
    this.setState('unauthorized');
    this.opts.onUnauthorized?.();
  }

  private scheduleReconnect(): void {
    if (!this.running || this.state === 'unauthorized' || this.reconnectTimer !== null) return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.maxBackoffMs, this.backoffMs * 2);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.running) this.connect();
    }, delay);
  }

  private markLive(gen: number): void {
    if (!this.running || gen !== this.connGen) return;
    this.authenticated = true;
    this.backoffMs = this.baseBackoffMs;
    this.setState('live');
    this.opts.onRecovered?.();
    this.startPingTimer(gen);
  }

  private syncIfChannelsChanged(): void {
    const desired = this.opts.getSubscribe().channels;
    if (
      desired.length !== this.subscribedChannels.size ||
      desired.some((c) => !this.subscribedChannels.has(c))
    ) {
      this.syncSubscriptions();
    }
  }

  private handleMessage(raw: unknown, gen: number): void {
    if (!this.running || gen !== this.connGen || typeof raw !== 'string') return;
    let msg: Record<string, unknown>;
    try { msg = JSON.parse(raw) as Record<string, unknown>; } catch { return; }
    const kind = typeof msg.type === 'string' ? msg.type : '';
    if (kind === 'auth_ok') {
      this.markLive(gen);
      this.subscribedChannels.clear();
      this.syncSubscriptions();
    } else if (kind === 'subscribed') {
      if (!this.authenticated) {
        this.markLive(gen);
        this.syncIfChannelsChanged();
      }
    } else if (kind === 'metrics' && msg.data && typeof msg.data === 'object') {
      if (!this.authenticated) { this.markLive(gen); this.syncIfChannelsChanged(); }
      this.opts.onMetrics?.(msg.data as StatusResponse);
    } else if (kind === 'connections' && msg.data) {
      if (!this.authenticated) { this.markLive(gen); this.syncIfChannelsChanged(); }
      const payload = msg.data as { connections?: ConnectionItem[] } | ConnectionItem[];
      this.opts.onConnections?.(Array.isArray(payload) ? payload : (payload.connections ?? []));
    } else if (kind === 'log' && msg.data && typeof msg.data === 'object') {
      if (!this.authenticated) { this.markLive(gen); this.syncIfChannelsChanged(); }
      this.opts.onLog?.(msg.data as LogEntry);
    } else if (kind === 'error') {
      const code = typeof msg.code === 'string' ? msg.code : undefined;
      const text = typeof msg.message === 'string' ? msg.message : 'WebSocket error';
      if (code === 'unauthorized') this.handleUnauthorized();
      else this.opts.onError?.(text, code);
    }
  }

  private connect(): void {
    if (!this.running) return;
    const factory =
      this.opts.createSocket ??
      (typeof WebSocket !== 'undefined' ? (u: string) => new WebSocket(u) as unknown as WsLike : null);
    if (!factory) { this.opts.onFallback?.(); return; }

    const gen = ++this.connGen;
    this.authenticated = false;
    let sock: WsLike;
    try {
      sock = factory((this.opts.buildUrl ?? buildControlWsUrl)());
    } catch {
      this.opts.onFallback?.();
      this.scheduleReconnect();
      return;
    }
    this.socket = sock;

    sock.onopen = () => {
      if (!this.running || gen !== this.connGen) return;
      const token = this.opts.getToken().trim();
      if (token) {
        this.sendJson({ type: 'auth', token });
      } else {
        const desired = this.opts.getSubscribe();
        this.subscribedChannels = new Set(desired.channels);
        this.sendJson({
          type: 'subscribe',
          channels: desired.channels,
          since: desired.since ?? 0,
          interval_ms: desired.interval_ms ?? 1000,
        });
      }
    };
    sock.onmessage = (ev) => this.handleMessage(ev?.data, gen);
    sock.onerror = () => {};
    sock.onclose = (ev) => {
      if (gen !== this.connGen) return;
      this.authenticated = false;
      this.socket = null;
      if (this.pingTimer !== null) { clearInterval(this.pingTimer); this.pingTimer = null; }
      if (ev?.code === WS_CLOSE_UNAUTHORIZED) { this.handleUnauthorized(); return; }
      if (this.running) {
        this.opts.onFallback?.();
        this.scheduleReconnect();
      }
    };
  }
}
