import { createStatusStream, getBearerToken, nexusApi, notifyUnauthorized, onAuthEvent } from './api.ts';
import type { ManagedStream } from './sse.ts';
import type {
  ConnectionItem,
  LogEntry,
  ModeResponse,
  RateSample,
  StatusResponse,
  StreamState,
  ThemePreference,
} from './types.ts';
import { ControlWsClient, type WsChannel } from './ws.ts';

const THEME_KEY = 'nexus_web_theme';
const MAX_HISTORY = 45;

export class AppStore extends EventTarget {
  status: StatusResponse | null = null;
  mode: ModeResponse | null = null;
  streamState: StreamState = 'connecting';
  streamTransport: 'ws' | 'sse' = 'ws';
  streamError = '';
  authRequired = false;
  upRate = 0;
  downRate = 0;
  history: RateSample[] = [];
  themePref: ThemePreference = 'system';
  resolvedTheme: 'dark' | 'light' = 'dark';
  latestConnections: ConnectionItem[] = [];

  private wsClient: ControlWsClient | null = null;
  private sseFallback: ManagedStream<StatusResponse> | null = null;
  private channelRefs: Record<'connections' | 'logs', number> = { connections: 0, logs: 0 };
  private logSince = 0;
  private lastUp = 0;
  private lastDown = 0;
  private lastTs = 0;
  private mediaQuery: MediaQueryList | null = null;
  private unsubAuth: (() => void)[] = [];
  private started = false;

  constructor() {
    super();
    this.themePref = this.loadThemePref();
    this.resolvedTheme = this.computeResolvedTheme();
  }

  get wsLive(): boolean {
    return this.wsClient?.isLive ?? false;
  }

  get shouldUseSseFallback(): boolean {
    return this.streamTransport === 'sse' && !this.wsLive && !this.authRequired;
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.applyThemeDom();

    if (typeof window !== 'undefined' && window.matchMedia) {
      this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      this.mediaQuery.addEventListener('change', this.handleMediaChange);
    }

    this.unsubAuth.push(
      onAuthEvent('unauthorized', () => {
        this.authRequired = true;
        this.streamState = 'unauthorized';
        this.sseFallback?.stop();
        this.emit('transport-change');
        this.emit('change');
        this.emit('auth-required');
      }),
      onAuthEvent('token-changed', () => {
        this.authRequired = false;
        this.streamTransport = 'ws';
        this.streamError = '';
        this.sseFallback?.stop();
        this.wsClient?.restart();
        void this.refreshMode();
        this.emit('transport-change');
        this.emit('change');
        this.emit('refresh');
      }),
    );

    this.wsClient = new ControlWsClient({
      getToken: getBearerToken,
      getSubscribe: () => ({
        channels: this.activeWsChannels(),
        since: this.logSince,
        interval_ms: 1500,
      }),
      onMetrics: (s) => this.ingestStatus(s),
      onConnections: (items) => {
        this.latestConnections = items;
        this.dispatchEvent(new CustomEvent('ws-connections', { detail: items }));
      },
      onLog: (entry) => {
        if (entry.seq > this.logSince) this.logSince = entry.seq;
        this.dispatchEvent(new CustomEvent('ws-log', { detail: entry }));
      },
      onState: (st) => {
        if (st === 'live' || st === 'unauthorized') {
          this.streamState = st;
          if (st === 'live') {
            this.streamTransport = 'ws';
            this.authRequired = false;
            this.streamError = '';
          }
          this.emit('change');
        }
      },
      onError: (err) => {
        this.streamError = err;
        this.emit('change');
      },
      onUnauthorized: notifyUnauthorized,
      onFallback: () => this.activateSseFallback(),
      onRecovered: () => this.stopSseFallback(),
    });
    this.wsClient.start();
    void this.refreshMode();
  }

  stop(): void {
    if (!this.started) return;
    this.started = false;
    this.wsClient?.stop();
    this.wsClient = null;
    this.sseFallback?.stop();
    this.sseFallback = null;
    this.mediaQuery?.removeEventListener('change', this.handleMediaChange);
    for (const fn of this.unsubAuth) fn();
    this.unsubAuth = [];
  }

  acquireChannel(channel: 'connections' | 'logs', since?: number): () => void {
    if (channel === 'logs' && since !== undefined && since >= 0) {
      this.logSince = since;
    }
    this.channelRefs[channel]++;
    this.wsClient?.syncSubscriptions();
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.channelRefs[channel] = Math.max(0, this.channelRefs[channel] - 1);
      this.wsClient?.syncSubscriptions();
    };
  }

  setLogCursor(since: number): void {
    if (since > this.logSince) {
      this.logSince = since;
      if (this.channelRefs.logs > 0) this.wsClient?.syncSubscriptions();
    }
  }

  onWsConnections(cb: (items: ConnectionItem[]) => void): () => void {
    const handler = (ev: Event) => cb((ev as CustomEvent<ConnectionItem[]>).detail);
    this.addEventListener('ws-connections', handler);
    return () => this.removeEventListener('ws-connections', handler);
  }

  onWsLog(cb: (entry: LogEntry) => void): () => void {
    const handler = (ev: Event) => cb((ev as CustomEvent<LogEntry>).detail);
    this.addEventListener('ws-log', handler);
    return () => this.removeEventListener('ws-log', handler);
  }

  async refreshNow(): Promise<void> {
    try {
      const [s, m] = await Promise.all([nexusApi.status(), nexusApi.mode().catch(() => this.mode)]);
      this.ingestStatus(s);
      if (m) this.mode = m;
      this.authRequired = false;
      this.streamError = '';
    } catch (err) {
      this.streamError = err instanceof Error ? err.message : String(err);
    }
    this.emit('change');
    this.emit('refresh');
  }

  async refreshMode(): Promise<void> {
    try {
      this.mode = await nexusApi.mode();
      this.emit('change');
    } catch {
      // mode endpoint optional or unauthorized
    }
  }

  setModeLocal(mode: ModeResponse): void {
    this.mode = mode;
    this.emit('change');
  }

  cycleTheme(): ThemePreference {
    const order: ThemePreference[] = ['dark', 'light', 'system'];
    const idx = order.indexOf(this.themePref);
    const next = order[(idx + 1) % order.length];
    this.setTheme(next);
    return next;
  }

  setTheme(pref: ThemePreference): void {
    this.themePref = pref;
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(THEME_KEY, pref);
      } catch {
        // ignore
      }
    }
    this.resolvedTheme = this.computeResolvedTheme();
    this.applyThemeDom();
    this.emit('change');
  }

  subscribe(
    cb: () => void,
    event: 'change' | 'refresh' | 'auth-required' | 'transport-change' = 'change',
  ): () => void {
    this.addEventListener(event, cb);
    return () => this.removeEventListener(event, cb);
  }

  private activeWsChannels(): WsChannel[] {
    const list: WsChannel[] = ['metrics'];
    if (this.channelRefs.connections > 0) list.push('connections');
    if (this.channelRefs.logs > 0) list.push('logs');
    return list;
  }

  private activateSseFallback(): void {
    if (!this.started || this.authRequired) return;
    this.streamTransport = 'sse';
    if (!this.sseFallback) {
      this.sseFallback = createStatusStream(
        (s) => this.ingestStatus(s),
        (st) => {
          if (this.wsLive) return;
          this.streamState = st;
          if (st === 'live' || st === 'polling') {
            this.authRequired = false;
            this.streamError = '';
          }
          this.emit('change');
        },
        (err) => {
          if (this.wsLive) return;
          this.streamError = err;
          this.emit('change');
        },
        1500,
      );
    }
    this.sseFallback.start();
    this.emit('transport-change');
    this.emit('change');
  }

  private stopSseFallback(): void {
    this.streamTransport = 'ws';
    this.sseFallback?.stop();
    this.emit('transport-change');
    this.emit('change');
  }

  private emit(name: 'change' | 'refresh' | 'auth-required' | 'transport-change'): void {
    this.dispatchEvent(new CustomEvent(name));
  }

  private ingestStatus(s: StatusResponse): void {
    const now = Date.now();
    const up = Number(s.upload_bytes_total || 0);
    const down = Number(s.download_bytes_total || 0);
    if (this.lastTs > 0 && now > this.lastTs) {
      const dt = (now - this.lastTs) / 1000;
      const dUp = up >= this.lastUp ? up - this.lastUp : 0;
      const dDown = down >= this.lastDown ? down - this.lastDown : 0;
      this.upRate = Math.max(0, dUp / dt);
      this.downRate = Math.max(0, dDown / dt);
      this.history = [...this.history.slice(-(MAX_HISTORY - 1)), { up: this.upRate, down: this.downRate, ts: now }];
    } else if (this.history.length === 0) {
      this.history = [{ up: 0, down: 0, ts: now }];
    }
    this.lastUp = up;
    this.lastDown = down;
    this.lastTs = now;
    this.status = s;
    this.authRequired = false;
    this.streamError = '';
    this.emit('change');
  }

  private loadThemePref(): ThemePreference {
    if (typeof window === 'undefined') return 'dark';
    try {
      const saved = window.localStorage.getItem(THEME_KEY);
      if (saved === 'dark' || saved === 'light' || saved === 'system') return saved;
    } catch {
      // ignore
    }
    return 'system';
  }

  private computeResolvedTheme(): 'dark' | 'light' {
    if (this.themePref === 'dark' || this.themePref === 'light') return this.themePref;
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    return 'dark';
  }

  private handleMediaChange = (): void => {
    if (this.themePref === 'system') {
      this.resolvedTheme = this.computeResolvedTheme();
      this.applyThemeDom();
      this.emit('change');
    }
  };

  private applyThemeDom(): void {
    if (typeof document === 'undefined') return;
    document.documentElement.dataset.theme = this.resolvedTheme;
    document.documentElement.style.colorScheme = this.resolvedTheme;
    const color = this.resolvedTheme === 'dark' ? '#111317' : '#f5f6f8';
    let meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    if (!meta && document.head) {
      meta = document.createElement('meta');
      meta.name = 'theme-color';
      document.head.appendChild(meta);
    }
    if (meta) meta.content = color;
  }
}

export const appStore = new AppStore();
