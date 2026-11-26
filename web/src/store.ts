import { createStatusStream, nexusApi, onAuthEvent } from './api.ts';
import type { ManagedStream } from './sse.ts';
import type { ModeResponse, RateSample, StatusResponse, StreamState, ThemePreference } from './types.ts';

const THEME_KEY = 'nexus_web_theme';
const MAX_HISTORY = 45;

export class AppStore extends EventTarget {
  status: StatusResponse | null = null;
  mode: ModeResponse | null = null;
  streamState: StreamState = 'connecting';
  streamError = '';
  authRequired = false;
  upRate = 0;
  downRate = 0;
  history: RateSample[] = [];
  themePref: ThemePreference = 'system';
  resolvedTheme: 'dark' | 'light' = 'dark';

  private stream: ManagedStream<StatusResponse> | null = null;
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
        this.emit('change');
        this.emit('auth-required');
      }),
      onAuthEvent('token-changed', () => {
        this.authRequired = false;
        this.streamError = '';
        this.stream?.restart();
        void this.refreshMode();
        this.emit('change');
        this.emit('refresh');
      }),
    );

    this.stream = createStatusStream(
      (s) => this.ingestStatus(s),
      (st) => {
        this.streamState = st;
        if (st === 'live' || st === 'polling') {
          this.authRequired = false;
          this.streamError = '';
        }
        this.emit('change');
      },
      (err) => {
        this.streamError = err;
        this.emit('change');
      },
      1500,
    );
    this.stream.start();
    void this.refreshMode();
  }

  stop(): void {
    if (!this.started) return;
    this.started = false;
    this.stream?.stop();
    this.stream = null;
    this.mediaQuery?.removeEventListener('change', this.handleMediaChange);
    for (const fn of this.unsubAuth) fn();
    this.unsubAuth = [];
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

  subscribe(cb: () => void, event: 'change' | 'refresh' | 'auth-required' = 'change'): () => void {
    this.addEventListener(event, cb);
    return () => this.removeEventListener(event, cb);
  }

  private emit(name: 'change' | 'refresh' | 'auth-required'): void {
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
    if (typeof document !== 'undefined') {
      document.documentElement.dataset.theme = this.resolvedTheme;
    }
  }
}

export const appStore = new AppStore();
