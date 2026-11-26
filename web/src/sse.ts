import type { StreamState } from './types.ts';

export interface SseFrame {
  event: string;
  data: string;
  id?: string;
}

export class SseParser {
  private buffer = '';

  push(chunk: string): SseFrame[] {
    this.buffer += chunk;
    const frames: SseFrame[] = [];
    // Normalize CRLF and CR to LF only up to completed frame boundaries.
    const normalized = this.buffer.replace(/\r\n/g, '\n');
    const parts = normalized.split('\n\n');
    this.buffer = parts.pop() ?? '';

    for (const block of parts) {
      if (!block.trim()) continue;
      let event = 'message';
      let id: string | undefined;
      const dataLines: string[] = [];

      for (const line of block.split('\n')) {
        if (!line || line.startsWith(':')) continue;
        const colon = line.indexOf(':');
        const field = colon === -1 ? line : line.slice(0, colon);
        let value = colon === -1 ? '' : line.slice(colon + 1);
        if (value.startsWith(' ')) value = value.slice(1);

        if (field === 'event') event = value || 'message';
        else if (field === 'data') dataLines.push(value);
        else if (field === 'id') id = value;
      }

      if (dataLines.length > 0) {
        frames.push({ event, data: dataLines.join('\n'), id });
      }
    }
    return frames;
  }

  reset(): void {
    this.buffer = '';
  }
}

export interface ManagedStreamOptions<T> {
  buildUrl: () => string;
  getToken: () => string;
  parseFrame: (frame: SseFrame) => T | null;
  onData: (item: T) => void;
  onState: (state: StreamState) => void;
  onError?: (err: string, status?: number) => void;
  onUnauthorized?: () => void;
  pollFallback: () => Promise<void>;
  pollIntervalMs?: number;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
}

export class ManagedStream<T> {
  private readonly opts: ManagedStreamOptions<T>;
  private running = false;
  private controller: AbortController | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private backoffMs: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly pollIntervalMs: number;
  private state: StreamState = 'connecting';
  private sseActive = false;
  private connGen = 0;

  constructor(opts: ManagedStreamOptions<T>) {
    this.opts = opts;
    this.baseBackoffMs = opts.baseBackoffMs ?? 1000;
    this.maxBackoffMs = opts.maxBackoffMs ?? 15000;
    this.pollIntervalMs = opts.pollIntervalMs ?? 2500;
    this.backoffMs = this.baseBackoffMs;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.backoffMs = this.baseBackoffMs;
    this.setState('connecting');
    void this.connectLoop();
  }

  restart(): void {
    this.stop();
    this.start();
  }

  stop(): void {
    this.running = false;
    this.sseActive = false;
    this.connGen++;
    this.clearTimers();
    if (this.controller) {
      this.controller.abort();
      this.controller = null;
    }
  }

  private setState(next: StreamState): void {
    if (this.state === next) return;
    this.state = next;
    this.opts.onState(next);
  }

  private clearTimers(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private startPollingFallback(): void {
    if (this.pollTimer !== null || !this.running) return;
    const tick = async (): Promise<void> => {
      if (!this.running || this.sseActive) return;
      try {
        await this.opts.pollFallback();
        if (this.running && !this.sseActive) this.setState('polling');
      } catch (err) {
        if (!this.running || this.sseActive) return;
        const status = (err as { status?: number })?.status;
        if (status === 401) {
          this.handleUnauthorized();
          return;
        }
        this.setState('offline');
        this.opts.onError?.(err instanceof Error ? err.message : String(err), status);
      }
    };
    void tick();
    this.pollTimer = setInterval(() => void tick(), this.pollIntervalMs);
  }

  private stopPollingFallback(): void {
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private handleUnauthorized(): void {
    this.sseActive = false;
    this.clearTimers();
    if (this.controller) {
      this.controller.abort();
      this.controller = null;
    }
    this.setState('unauthorized');
    this.opts.onUnauthorized?.();
  }

  private scheduleReconnect(): void {
    if (!this.running || this.state === 'unauthorized') return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.maxBackoffMs, this.backoffMs * 2);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.running) void this.connectLoop();
    }, delay);
  }

  private async connectLoop(): Promise<void> {
    if (!this.running) return;
    const gen = ++this.connGen;
    this.controller = new AbortController();
    const { signal } = this.controller;
    const headers = new Headers({ Accept: 'text/event-stream' });
    const token = this.opts.getToken();
    if (token) headers.set('Authorization', `Bearer ${token}`);

    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    try {
      const resp = await fetch(this.opts.buildUrl(), {
        method: 'GET',
        headers,
        cache: 'no-store',
        signal,
      });
      if (!this.running || gen !== this.connGen) return;

      if (resp.status === 401) {
        this.handleUnauthorized();
        return;
      }

      const ct = resp.headers.get('content-type') ?? '';
      if (!resp.ok || !resp.body || !ct.includes('text/event-stream')) {
        throw Object.assign(new Error(`SSE unavailable (HTTP ${resp.status})`), {
          status: resp.status,
        });
      }

      this.stopPollingFallback();
      this.backoffMs = this.baseBackoffMs;
      this.sseActive = true;
      this.setState('live');

      reader = resp.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SseParser();

      while (this.running && gen === this.connGen) {
        const { done, value } = await reader.read();
        if (done || !this.running || gen !== this.connGen) break;
        const text = decoder.decode(value, { stream: true });
        for (const frame of parser.push(text)) {
          if (!this.running || gen !== this.connGen) break;
          const parsed = this.opts.parseFrame(frame);
          if (parsed !== null) this.opts.onData(parsed);
        }
      }
      if (gen !== this.connGen) return;
      this.sseActive = false;
      if (this.running) {
        this.startPollingFallback();
        this.scheduleReconnect();
      }
    } catch (err) {
      if (gen !== this.connGen) return;
      this.sseActive = false;
      if (!this.running || signal.aborted) return;
      const status = (err as { status?: number })?.status;
      if (status === 401) {
        this.handleUnauthorized();
        return;
      }
      this.startPollingFallback();
      this.scheduleReconnect();
    } finally {
      if (reader) void reader.cancel().catch(() => {});
    }
  }
}
