import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildDnsQueryUrl,
  buildLogsQuery,
  formatBytes,
  formatDuration,
  getLatencyTier,
  latencyBars,
} from '../src/api.ts';
import { getLocale, setLocale, t, toggleLocale } from '../src/i18n.ts';
import { ManagedStream, SseParser } from '../src/sse.ts';
import { AppStore } from '../src/store.ts';
import { buildControlWsUrl, ControlWsClient, type WsChannel, type WsLike } from '../src/ws.ts';

test('SseParser parses split chunks, CRLF, keepalive comments, and multiline data', () => {
  const parser = new SseParser();
  const f1 = parser.push(': keepalive\r\n\r\nevent: status\r\ndata: {"state":');
  assert.equal(f1.length, 0);

  const f2 = parser.push('"running"}\r\n\r\nevent: log\ndata: line1\ndata: line2\n\n');
  assert.equal(f2.length, 2);
  assert.deepEqual(f2[0], { event: 'status', data: '{"state":"running"}', id: undefined });
  assert.deepEqual(f2[1], { event: 'log', data: 'line1\nline2', id: undefined });
});

test('buildDnsQueryUrl and buildLogsQuery encode query parameters cleanly without tokens', () => {
  const dnsUrl = buildDnsQueryUrl({ name: 'example.com', type: 'https', server: 'cf-doh' });
  assert.equal(dnsUrl, '/v1/dns/query?name=example.com&type=HTTPS&server=cf-doh');
  assert.equal(dnsUrl.includes('token='), false);

  const logsUrl = buildLogsQuery({ level: 'warn', domain: 'route', search: 'foo bar', since: 42 }, true);
  assert.equal(logsUrl, '/v1/logs?stream=1&level=warn&domain=route&search=foo%20bar&since=42');
  assert.equal(logsUrl.includes('+'), false);
  assert.equal(logsUrl.includes('token='), false);
});

test('formatters and 5-tier latency classification match design thresholds', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1536), '1.5 KiB');
  assert.equal(formatBytes('1048576'), '1.00 MiB');
  assert.equal(formatDuration(450), '450ms');
  assert.equal(formatDuration(65000), '1m 5s');

  assert.equal(getLatencyTier(45, 'up'), 'fast');
  assert.equal(getLatencyTier(120, 'up'), 'good');
  assert.equal(getLatencyTier(260, 'up'), 'mid');
  assert.equal(getLatencyTier(500, 'up'), 'slow');
  assert.equal(getLatencyTier(null, 'down'), 'down');
  assert.equal(getLatencyTier(undefined, 'not-probed'), 'unprobed');
  assert.equal(latencyBars(50), 4);
  assert.equal(latencyBars(400), 1);
  assert.equal(latencyBars(null), 0);
});

test('i18n toggles locales and interpolates parameters cleanly', () => {
  setLocale('en');
  assert.equal(getLocale(), 'en');
  assert.equal(t('overview.flushedFakeip', { count: 7 }), 'Flushed 7 unpinned FakeIP entries.');

  toggleLocale();
  assert.equal(getLocale(), 'zh');
  assert.equal(t('overview.flushedFakeip', { count: 7 }), '已清理 7 条 FakeIP 映射。');
  setLocale('en');
});

test('ManagedStream sends Bearer header only (never query token) and handles 401 cleanly', async () => {
  const originalFetch = globalThis.fetch;
  const seenUrls: string[] = [];
  let seenAuth = '';
  let unauthCalls = 0;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seenUrls.push(String(input));
    const h = new Headers(init?.headers);
    seenAuth = h.get('Authorization') ?? '';
    return new Response('{"error":{"code":"unauthorized","message":"bad"}}', {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  try {
    const states: string[] = [];
    const stream = new ManagedStream<string>({
      buildUrl: () => '/v1/status?stream=1&interval_ms=1500',
      getToken: () => 'secret-demo-token',
      parseFrame: (f) => f.data,
      onData: () => {},
      onState: (s) => states.push(s),
      onUnauthorized: () => {
        unauthCalls++;
      },
      pollFallback: async () => {},
    });
    stream.start();
    await new Promise((r) => setTimeout(r, 30));
    stream.stop();

    assert.equal(seenUrls.length, 1);
    assert.equal(seenUrls[0].includes('token='), false);
    assert.equal(seenAuth, 'Bearer secret-demo-token');
    assert.equal(unauthCalls, 1);
    assert.ok(states.includes('unauthorized'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('ManagedStream delivers SSE frames and falls back to polling when SSE is unavailable', async () => {
  const originalFetch = globalThis.fetch;
  let mode: 'sse' | 'fail' = 'sse';
  const received: Array<{ state: string }> = [];
  let pollCount = 0;

  globalThis.fetch = (async () => {
    if (mode === 'fail') {
      return new Response('unavailable', { status: 503, headers: { 'content-type': 'text/plain' } });
    }
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('event: status\ndata: {"state":"running"}\n\n'));
        controller.close();
      },
    });
    mode = 'fail';
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    });
  }) as typeof fetch;

  try {
    const states: string[] = [];
    const stream = new ManagedStream<{ state: string }>({
      buildUrl: () => '/v1/status?stream=1',
      getToken: () => '',
      parseFrame: (f) => (f.event === 'status' ? (JSON.parse(f.data) as { state: string }) : null),
      onData: (item) => received.push(item),
      onState: (s) => states.push(s),
      pollFallback: async () => {
        pollCount++;
      },
      pollIntervalMs: 50,
      baseBackoffMs: 200,
    });
    stream.start();
    await new Promise((r) => setTimeout(r, 80));
    stream.stop();

    assert.deepEqual(received, [{ state: 'running' }]);
    assert.ok(states.includes('live'));
    assert.ok(pollCount >= 1);
    assert.ok(states.includes('polling'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('ManagedStream restart ignores stale connection aborts via connGen guard', async () => {
  const originalFetch = globalThis.fetch;
  let call = 0;
  const received: string[] = [];

  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const idx = ++call;
    if (idx === 1) {
      await new Promise((r) => setTimeout(r, 40));
      if (init?.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    }
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`event: status\ndata: "conn-${idx}"\n\n`));
      },
    });
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    });
  }) as typeof fetch;

  try {
    const states: string[] = [];
    const stream = new ManagedStream<string>({
      buildUrl: () => '/v1/status?stream=1',
      getToken: () => '',
      parseFrame: (f) => JSON.parse(f.data) as string,
      onData: (item) => received.push(item),
      onState: (s) => states.push(s),
      pollFallback: async () => {},
    });
    stream.start();
    stream.restart();
    await new Promise((r) => setTimeout(r, 70));
    stream.stop();

    assert.deepEqual(received, ['conn-2']);
    assert.equal(states[states.length - 1], 'live');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

class MockWebSocket implements WsLike {
  readyState = 0;
  readonly sent: string[] = [];
  closedWith: { code?: number; reason?: string } | null = null;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null = null;

  send(data: string): void {
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.readyState = 3;
    this.closedWith = { code, reason };
  }

  triggerOpen(): void {
    this.readyState = 1;
    this.onopen?.({});
  }

  triggerMessage(payload: unknown): void {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }

  triggerClose(code = 1006, reason = ''): void {
    this.readyState = 3;
    this.onclose?.({ code, reason });
  }
}

test('buildControlWsUrl produces ws(s) /v1/ws without token or secret query params', () => {
  const httpUrl = buildControlWsUrl({ protocol: 'http:', host: '127.0.0.1:9090' });
  const httpsUrl = buildControlWsUrl({ protocol: 'https:', host: 'console.example:8443' });
  assert.equal(httpUrl, 'ws://127.0.0.1:9090/v1/ws');
  assert.equal(httpsUrl, 'wss://console.example:8443/v1/ws');
  for (const u of [httpUrl, httpsUrl]) {
    assert.equal(u.includes('token='), false);
    assert.equal(u.includes('secret='), false);
    assert.equal(u.includes('?'), false);
  }
});

test('ControlWsClient performs first-frame auth -> auth_ok -> subscribe and dispatches multiplexed channels', () => {
  const seenUrls: string[] = [];
  let sock: MockWebSocket | null = null;
  const states: string[] = [];
  const metricsEvents: unknown[] = [];
  const connEvents: unknown[] = [];
  const logEvents: unknown[] = [];
  let channels: WsChannel[] = ['metrics', 'connections', 'logs'];
  let recovered = 0;

  const client = new ControlWsClient({
    buildUrl: () => buildControlWsUrl({ protocol: 'http:', host: '127.0.0.1:9090' }),
    getToken: () => 'secret-ws-token',
    getSubscribe: () => ({ channels, since: 12, interval_ms: 1000 }),
    onMetrics: (m) => metricsEvents.push(m),
    onConnections: (c) => connEvents.push(c),
    onLog: (l) => logEvents.push(l),
    onState: (s) => states.push(s),
    onRecovered: () => recovered++,
    createSocket: (url) => {
      seenUrls.push(url);
      sock = new MockWebSocket();
      return sock;
    },
    pingIntervalMs: 0,
  });

  client.start();
  assert.equal(seenUrls[0], 'ws://127.0.0.1:9090/v1/ws');
  assert.ok(sock);

  // Open with token -> ONLY first-frame auth sent (must wait for auth_ok before subscribe).
  sock.triggerOpen();
  assert.equal(sock.sent.length, 1);
  assert.deepEqual(JSON.parse(sock.sent[0]), { type: 'auth', token: 'secret-ws-token' });
  assert.equal(client.isLive, false);

  // Server replies auth_ok -> client immediately subscribes and marks live.
  sock.triggerMessage({ type: 'auth_ok' });
  assert.equal(client.isLive, true);
  assert.equal(recovered, 1);
  assert.equal(sock.sent.length, 2);
  assert.deepEqual(JSON.parse(sock.sent[1]), {
    type: 'subscribe',
    channels: ['metrics', 'connections', 'logs'],
    since: 12,
    interval_ms: 1000,
  });

  // Multiplexed channel dispatch
  sock.triggerMessage({ type: 'metrics', data: { instance: 'nx', state: 'running', workers: 2 } });
  sock.triggerMessage({ type: 'connections', data: { connections: [{ id: '9', protocol: 'tcp' }] } });
  sock.triggerMessage({ type: 'log', data: { seq: 13, level: 'info', domain: 'route', message: 'ok' } });

  assert.equal(metricsEvents.length, 1);
  assert.equal(connEvents.length, 1);
  assert.equal(logEvents.length, 1);

  // Dynamic unsubscribe when leaving pages
  channels = ['metrics'];
  client.syncSubscriptions();
  assert.deepEqual(JSON.parse(sock.sent[2]), { type: 'unsubscribe', channels: ['connections', 'logs'] });
  assert.deepEqual(JSON.parse(sock.sent[3]), {
    type: 'subscribe',
    channels: ['metrics'],
    since: 12,
    interval_ms: 1000,
  });

  client.stop();
  assert.equal(client.isLive, false);
  assert.ok(states.includes('live'));
});

test('ControlWsClient handles 4401 auth rejection and triggers graceful SSE fallback on disconnect', () => {
  let sock: MockWebSocket | null = null;
  let unauthCount = 0;
  let fallbackCount = 0;
  const states: string[] = [];

  const client = new ControlWsClient({
    buildUrl: () => 'ws://127.0.0.1:9090/v1/ws',
    getToken: () => 'bad-token',
    getSubscribe: () => ({ channels: ['metrics'], since: 0, interval_ms: 1000 }),
    onState: (s) => states.push(s),
    onUnauthorized: () => unauthCount++,
    onFallback: () => fallbackCount++,
    createSocket: () => {
      sock = new MockWebSocket();
      return sock;
    },
    baseBackoffMs: 5000,
    pingIntervalMs: 0,
  });

  // Case 1: Close 4401 triggers unauthorized without SSE fallback
  client.start();
  sock!.triggerOpen();
  sock!.triggerClose(4401, 'unauthorized');
  assert.equal(unauthCount, 1);
  assert.equal(fallbackCount, 0);
  assert.equal(states[states.length - 1], 'unauthorized');

  // Case 2: Restart and fail upgrade (1006) -> invokes SSE fallback
  client.restart();
  sock!.triggerClose(1006, 'upgrade rejected');
  assert.equal(fallbackCount, 1);
  client.stop();
});

test('ControlWsClient empty-token mode resyncs channels acquired between onopen and subscribed ack', () => {
  let sock: MockWebSocket | null = null;
  let channels: WsChannel[] = ['metrics'];

  const client = new ControlWsClient({
    buildUrl: () => 'ws://127.0.0.1:9090/v1/ws',
    getToken: () => '',
    getSubscribe: () => ({ channels, since: 5, interval_ms: 1000 }),
    onState: () => {},
    createSocket: () => {
      sock = new MockWebSocket();
      return sock;
    },
    pingIntervalMs: 0,
  });

  client.start();
  sock!.triggerOpen();
  assert.equal(sock!.sent.length, 1);
  assert.deepEqual(JSON.parse(sock!.sent[0]), {
    type: 'subscribe',
    channels: ['metrics'],
    since: 5,
    interval_ms: 1000,
  });

  // Channel added before server replies with subscribed ack
  channels = ['metrics', 'connections'];
  sock!.triggerMessage({ type: 'subscribed', channels: ['metrics'] });
  assert.equal(client.isLive, true);
  assert.equal(sock!.sent.length, 2);
  assert.deepEqual(JSON.parse(sock!.sent[1]), {
    type: 'subscribe',
    channels: ['metrics', 'connections'],
    since: 5,
    interval_ms: 1000,
  });
  client.stop();
});

test('AppStore emits transport-change on WS live and 4401 and gates SSE fallback cleanly', () => {
  const origWs = globalThis.WebSocket;
  const origFetch = globalThis.fetch;
  const sockets: MockWebSocket[] = [];

  globalThis.WebSocket = class {
    constructor() {
      const m = new MockWebSocket();
      sockets.push(m);
      return m as unknown as WebSocket;
    }
  } as unknown as typeof WebSocket;
  globalThis.fetch = (async () =>
    new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as typeof fetch;

  const store = new AppStore();
  let transportEvents = 0;
  store.subscribe(() => transportEvents++, 'transport-change');

  try {
    store.start();
    // Connecting phase: MUST NOT trigger SSE fallback
    assert.equal(store.shouldUseSseFallback, false);
    assert.equal(sockets.length, 1);

    // WS opens + subscribed -> emits transport-change even though streamTransport started as 'ws'
    sockets[0].triggerOpen();
    sockets[0].triggerMessage({ type: 'subscribed', channels: ['metrics'] });
    assert.equal(store.wsLive, true);
    assert.equal(store.shouldUseSseFallback, false);
    assert.equal(transportEvents, 1);

    // Close 4401 -> emits transport-change, marks authRequired, and MUST NOT enable SSE fallback
    sockets[0].triggerClose(4401, 'unauthorized');
    assert.equal(store.authRequired, true);
    assert.equal(store.shouldUseSseFallback, false);
    assert.equal(transportEvents, 2);
  } finally {
    store.stop();
    globalThis.WebSocket = origWs;
    globalThis.fetch = origFetch;
  }
});
