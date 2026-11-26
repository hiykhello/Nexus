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
  assert.equal(t('overview.flushedFakeip', { count: 7 }), '已清理 7 条未固定 FakeIP 映射。');
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
